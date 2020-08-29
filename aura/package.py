# -*- coding: utf-8 -*-
from __future__ import annotations
import math
import datetime
import tempfile
import shutil
import xmlrpc.client
from functools import partial
from urllib.parse import urlparse, ParseResult
from pathlib import Path
from itertools import product, chain
from contextlib import contextmanager
from typing import Optional, Generator, Tuple, List

import pytz
import requests
import rapidjson as json
from packaging.version import Version
from packaging.utils import canonicalize_name
from packaging.requirements import Requirement
from textdistance import jaccard

from . import config
from . import github
from . import utils
from . import exceptions
from .uri_handlers.base import ScanLocation
from .output import table
from .mirror import LocalMirror


LOGGER = config.get_logger(__name__)


class PypiPackage:
    mirror = None

    def __init__(self, name, info, source=None):
        self.name = name
        self.info = info
        self.source = source
        self.release = "all"
        self.packagetype = None
        self.filename = None
        self.md5 = None

    @classmethod
    def from_pypi(cls, name, *args, **kwargs):
        name = canonicalize_name(name)
        resp = requests.get(f"https://pypi.org/pypi/{name}/json")
        if resp.status_code == 404:
            LOGGER.error(f"Package {name} does not exists on PyPI")
            raise exceptions.NoSuchPackage(f"{name} on PyPI repository")

        kwargs["info"] = resp.json()
        kwargs["source"] = "pypi"

        return cls(name, *args, **kwargs)

    @classmethod
    def from_local_mirror(cls, name, *args, **kwargs):
        name = canonicalize_name(name)

        if cls.mirror is None:
            cls.mirror = LocalMirror()

        kwargs["source"] = "local_mirror"
        kwargs["info"] = cls.mirror.get_json(name)

        return cls(name, *args, **kwargs)

    @classmethod
    def list_packages(cls):
        repo = xmlrpc.client.ServerProxy(
            "https://pypi.python.org/pypi", use_builtin_types=True
        )
        return list(repo.list_packages())

    def __contains__(self, item):
        return item in self.info["releases"].keys()

    def __getitem__(self, item):
        return self.info[item]

    def get_latest_release(self) -> str:
        return self.info["info"]["version"]

    def get_dependencies(self) -> Generator[Requirement, None, None]:
        deps = self.info["info"].get("requires_dist", [])
        if deps:
            for req_line in deps:
                yield Requirement(req_line)

    def download_release(
        self,
        dest,
        all=True,
        **filters
    ):
        dest = Path(dest)
        files = []

        filtered = self.filter_package_types(**filters)

        if not all:
            filtered = filtered[:1]

        for url in filtered:
            with open(dest / url["filename"], "wb") as fd:
                utils.download_file(url["url"], fd)
            files.append(url["filename"])

        return files

    @contextmanager
    def url2local(self, url: str):
        if not isinstance(url, ParseResult):
            url = urlparse(url)

        if self.mirror is not None and self.source == "local_mirror":
            yield self.mirror.url2local(url)
        else:
            suffix = "_" + url.path.split("/")[-1]
            with tempfile.NamedTemporaryFile(
                prefix="aura_package_", suffix=suffix
            ) as tmp_file:
                utils.download_file(url.geturl(), tmp_file)
                yield Path(tmp_file.name)

    def filter_package_types(
        self,
        release="latest",
        packagetype=None,
        filename=None,
        md5=None,
    ):
        if release == "latest":
            release = self.get_latest_release()

        if release == "all":
            releases = list(chain(self.info["releases"].values()))
        else:
            releases = self.info["releases"][release]


        types = set(x.get("packagetype") for x in releases)

        if "sdist" in types and packagetype is None:
            packagetype = "sdist"

        filters = (
            partial(packagetype_filter, packagetype=packagetype),
            partial(filename_filter, filename=filename),
            partial(md5_filter, md5=md5)
        )
        pkgs = []

        for pkg in releases:
            if all(x(pkg) for x in filters):
                pkgs.append(pkg)

        # FIXME: sort by version pkgs.sort(key=lambda x: Version(x), reverse=True)
        return pkgs

    @property
    def score(self) -> PackageScore:  # TODO: add caching
        return PackageScore(self.name, package=self)

    def _yield_cmp_versions(self, other: PypiPackage) -> Generator[Tuple[str, str], None, None]:
        self_latest = self.get_latest_release()
        self_parsed = Version(self_latest)
        other_latest = other.get_latest_release()
        other_parsed = Version(other_latest)

        yield (self_latest, other_latest)
        if self_parsed != other_parsed:
            if self_latest in other:
                yield (self_latest, self_latest)
            elif other_latest in self:
                yield (other_latest, other_latest)

    def _yield_archive_md5(
        self,
        self_version,
        other,
        other_version,
    ) -> Generator[Tuple[dict, dict], None, None]:
        sortkey = lambda x: (-1 if x.get("packagetype") == "sdist" else 0)

        self_releases = sorted(self.info["releases"][self_version], key=sortkey)
        other_releases = sorted(other.info["releases"][other_version], key=sortkey)
        all_candidates = []

        for x, y in product(self_releases, other_releases):
            # Make sure these attributes are equal between releases
            if x.get("packagetype") != y.get("packagetype"):
                continue
            elif x.get("python_version") != y.get("python_version"):
                continue

            all_candidates.append((x, y))

        if all_candidates:
            yield all_candidates[0]
        else:
            # If there are no candidates after filtering, fallback to just take the first ones from each
            yield (self_releases[0], other_releases[0])

    def _cmp_info(self, other: PypiPackage) -> table.Table:
        info_table = table.Table(metadata={"title": "PyPI metadata diff"})

        sum1 = self["info"]["summary"] or ""
        sum2 = other["info"]["summary"] or ""
        sum_sim = jaccard.normalized_similarity(sum1, sum2)
        info_table += ("Description Similarity", sum_sim)

        is_similar_desc = (sum_sim >= 0.8)
        info_table += ("Similar Description", is_similar_desc)

        page1 = self["info"]["home_page"] or ""
        page2 = other["info"]["home_page"] or ""
        info_table += ("Same homepage", (page1 == page2))

        docs1 = self["info"]["docs_url"] or ""
        docs2 = other["info"]["docs_url"] or ""
        info_table += ("Same documentation URL", (docs1 == docs2))

        releases1 = set(self["releases"].keys())
        releases2 = set(other["releases"].keys())
        info_table += ("Has Subreleases", releases1.issuperset(releases2))

        return info_table

    def _cmp_archives(self, other: PypiPackage) -> Generator[Tuple[ScanLocation, ScanLocation], None, None]:
        diff_candidates = []
        temp_dir = Path(tempfile.mkdtemp(prefix="aura_pkg_diff_"))

        try:
            for self_version, other_version in self._yield_cmp_versions(other):
                for self_archive, other_archive in self._yield_archive_md5(self_version, other, other_version):
                    diff_candidates.append((self_archive, other_archive))

            for (x, y) in diff_candidates:
                x_path = temp_dir / x["md5_digest"]
                x_path.mkdir()
                x_path /= x["filename"]

                with x_path.open("wb") as fd:
                    utils.download_file(x["url"], fd)

                x_loc = ScanLocation(
                    location=x_path,
                    strip_path=str(x_path.parent),
                    metadata={"release": x}
                )

                y_path = temp_dir / y["md5_digest"]
                y_path.mkdir()
                y_path /= y["filename"]

                with y_path.open("wb") as fd:
                    utils.download_file(y["url"], fd)

                y_loc = ScanLocation(
                    location=y_path,
                    strip_path=str(y_path.parent),
                    metadata={"release": y}
                )
                yield x_loc, y_loc

        finally:
            if temp_dir.exists():
                shutil.rmtree(temp_dir)


class PackageScore:
    def __init__(self, package_name: str, package: Optional[PypiPackage]=None):
        self.package_name = package_name

        if package is None:
            self.pkg = PypiPackage.from_pypi(package_name)
        else:
            self.pkg = package

        self.now = pytz.UTC.localize(datetime.datetime.utcnow())
        self.github = None

        self.__load_github()

    def __load_github(self):
        self.repo_url = self.pkg.info["info"]["project_urls"].get("Source")
        if self.repo_url is None:
            return

        self.github = github.GitHub.from_url(self.repo_url)

    def score_pypi_downloads(self) -> int:
        for line in config.iter_pypi_stats():
            pkg_name = canonicalize_name(line["package_name"])
            if pkg_name == self.package_name:
                return math.ceil(math.log(int(line.get("downloads", 0)), 10))

        return 0

    def score_reverse_dependencies(self) -> int:
        dependencies = get_reverse_dependencies(self.package_name)
        if not dependencies:
            return 0

        return math.ceil(math.log(len(dependencies), 10))

    def score_github_stars(self) -> int:
        if self.github is None:
            return 0

        return math.ceil(math.log(self.github.repo["stargazers_count"], 10))

    def score_github_forks(self) ->int:
        if self.github is None:
            return 0

        return math.ceil(math.log(self.github.repo["forks"], 10))

    def score_github_contributors(self) -> int:
        if self.github is None:
            return 0

        return math.ceil(math.log(len(self.github.contributors), 10))

    def score_last_commit(self) -> bool:
        if self.github is None:
            return False

        last_commit = utils.parse_iso_8601(self.github.repo["pushed_at"])

        if last_commit + datetime.timedelta(days=31*3) >= self.now:
            return True
        else:
            return False

    def score_is_new_on_github(self) -> bool:
        if self.github is None:
            return False

        created = utils.parse_iso_8601(self.github.repo["created_at"])

        if created + datetime.timedelta(days=31*6) <= self.now:
            return True
        else:
            return False

    def has_multiple_releases(self) -> bool:
        if len(self.pkg["releases"]) > 1:
            return True
        else:
            return False

    def has_source_repository(self) -> bool:
        if self.pkg["info"]["project_urls"].get("Source"):
            return True
        else:
            return False

    def has_documentation(self) -> bool:
        if self.pkg["info"]["project_urls"].get("Documentation"):
            return True
        else:
            return False

    def has_homepage(self) -> bool:
        if self.pkg["info"]["project_urls"].get("Homepage"):
            return True
        else:
            return False

    def has_wheel(self) -> bool:
        for r in self.pkg["urls"]:
            if r["packagetype"] == "bdist_wheel":
                return True
        return False

    def has_sdist_source(self) -> bool:
        for r in self.pkg["urls"]:
            if r["packagetype"] == "sdist" and r.get("python_version") == "source":
                return True
        return False

    def get_score_matrix(self) -> dict:
        score_matrix = {
            "pypi_downloads": self.score_pypi_downloads(),
            "reverse_dependencies": self.score_reverse_dependencies(),
            "github_stars": self.score_github_stars(),
            "forks": self.score_github_forks(),
            "contributors": self.score_github_contributors(),
            "last_commit": self.score_last_commit(),
            "is_new": self.score_is_new_on_github(),
            "multiple_releases": self.has_multiple_releases(),
            "has_source_repository": self.has_source_repository(),
            "has_documentation": self.has_documentation(),
            "has_homepage": self.has_homepage(),
            "has_wheel": self.has_wheel(),
            "has_sdist_source": self.has_sdist_source(),
        }
        total = sum(score_matrix.values())
        score_matrix["total"] = total
        return score_matrix

    def get_score_table(self) -> table.Table:
        score_table = table.Table(metadata={"title": f"Package score for '{self.package_name}'"})

        for k, v in self.get_score_matrix().items():
            row = (table.Column(k), table.Column(v))

            if k == "total":
                row[0].metadata["style"] = row[1].metadata["style"] = {"fg": "blue", "bold": True}

            score_table += row  # TODO: convert k/id to human text

        return score_table



def packagetype_filter(release, packagetype="all") -> bool:
    if packagetype == "all":
        return True
    elif packagetype and release.get("packagetype") == packagetype:
        return True
    else:
        return False


def filename_filter(release, filename=None) -> bool:
    if filename is None:
        return True

    return (release["filename"] == filename)


def md5_filter(release, md5=None) -> bool:
    if md5 is None:
        return True

    return (md5 == release["md5_digest"])


def get_reverse_dependencies(pkg_name: str) -> List[str]:
    pkg_name = canonicalize_name(pkg_name)
    dataset_path = Path("reverse_dependencies.json_blah")
    with dataset_path.open("r") as fd:
        dataset = json.loads(fd.read())

    if pkg_name in dataset:
        return dataset[pkg_name]
    else:
        return []


def get_packages_for_author(author: str) -> List[Tuple[str, str]]:
    repo = xmlrpc.client.ServerProxy(
        "https://pypi.org/pypi", use_builtin_types=True
    )
    return list(repo.user_packages(author))
