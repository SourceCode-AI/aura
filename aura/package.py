# -*- coding: utf-8 -*-
from __future__ import annotations
import math
import datetime
import dataclasses
import tempfile
import shutil
import difflib
import xmlrpc.client
from functools import partial
from urllib.parse import urlparse, ParseResult
from pathlib import Path
from itertools import product, chain
from contextlib import contextmanager
from typing import Optional, Generator, Tuple, List, Union

import pytz
import requests
from packaging.version import Version
from packaging.utils import canonicalize_name
from packaging.requirements import Requirement

from . import config
from . import github
from . import cache
from .json_proxy import loads
from . import utils
from . import exceptions
from .uri_handlers.base import ScanLocation
from .output import table
from .mirror import LocalMirror
from .type_definitions import ReleaseInfo
from .exceptions import NoSuchPackage, MissingFile


LOGGER = config.get_logger(__name__)


class PypiPackage:
    mirror = LocalMirror()

    def __init__(self, name: str, info: dict, source: Optional[str]=None, opts: Optional[dict]=None):
        self.name: str = name
        self.info: dict = info
        self.source: Optional[str] = source
        self.opts: dict = opts or {}  # TODO: check if this attribute is used anywhere
        # normalize missing data
        self.info["info"].setdefault("project_urls", {})
        if self.info["info"]["project_urls"] is None:
            self.info["info"]["project_urls"] = {}

    @classmethod
    def from_cached(cls, name: str, *args, **kwargs):
        name = canonicalize_name(name)

        if cls.mirror.get_mirror_path():
            try:
                kwargs["info"] = cls.mirror.get_json(name)
                kwargs["source"] = "local_mirror"
                return cls(name, *args, **kwargs)
            except NoSuchPackage:
                pass

        try:
            resp = cache.URLCache.proxy(url=f"https://pypi.org/pypi/{name}/json", tags=["pypi_json"])
        except requests.exceptions.HTTPError as exc:
            raise NoSuchPackage(f"`{name}` on PyPI repository") from exc

        kwargs["info"] = loads(resp)
        kwargs["source"] = "pypi"

        return cls(name, *args, **kwargs)

    @classmethod
    def list_packages(cls):
        repo = xmlrpc.client.ServerProxy(
            "https://pypi.python.org/pypi", use_builtin_types=True
        )
        return list(repo.list_packages())

    def __contains__(self, item: str):
        return item in self.info["releases"].keys()

    def __getitem__(self, item: str):
        return self.info[item]

    @property
    def source_url(self) -> Optional[str]:
        if src := self.info["info"]["project_urls"].get("Source"):
            return src

        if src := self.homepage_url:
            parsed_src = urlparse(src)
            if parsed_src.netloc == "github.com":
                return src

    @property
    def homepage_url(self) -> Optional[str]:
        return self.info["info"].get("home_page")

    @property
    def documentation_url(self) -> Optional[str]:
        return self.info["info"]["project_urls"].get("Documentation")

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
        **filters  # TODO: add tests for the filters
    ):
        dest = Path(dest)
        files = []

        filtered = self.filter_package_types(**filters)

        if not all:
            filtered = filtered[:1]

        for url in filtered:
            with open(dest / url["filename"], "wb") as fd:
                cache.FileDownloadCache.proxy(url=url["url"], fd=fd)
            files.append(url)

        return files

    @contextmanager
    def url2local(self, url: str) -> Generator[Path, None, None]:
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
        release: str = "latest",
        packagetype: Optional[str] = None,
        filename: Optional[str] =None,
        md5: Optional[str] =None,
    ) -> List[ReleaseInfo, ...]:
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

        if self.opts.get("diff_include_latest", False):
            yield (self_latest, other_latest)

        if self_parsed != other_parsed:
            if self_latest in other:
                yield (self_latest, self_latest)
            elif other_latest in self:
                yield (other_latest, other_latest)

    def _yield_archive_md5(
        self,
        self_version: str,
        other: PypiPackage,
        other_version: str,
    ) -> Generator[Tuple[ReleaseInfo, ReleaseInfo], None, None]:
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

    def get_diff_candidates(self, other: PypiPackage) -> Generator[Tuple[ReleaseInfo, ReleaseInfo], None, None]:
        for self_version, other_version in self._yield_cmp_versions(other):
            for self_archive, other_archive in self._yield_archive_md5(self_version, other, other_version):
                yield (self_archive, other_archive)

    def _cmp_info(self, other: PypiPackage) -> table.Table:
        info_table = table.Table(metadata={"title": "PyPI metadata diff"})

        sum1 = self["info"]["summary"] or ""
        sum2 = other["info"]["summary"] or ""
        sum_sim = difflib.SequenceMatcher(lambda x: x in " \t\n", sum1, sum2).ratio()
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
        temp_dir = Path(tempfile.mkdtemp(prefix="aura_pkg_diff_"))
        location_cache = {}
        # Inline cache function as we want this to be temporary within the function scope only
        def get_cached_location(pkg: ReleaseInfo) -> ScanLocation:
            if pkg["url"] not in location_cache:
                pkg_path = temp_dir / pkg["md5_digest"]
                pkg_path.mkdir()
                pkg_path /= pkg["filename"]

                with pkg_path.open("wb") as fd:
                    cache.FileDownloadCache.proxy(url=pkg["url"], fd=fd)

                location_cache[pkg["url"]] = ScanLocation(
                    location=pkg_path,
                    strip_path=str(pkg_path.parent),
                    metadata={"release": pkg, "report_imports": True}
                )
            return location_cache[pkg["url"]]

        try:
            for (x, y) in self.get_diff_candidates(other):
                LOGGER.info(f"Diffing `{x['filename']}` and `{y['filename']}`")

                x_loc = get_cached_location(x)
                x_loc.cleanup = temp_dir
                y_loc = get_cached_location(y)
                y_loc.cleanup = temp_dir
                yield x_loc, y_loc

        except Exception:
            if temp_dir.exists():
                shutil.rmtree(temp_dir)
            raise


class PackageScore:
    @dataclasses.dataclass
    class Value:  # Scoped class specific to package score
        value: int
        normalized: int
        label: str
        explanation: str
        slug: Optional[str] = None

        def __post_init__(self):
            if self.slug is None:
                self.slug = self.label.lower().replace(" ", "_")

        def __int__(self):
            return self.normalized

        def __str__(self):
            return self.label

        def as_row(self) -> Tuple[table.Column, table.Column]:
            s = {"fg": ("green" if self.normalized else "red")}
            return (table.Column(self.label, {"style": s}), table.Column(self.explanation, {"style": s}))

    @dataclasses.dataclass
    class NA:
        label: str
        explanation: str = "N/A"

        def __int__(self):
            return 0

        def as_row(self) -> Tuple[table.Column, table.Column]:
            s = {"style": {"fg": "bright_black"}}
            return (table.Column(self.label, s), table.Column(self.explanation, s))


    def __init__(
            self,
            package_name: str,
            package: Optional[PypiPackage]=None,
            fetch_github: bool=True
    ):
        self.package_name = package_name

        if package is None:
            self.pkg = PypiPackage.from_cached(package_name)
        else:
            self.pkg = package

        self.now = pytz.UTC.localize(datetime.datetime.utcnow())
        self.github = None

        if fetch_github:
            try:
                self.load_github()
            except exceptions.NoSuchRepository:
                LOGGER.warning(f"Repository does not exists: `{self.pkg.source_url}`")

    def load_github(self):
        self.repo_url = self.pkg.source_url
        if self.repo_url is None:
            return

        self.github = github.GitHub.from_url(self.repo_url)

    def score_pypi_downloads(self) -> Union[Value, NA]:
        try:
            for line in config.iter_pypi_stats():
                pkg_name = canonicalize_name(line["package_name"])
                if pkg_name == self.package_name:
                    downloads = int(line.get("downloads", 0))
                    normalized = log_scale(downloads)
                    explanation = f"{downloads} (+{normalized})"
                    return self.Value(downloads, normalized, "PyPI downloads", explanation)
        except ValueError:
            pass
        except MissingFile:
            pass

        return PackageScore.NA("PyPI downloads")

    def score_reverse_dependencies(self) -> Union[Value, NA]:
        try:
            dependencies = get_reverse_dependencies(self.package_name)
        except MissingFile:
            return PackageScore.NA("Reverse dependencies")

        if not dependencies:
            return PackageScore.NA("Reverse dependencies")

        dependencies = len(dependencies)
        normalized = log_scale(dependencies)
        explanation = f"{dependencies} (+{normalized})"

        return self.Value(dependencies, normalized, "Reverse dependencies", explanation)

    def score_github_stars(self) -> Union[Value, NA]:
        if self.github is None:
            return self.NA("GitHub stars")

        stars = self.github.repo["stargazers_count"]
        normalized = log_scale(stars)
        explanation = f"{stars} (+{normalized})"
        return self.Value(stars, normalized, "GitHub stars", explanation)

    def score_github_forks(self) -> Union[Value, NA]:
        if self.github is None:
            return self.NA("GitHub forks")

        forks = self.github.repo["forks"]
        normalized = log_scale(forks)
        explanation = f"{forks} (+{normalized})"
        return self.Value(forks, normalized, "GitHub forks", explanation)

    def score_github_contributors(self) -> Union[Value, NA]:
        if self.github is None:
            return self.NA("GitHub contributors")

        contributors = len(self.github.contributors)
        normalized = log_scale(contributors)
        explanation = f"{contributors} (+{normalized})"
        return self.Value(contributors, normalized, "GitHub contributors", explanation)

    def score_last_commit(self) -> Union[Value, NA]:
        if self.github is None:
            return self.NA("Recent commit")

        last_commit = utils.parse_iso_8601(self.github.repo["pushed_at"])

        if last_commit + datetime.timedelta(days=31*3) >= self.now:
            val = 1
            note = "< 3m"
        else:
            val = 0
            note = "> 3m"

        return self.Value(val, val, "Recent commit", f"{note} (+{val})")

    def score_is_new_on_github(self) -> Union[Value, NA]:
        if self.github is None:
            return self.NA("New on GitHub")

        created = utils.parse_iso_8601(self.github.repo["created_at"])

        if created + datetime.timedelta(days=31*6) <= self.now:
            val = 1
            note = "older than 6m"
        else:
            val = 0
            note = "newer than 6m"

        return self.Value(val, val, "New on GitHub", f"{note} (+{val})")

    def has_multiple_releases(self) -> Value:
        releases = len(self.pkg["releases"])
        normalized = log_scale(releases)
        return self.Value(releases, normalized, "Multiple releases", f"{releases} (+{normalized})")

    def has_source_repository(self) -> Value:
        source = 1 if self.pkg.source_url else 0
        return self.Value(source, source, "Has source repository", f"+{source}")

    def has_documentation(self) -> Value:
        doc = 1 if self.pkg.documentation_url else 0
        return self.Value(doc, doc, "Has documentation", f"+{doc}")

    def has_homepage(self) -> Value:
        homepage = 1 if self.pkg.homepage_url else 0
        return self.Value(homepage, homepage, "Has homepage", f"+{homepage}")

    def has_wheel(self) -> Value:
        wheel = 0
        for r in self.pkg["urls"]:
            if r["packagetype"] == "bdist_wheel":
                wheel = 1
                break

        return self.Value(wheel, wheel, "Has wheel", f"+{wheel}")

    def has_sdist_source(self) -> Value:
        sdist = 0
        for r in self.pkg["urls"]:
            if r["packagetype"] == "sdist" and r.get("python_version") == "source":
                sdist = 1
                break
        return self.Value(sdist, sdist, "Has sdist", f"+{sdist}")

    def get_score_entries(self) -> List[Value]:
        entries = [
            self.score_pypi_downloads(),
            self.score_reverse_dependencies(),
            self.score_github_stars(),
            self.score_github_forks(),
            self.score_github_contributors(),
            self.score_last_commit(),
            self.score_is_new_on_github(),
            self.has_multiple_releases(),
            self.has_source_repository(),
            self.has_documentation(),
            self.has_homepage(),
            self.has_wheel(),
            self.has_sdist_source()
        ]
        return entries

    def get_score_matrix(self) -> dict:
        score_entries = self.get_score_entries()
        total_score = sum(int(x) for x in score_entries)
        score_matrix = {
            "total": total_score,
            "entries": [dataclasses.asdict(x) for x in score_entries]
        }
        return score_matrix

    def get_score_table(self) -> table.Table:
        score_table = table.Table(metadata={"title": f"Package score for '{self.package_name}'"})

        score_entries = self.get_score_entries()
        total_score = sum(int(x) for x in score_entries)

        for x in score_entries:
            score_table += x.as_row()

        total_row = (table.Column("Total score"), table.Column(str(total_score)))
        total_row[0].metadata["style"] = total_row[1].metadata["style"] = {"fg": "blue", "bold": True}
        score_table += total_row

        return score_table


def packagetype_filter(release: ReleaseInfo, packagetype: str="all") -> bool:
    if packagetype == "all":
        return True
    elif packagetype and release.get("packagetype") == packagetype:
        return True
    else:
        return False


def filename_filter(release: ReleaseInfo, filename: Optional[str]=None) -> bool:
    if filename is None:
        return True

    return (release["filename"] == filename)


def md5_filter(release: ReleaseInfo, md5: Optional[str]=None) -> bool:
    if md5 is None:
        return True

    return (md5 == release["md5_digest"])


def get_reverse_dependencies(pkg_name: str) -> List[str]:
    pkg_name = canonicalize_name(pkg_name)
    dataset_path = config.get_reverse_dependencies_path()
    with dataset_path.open("r") as fd:
        dataset = loads(fd.read())

    if pkg_name in dataset:
        return dataset[pkg_name]
    else:
        return []


def get_packages_for_author(author: str) -> List[Tuple[str, str]]:
    repo = xmlrpc.client.ServerProxy(
        "https://pypi.org/pypi", use_builtin_types=True
    )
    return list(repo.user_packages(author))


def log_scale(metric: int, base=10) -> int:
    """
    Normalizes the metric to log scale score
    """
    if metric > 0:
        return math.ceil(math.log(metric, base))
    else:
        return 0
