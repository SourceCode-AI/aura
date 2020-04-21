# -*- coding: utf-8 -*-
import math
import datetime
import tempfile
import functools
import xmlrpc.client
from urllib.parse import urlparse, ParseResult
from pathlib import Path
from contextlib import contextmanager

import pytz
import requests
import requirements
from packaging import version
from dateutil import parser


from . import config
from . import github
from . import utils
from . import exceptions
from .mirror import LocalMirror


LOGGER = config.get_logger(__name__)
CONSTRAINS = {
    "<": lambda x, ver: x < ver,
    "<=": lambda x, ver: x <= ver,
    "!=": lambda x, ver: x != ver,
    "==": lambda x, ver: x == ver,
    ">=": lambda x, ver: x >= ver,
    ">": lambda x, ver: x > ver,
}


class PypiPackage:
    mirror = None

    def __init__(self, name, info, source=None):
        self.name = name
        self.info = info
        self.source = source
        self.requirements = []
        self._parse_requirements()

    @classmethod
    def from_pypi(cls, name, *args, **kwargs):
        resp = requests.get(f"https://pypi.org/pypi/{name}/json")
        if resp.status_code == 404:
            LOGGER.error(f"Package {name} does not exists on PyPI")
            raise exceptions.NoSuchPackage(f"{name} on PyPI repository")

        kwargs["info"] = resp.json()
        kwargs["source"] = "pypi"

        return cls(name, *args, **kwargs)

    @classmethod
    def from_local_mirror(cls, name, *args, **kwargs):
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

    def __getitem__(self, item):
        return self.info[item]

    def _parse_requirements(self):
        if not self["info"].get("requires_dist"):
            return

        for req_line in self["info"]["requires_dist"]:
            for req in requirements.parse(req_line):
                # FIXME: reference lost # req = utils.filter_empty_dict(dict(req))
                self.requirements.append(req)

    def find_release(self, constrains=(), find_highest=True):
        """
        Find the releases of a package matching the given constrains
        Constrains are list of tuples with 2 elements in form (constrain, version)
        The constrain itself is a string such as '<', '>=', '!=' as defined by requirements format
        Version is a string of version to which the constrain apply

        :param constrains: list of constrains
        :param find_highest: Flag; just the highest possible version should be returned or all matching versions
        :return: list of matching version or just the highest version (or None if no matches found)
        """
        conditions = []
        for cond, c_ver in constrains:
            c_ver = version.parse(c_ver)

            if cond in CONSTRAINS:
                condition = functools.partial(CONSTRAINS[cond], ver=c_ver)
            else:
                continue

            conditions.append(condition)

        releases = [version.parse(x) for x in self["releases"].keys()]
        releases = list(
            filter(lambda x: all(map(lambda cond: cond(x), conditions)), releases)
        )
        if find_highest:
            if releases:
                return str(max(releases))
            else:
                return None
        else:
            return [str(x) for x in releases]

    def get_latest_release(self):
        return self.info["info"]["version"]

    def download_release(self, dest, release="latest"):
        dest = Path(dest)

        if release == "latest":
            release = self.get_latest_release()

        urls = self.info["releases"][release]
        files = []

        for url in urls:
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


class PackageScore:
    def __init__(self, package_name):
        self.package_name = package_name
        self.pkg = PypiPackage.from_pypi(package_name)
        self.now = pytz.UTC.localize(datetime.datetime.utcnow())
        self.github = None

        self.__load_github()

    def __load_github(self):
        self.repo_url = self.pkg.info["info"]["project_urls"].get("Source")
        if self.repo_url is None:
            return

        self.github = github.GitHub.from_url(self.repo_url)

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

    def score_last_commit(self) -> int:
        if self.github is None:
            return 0

        last_commit = parser.parse(self.github.repo["pushed_at"])

        if last_commit + datetime.timedelta(days=31*3) >= self.now:
            return 1
        else:
            return 0

    def score_is_new_on_github(self) -> int:
        if self.github is None:
            return 0

        created = parser.parse(self.github.repo["created_at"])

        if created + datetime.timedelta(days=31*6) <= self.now:
            return 1
        else:
            return 0

    def has_multiple_releases(self) -> int:
        if len(self.pkg["releases"]) > 1:
            return 1
        else:
            return 0

    def has_source_repository(self) -> int:
        if self.pkg["info"]["project_urls"].get("Source"):
            return 1
        else:
            return 0

    def has_documentation(self) -> int:
        if self.pkg["info"]["project_urls"].get("Documentation"):
            return 1
        else:
            return 0

    def has_homepage(self) -> int:
        if self.pkg["info"]["project_urls"].get("Homepage"):
            return 1
        else:
            return 0

    def has_wheel(self) -> int:
        for r in self.pkg["urls"]:
            if r["packagetype"] == "bdist_wheel":
                return 1
        return 0

    def has_sdist_source(self):
        for r in self.pkg["urls"]:
            if r["packagetype"] == "sdist" and r.get("python_version") == "source":
                return 1
        return 0

    def get_score_matrix(self):
        score_matrix = {
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


if __name__ == "__main__":
    import sys, pprint

    pkg_score = PackageScore(sys.argv[1])
    pprint.pprint(pkg_score.get_score_matrix())
