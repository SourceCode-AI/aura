# -*- coding: utf-8 -*-
import os
import shutil
import tempfile
import pathlib
import urllib.parse
from typing import Generator, Tuple, Optional, Dict, Any, List

from packaging.utils import canonicalize_name

from .base import URIHandler, PackageProvider, ScanLocation
from ..cache import FileDownloadCache
from ..exceptions import UnsupportedDiffLocation
from ..package import PypiPackage
from ..type_definitions import ReleaseInfo


class PyPiHandler(URIHandler, PackageProvider):
    scheme = "pypi"
    help = """
    PyPI URI handler:\n
    Use/download package directly as is published on PyPi\n
    Format 'pypi://<package_name>[?release=<version>]'\n
    \n
    Examples:\n
    - pypi://requests\n
    - pypi://simplejson?version=3.16.0
    """

    def __init__(self, uri: urllib.parse.ParseResult):
        super().__init__(uri)

        self.uri = uri
        self.package_name = uri.netloc
        self.pkg = PypiPackage.from_cached(name=self.package_name)
        self.file_name = uri.path.lstrip("/")
        self.opts : Dict[str, Any] = {"cleanup": False}

        if self.opts.get("download_dir"):
            self.opts["download_dir"] = pathlib.Path(self.opts["download_dir"])


        parsed_qs = parse_qs(uri.query)
        self.opts.update(parsed_qs)

        self.filename = self.opts.get("filename")
        self.md5 = self.opts.get("md5")

        if self.filename or self.md5 and not parsed_qs.get("release"):
            self.release = "all"
        else:
            self.release = parsed_qs.get("release", "latest")

        self.comment = uri.fragment.lstrip("#")

    @property
    def package(self):
        return self.pkg

    @property
    def metadata(self):
        m = {
            "uri": self.uri,
            "scheme": self.scheme,
            "package_name": canonicalize_name(self.package_name),
        }

        if self.release == "latest":
            m["package_release"] = self.pkg.info["info"]["version"]
        else:
            m["package_release"] = self.release

        return m

    def list_releases(self, all=None) -> List[ReleaseInfo]:
        if all is None:
            all = (self.release == "all")

        filtered = self.package.filter_package_types(
            release=self.release,
            filename=self.filename,
            md5=self.md5
        )

        if not all:
            filtered = filtered[:1]

        return filtered

    def get_paths(self, metadata: Optional[dict]=None):
        if self.opts.get("download_dir") is None:
            self.opts["download_dir"] = pathlib.Path(
                tempfile.mkdtemp(prefix="aura_pypi_download_")
            )
            self.opts["cleanup"] = True

        for release in self.list_releases():
            loc = self.opts["download_dir"] / release["filename"]

            with loc.open("wb") as fd:
                FileDownloadCache.proxy(url=release["url"], fd=fd)

            if metadata:
                meta = metadata.copy()
            else:
                meta = {"depth": 0, "report_imports": True, "package_instance": self.package}

            meta.update(self.metadata)
            meta["package_file"] = release["filename"]
            meta.setdefault("package", {})["info"] = release
            meta["name"] = f"PyPI package {release['filename']}"

            yield ScanLocation(
                location=loc,
                strip_path=os.fspath(self.opts["download_dir"]),
                metadata=meta
            )

    def get_diff_paths(
            self,
            other: URIHandler
    )-> Generator[Tuple[ScanLocation, ScanLocation], None, None]:
        if isinstance(other, PyPiHandler):
            yield self.package.score.get_score_table()
            yield other.package.score.get_score_table()
            yield self.package._cmp_info(other.package)

            yield from self.package._cmp_archives(other.package)
        else:
            raise UnsupportedDiffLocation()

    def cleanup(self):
        if self.opts.get("cleanup", False) and self.opts["download_dir"].exists():
            shutil.rmtree(self.opts["download_dir"])


def parse_qs(query: str) -> dict:
    q = {}

    for name, value in urllib.parse.parse_qs(query).items():
        if type(value) == list:
            value = value[0]

        q[name] = value

    return q
