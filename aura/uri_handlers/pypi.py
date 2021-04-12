# -*- coding: utf-8 -*-
import os
import shutil
import tempfile
import pathlib
import urllib.parse
from typing import Generator, Tuple, Optional

from .base import URIHandler, PackageProvider, ScanLocation
from ..exceptions import UnsupportedDiffLocation
from ..package import PypiPackage


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
        self.opts = {"release": "latest", "cleanup": False}

        if self.opts.get("download_dir"):
            self.opts["download_dir"] = pathlib.Path(self.opts["download_dir"])

        self.release = self.opts["release"]
        self.opts.update(urllib.parse.parse_qs(uri.query))
        self.comment = uri.fragment.lstrip("#")

    @property
    def package(self):
        return self.pkg

    @property
    def metadata(self):
        m = {
            "uri": self.uri,
            "scheme": self.scheme,
            "package_name": self.package_name,
            "package_release": self.opts["release"],
        }
        return m

    def get_paths(self, metadata: Optional[dict]=None):
        if self.opts.get("download_dir") is None:
            self.opts["download_dir"] = pathlib.Path(
                tempfile.mkdtemp(prefix="aura_pypi_download_")
            )
            self.opts["cleanup"] = True

        for f in self.package.download_release(
            dest=self.opts["download_dir"], release=self.release
        ):
            loc = self.opts["download_dir"] / f["filename"]

            if metadata:
                meta = metadata.copy()
            else:
                meta = {"depth": 0, "report_imports": True, "package_instance": self.package}

            meta.update(self.metadata)
            meta.setdefault("package", {})["info"] = f

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
