# -*- coding: utf-8 -*-
from urllib.parse import urlparse, ParseResult, parse_qs
from typing import Optional, Generator

from .base import URIHandler, ScanLocation
from .. import cache
from .. import mirror
from ..package import PypiPackage


class MirrorHandler(URIHandler):
    scheme = "mirror"

    def __init__(self, uri: ParseResult):
        self.uri = uri
        self.opts = {"release": "latest"}

        self.package_name = uri.hostname
        self.mirror_path = mirror.LocalMirror.get_mirror_path()  # Path(uri.path)
        self.package = PypiPackage.from_cached(self.package_name)

        self.opts.update(parse_qs(uri.query))
        self.comment = uri.fragment.lstrip("#")

    @property
    def metadata(self):
        return {
            "uri": self.uri,
            "scheme": self.scheme,
            "package_name": self.package_name,
            "package_opts": self.opts  # TODO: pypi scheme is using `package_release`, unify this
        }

    def get_paths(self, metadata: Optional[dict]=None, package=None) -> Generator[ScanLocation, None, None]:
        if package is None:
            package = self.package

        if self.opts["release"] == "latest":
            release = package.get_latest_release()
        else:
            release = self.opts["release"]

        for x in self.package["releases"][release]:
            if metadata:
                meta = metadata.copy()
            else:
                meta = {"depth": 0, "report_imports": True, "package_instance": self.package}

            meta.update(self.metadata)
            meta.setdefault("package", {})["info"] = x
            pkg_path = self.mirror_path / urlparse(x["url"]).path.lstrip("/")
            target = cache.MirrorFile.proxy(src=pkg_path)

            if target:
                yield ScanLocation(
                    location=target,
                    metadata=meta
                )
