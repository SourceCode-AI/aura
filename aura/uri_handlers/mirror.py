# -*- coding: utf-8 -*-
import typing
from urllib.parse import urlparse, ParseResult, parse_qs

from .base import URIHandler, ScanLocation
from .. import mirror
from ..package import PypiPackage


class MirrorHandler(URIHandler):
    scheme = "mirror"

    def __init__(self, uri: ParseResult):
        self.uri = uri
        self.opts = {"release": "latest"}

        self.package_name = uri.hostname
        self.mirror_path = mirror.LocalMirror.get_mirror_path()  # Path(uri.path)

        if self.package_name == "$all":
            self.package = "$all"
        else:
            self.package = PypiPackage.from_local_mirror(self.package_name)

        self.opts.update(parse_qs(uri.query))
        self.comment = uri.fragment.lstrip("#")

    @property
    def metadata(self):
        return {"package": self.package_name, "package_opts": self.opts}

    def get_paths(self, metadata: dict=None, package=None) -> typing.Generator[ScanLocation, None, None]:
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
                meta = {"depth": 0}

            meta.setdefault("package", {})["info"] = x

            pkg_path = self.mirror_path / urlparse(x["url"]).path.lstrip("/")
            if pkg_path.exists():
                yield ScanLocation(
                    location=pkg_path,
                    metadata=meta
                )
