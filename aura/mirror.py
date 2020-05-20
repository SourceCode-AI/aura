# -*- coding: utf-8 -*-
import os
import json
import typing
from pathlib import Path
from urllib.parse import urlparse, ParseResult

from packaging.utils import canonicalize_name

from .exceptions import NoSuchPackage
from .config import CFG


class LocalMirror(object):
    def __init__(self, mirror_path=None):
        if mirror_path is None:
            self.mirror_path = self.get_mirror_path()
        else:
            self.mirror_path = Path(mirror_path)

    @classmethod
    def get_mirror_path(cls) -> Path:
        env_path = os.environ.get('AURA_MIRROR_PATH', None)
        if env_path:
            return Path(env_path)

        return Path(CFG["aura"]["mirror"])

    def list_packages(self) -> typing.Generator[Path, None, None]:
        yield from (self.mirror_path / "json").iterdir()

    def get_json(self, package_name):
        if package_name is None:
            raise NoSuchPackage(f"Could not find package '{package_name}' json at the mirror location")

        json_path = self.mirror_path / "json" / package_name

        if not json_path.is_file():
            json_path = self.mirror_path / "json" / self._lookup_package(package_name)

        with open(json_path, "r") as fd:
            return json.loads(fd.read())

    def _lookup_package(self, package_name):
        package_name = canonicalize_name(package_name)
        packages = {canonicalize_name(x.name): x.name for x in self.list_packages()}
        lookup = packages.get(package_name)
        if lookup is not None:
            return lookup
        else:
            raise NoSuchPackage(package_name)

    def url2local(self, url):
        if not isinstance(url, ParseResult):
            url = urlparse(url)

        pth = url.path.lstrip("/")
        return self.mirror_path / pth
