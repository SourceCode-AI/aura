# -*- coding: utf-8 -*-
import os
import json
import typing
from pathlib import Path
from urllib.parse import urlparse, ParseResult

from packaging.utils import canonicalize_name

from . import cache
from .exceptions import NoSuchPackage
from .config import CFG


class LocalMirror(object):
    @classmethod
    def get_mirror_path(cls) -> Path:
        env_path = os.environ.get('AURA_MIRROR_PATH', None)
        if env_path:
            return Path(env_path)

        return Path(CFG["aura"]["mirror"])

    def list_packages(self) -> typing.Generator[Path, None, None]:
        yield from (self.get_mirror_path() / "json").iterdir()

    def get_json(self, package_name):
        if package_name is None:
            raise NoSuchPackage(f"Could not find package '{package_name}' json at the mirror location")

        json_path = self.get_mirror_path() / "json" / package_name

        if not json_path.is_file():
            json_path = self.get_mirror_path() / "json" / canonicalize_name(package_name)
            if not json_path.exists():
                raise NoSuchPackage(package_name)

        target = cache.Cache.proxy_mirror_json(src=json_path)

        with open(target, "r") as fd:
            return json.loads(fd.read())

    def url2local(self, url):
        if not isinstance(url, ParseResult):
            url = urlparse(url)

        pth = url.path.lstrip("/")
        return self.get_mirror_path() / pth
