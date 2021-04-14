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


class LocalMirror:
    _mirror_path = None  # Used for caching

    @classmethod
    def get_mirror_path(cls) -> typing.Optional[Path]:
        if cls._mirror_path is None:
            if env_path := os.environ.get('AURA_MIRROR_PATH', None):
                cls._mirror_path = Path(env_path)
            else:
                cls._mirror_path = Path(CFG["aura"]["mirror"])

        return cls._mirror_path

    @classmethod
    def list_packages(cls) -> typing.Generator[Path, None, None]:
        yield from (cls.get_mirror_path() / "json").iterdir()

    def get_json(self, package_name) -> dict:
        assert package_name
        json_path = self.get_mirror_path() / "json" / package_name
        target = cache.MirrorJSON.proxy(src=json_path)

        if not target.is_file():
            json_path = self.get_mirror_path() / "json" / canonicalize_name(package_name)
            target = cache.MirrorJSON.proxy(src=json_path)
            if not target.exists():
                raise NoSuchPackage(package_name)

        return json.loads(target.read_text())

    def url2local(self, url: typing.Union[ParseResult, str]) -> Path:
        if not isinstance(url, ParseResult):
            url = urlparse(url)

        pth = url.path.lstrip("/")
        return self.get_mirror_path() / pth
