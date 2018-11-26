#-*- coding: utf-8 -*-

from pathlib import Path
from urllib.parse import urlparse, ParseResult

from . import utils
from . import json
from .exceptions import NoSuchPackage


class LocalMirror(object):
    def __init__(self, mirror_path):
        self.mirror_path = Path(mirror_path)

    def list_packages(self):
        yield from (self.mirror_path / 'json').iterdir()

    def get_json(self, package_name):
        json_path = self.mirror_path / 'json' / package_name
        if not json_path.is_file():
            json_path = self.mirror_path / 'json' / self._lookup_package(package_name)

        with open(json_path, 'r') as fd:
            return json.loads(fd.read())

    def _lookup_package(self, package_name):
        package_name = utils.normalize_name(package_name)
        packages = {utils.normalize_name(x.name): x.name for x in self.list_packages()}
        lookup = packages.get(package_name)
        if lookup is not None:
            return lookup
        else:
            raise NoSuchPackage(package_name)

    def url2local(self, url):
        if not isinstance(url, ParseResult):
            url = urlparse(url)

        pth = url.path.lstrip('/')
        return self.mirror_path / pth
