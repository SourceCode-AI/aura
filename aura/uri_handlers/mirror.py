#-*- coding: utf-8 -*-
import pathlib
from urllib.parse import urlparse, ParseResult, parse_qs

from .base import URIHandler
from ..package import PypiPackage


class MirrorHandler(URIHandler):
    scheme = 'mirror'

    def __init__(self, uri: ParseResult):
        self.uri = uri
        self.opts = {
            'release': 'latest'
        }

        self.package_name = uri.hostname
        self.mirror_path = pathlib.Path(uri.path)
        self.package = PypiPackage.from_local_mirror(self.package_name, mirror_path=self.mirror_path)

        self.opts.update(parse_qs(uri.query))
        self.comment = uri.fragment.lstrip('#')

    def get_paths(self):
        if self.opts['release'] == 'latest':
            release = self.package.get_latest_release()
        else:
            release = self.opts['release']

        for x in self.package['releases'][release]:
            pkg_path = self.mirror_path / urlparse(x['url']).path.lstrip('/')
            if pkg_path.exists():
                yield pkg_path

