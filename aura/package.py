#-*- coding: utf-8 -*-
import tempfile
import functools
from urllib.parse import urlparse, ParseResult
from pathlib import Path
from contextlib import contextmanager

import requests
import requirements
from packaging import version

from . import config
from . import utils
from . import exceptions
from .mirror import LocalMirror


LOGGER = config.get_logger(__name__)
CONSTRAINS = {
    '<': lambda x, ver: x < ver,
    '<=': lambda x, ver: x <= ver,
    '!=': lambda x, ver: x != ver,
    '==': lambda x, ver: x == ver,
    '>=': lambda x, ver: x >= ver,
    '>': lambda x, ver: x > ver,
}


class PypiPackage():
    mirror = None

    def __init__(self, name, info, source=None):
        self.name = name
        self.info = info
        self.source = source
        self.requirements = []
        self._parse_requirements()

    @classmethod
    def from_pypi(cls, name, *args, **kwargs):
        resp = requests.get(f'https://pypi.org/pypi/{name}/json')
        if resp.status_code == 404:
            LOGGER.error(f"Package {name} does not exists on PyPI")
            raise exceptions.NoSuchPackage(f"{name} on PyPI repository")

        kwargs['info'] = resp.json()
        kwargs['source'] = 'pypi'

        return cls(name, *args, **kwargs)

    @classmethod
    def from_local_mirror(cls, name, *args, **kwargs):
        if cls.mirror is None:
            cls.mirror = LocalMirror()

        kwargs['source'] = 'local_mirror'
        kwargs['info'] = cls.mirror.get_json(name)

        return cls(name, *args, **kwargs)

    def __getitem__(self, item):
        return self.info[item]

    def _parse_requirements(self):
        if not self['info'].get('requires_dist'):
            return

        for req_line in self['info']['requires_dist']:
            for req in requirements.parse(req_line):
                req = utils.filter_empty_dict(dict(req))
                self.requirements.append(req)

    def find_release(self, constrains, find_highest=True):
        """
        Find the releases of a package matching the given constrains
        Constrains are list of tuples with 2 elements in form (constrain, version)
        The constrain itself is a string such as '<', '>=', '!=' as defined by requirements format
        Version is a string of version to which the constrain apply

        :param constrains: list of constrains
        :param find_highest: Flag just the highest possible version should be returned or all matching versions
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

        releases = [version.parse(x) for x in self['releases'].keys()]
        releases = list(filter(lambda x: all(map(lambda cond: cond(x), conditions)), releases))
        if find_highest:
            if releases:
                return str(max(releases))
            else:
                return None
        else:
            return [str(x) for x in releases]

    def get_latest_release(self):
        return self.info['info']['version']

    def download_release(self, dest, release='latest'):
        dest = Path(dest)

        if release == 'latest':
            release = self.get_latest_release()

        urls = self.info['releases'][release]
        files = []

        for url in urls:
            with open(dest/url['filename'], 'wb') as fd:
                utils.download_file(url['url'], fd)
            files.append(url['filename'])

        return files

    @contextmanager
    def url2local(self, url:str):
        if not isinstance(url, ParseResult):
            url = urlparse(url)

        if self.mirror is not None:
            yield self.mirror.url2local(url)
        else:
            suffix = '_' + url.path.split('/')[-1]
            with tempfile.NamedTemporaryFile(prefix='aura_package_', suffix=suffix) as tmp_file:
                utils.download_file(url.geturl(), tmp_file)
                yield Path(tmp_file.name)
