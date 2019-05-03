import os
import contextlib
from pathlib import Path

import pytest


cfg_path = Path(__file__).parent / 'files' / 'test_config.ini'

os.environ.setdefault('AURA_CFG', os.fspath(cfg_path))


class Fixtures(object):
    BASE_PATH = Path(__file__).parent / 'files'

    def path(self, path=''):
        return os.fspath(self.BASE_PATH / path)

    def read(self, path):
        with open(self.path(path), 'r') as fp:
            return fp.read()


@pytest.fixture
def fixtures():
    yield Fixtures()


@pytest.fixture
def chdir():
    @contextlib.contextmanager
    def _(path):
        curr_dir = os.getcwd()
        os.chdir(path)
        yield
        os.chdir(curr_dir)
    return _
