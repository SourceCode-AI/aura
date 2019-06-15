import os
import json
import contextlib
from pathlib import Path

from click.testing import CliRunner
import pytest


cli = None
Rule = None
cfg_path = os.fspath(Path(__file__).parent / 'files' / 'test_config.ini')

os.environ['AURA_CFG'] = cfg_path
assert os.environ.get('AURA_CFG') == cfg_path


class Fixtures(object):
    BASE_PATH = Path(__file__).parent / 'files'

    def path(self, path=''):
        return os.fspath(self.BASE_PATH / path)

    def read(self, path):
        with open(self.path(path), 'r') as fp:
            return fp.read()

    def scan_test_file(self, name, decode=True):
        pth = self.path(name)

        result = self.get_cli_output(
            ['scan', os.fspath(pth), '--format', 'json']
        )
        if decode:
            return json.loads(result.output)
        else:
            return result

    def get_cli_output(self, args):
        global cli
        if cli is None:
            from aura import cli

        runner = CliRunner()
        result = runner.invoke(cli.cli, args=args)

        if result.exception:
            raise result.exception

        assert result.exit_code == 0
        return result


def match_rule(source, target):
    global Rule
    if Rule is None:
        from aura.analyzers.rules import Rule

    if isinstance(source, Rule):
        source = source._asdict()

    for x in target.keys():
        if type(target[x]) != type(source.get(x)):
            return False
        if isinstance(target[x], dict):
            if not match_rule(source[x], target[x]):
                return False
        elif isinstance(target[x], list):
            assert len(set(target[x]) - set(source[x])) == 0
        else:
            if target[x] != source[x]:
                return False

    return True


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


@pytest.fixture
def fuzzy_rule_match():
    return match_rule
