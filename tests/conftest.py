import os
import json
import tempfile
import contextlib
from pathlib import Path
from unittest import mock

from click.testing import CliRunner, Result
import responses
import pytest


# Definition used to replicate the PyPI mirror file system structure
MIRROR_FILES = {
    "wheel": (
        {
            "name": "wheel-0.34.2-py2.py3-none-any.whl",
            "path": "packages/8c/23/848298cccf8e40f5bbb59009b32848a4c38f4e7f3364297ab3c3e2e2cd14"
        },
        {
            "name": "wheel-0.34.2.tar.gz",
            "path": "packages/75/28/521c6dc7fef23a68368efefdcd682f5b3d1d58c2b90b06dc1d0b805b51ae"
        }
    )
}


cli = None
Rule = None
cfg_path = os.fspath(Path(__file__).parent / 'files' / 'test_config.ini')

os.environ['AURA_CFG'] = cfg_path
assert os.environ.get('AURA_CFG') == cfg_path


class MatchFound(ValueError):
    pass


class Fixtures(object):
    BASE_PATH = Path(__file__).parent / 'files'

    def path(self, path: str='') -> str:
        return os.fspath(self.BASE_PATH / path)

    def read(self, path):
        with open(self.path(path), 'r') as fp:
            return fp.read()

    def scan_test_file(self, name, decode=True, args=None):
        pth = self.path(name)
        cmd = ['scan', os.fspath(pth), '--format', 'json', '-v']

        if args:
            cmd += args

        result = self.get_cli_output(cmd)
        if decode:
            return json.loads(result.output)
        else:
            return result

    def get_cli_output(self, args, check_exit_code=True) -> Result:
        global cli
        if cli is None:
            from aura import cli

        runner = CliRunner(mix_stderr=False)
        result = runner.invoke(cli.cli, args=args)

        if check_exit_code:
            assert result.exit_code == 0, result.stdout
        if result.exception and type(result.exception) != SystemExit:
            raise result.exception

        return result

    def get_raw_ast(self, src):
        from aura import python_executor
        from aura.analyzers import python_src_inspector

        INSPECTOR_PATH = os.path.abspath(python_src_inspector.__file__)

        out = python_executor.run_with_interpreters(command = [INSPECTOR_PATH, '-'], stdin=bytes(src, 'utf-8'))
        return out['ast_tree']['body']

    def get_full_ast(self, src):
        """
        Get a full AST tree after all stages has been applied, e.g. rewrite & taint analysis
        """
        from aura.analyzers.python.taint.visitor import TaintAnalysis

        with tempfile.NamedTemporaryFile() as fd:
            fd.write(bytes(src, 'utf-8'))
            meta = {
                'path': fd.name,
                'source': 'cli'
            }
            analyzer = TaintAnalysis.from_cache(source=fd.name, metadata=meta)
            if not analyzer.traversed:
                analyzer.traverse()
            return analyzer.tree['ast_tree']

    def scan_and_match(self, input_file, matches):
        output = self.scan_test_file(input_file)
        for x in matches:
            assert any(match_rule(h, x) for h in output['hits']), x


def match_rule(source, target) -> bool:
    """
    Fuzzy match the source structure onto the target
    If something is defined in the target (such as dict key) it must also be present in the source
    Additional data (keys, list items etc...) that are present in source but not target are ignored
    This fuzzy match works recursively for nested structures

    :param source: input structure that we want to match on
    :param target: pattern that we match against, all structure items/keys from target must be present in source
    :return: bool
    """
    global Rule
    if Rule is None:
        from aura.analyzers.rules import Rule

    if isinstance(source, Rule):
        source = source._asdict()

    if type(target) != type(source):
        return False
    elif isinstance(target, list):
        for t in target:
            if not any(match_rule(s, t) for s in source):
                return False
        return True
    # Fallback to direct comparison if target is dict
    elif not isinstance(target, dict):
        return target == source

    # Check that all the keys from a target are present in the source using recursive fuzzy match
    for x in target.keys():
        # Fail if the key is not present in a source  or is of a different type then target
        if type(target[x]) != type(source.get(x)):
            return False
        # Recurse if target key value is a dict
        if isinstance(target[x], dict):
            if not match_rule(source[x], target[x]):
                return False
        # Recurse if a target key value is a list
        elif isinstance(target[x], list):
            # We don't care about the ordering so any source list item can match
            for t in target[x]:
                if any(match_rule(s, t) for s in source[x]):
                    return True
        # Fall back to direct comparison
        else:
            if target[x] != source[x]:
                return False

    return True


@pytest.fixture(scope="module")
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


@pytest.fixture(scope="module")
def simulate_mirror(fixtures):
    """
    Thjs fixture creates a file/directory structure that simulates an offline PyPI mirror
    Used to test the `mirror://` bandersnatch integration for scanning the whole PyPI repository
    """
    from aura import mirror as amirror

    with tempfile.TemporaryDirectory(prefix="aura_test_mirror_") as mirror:
        pmirror = Path(mirror)
        assert pmirror.is_dir()
        os.mkdir(pmirror / "json")

        for pkg, pkg_files in MIRROR_FILES.items():
            # copy the package JSON metadata
            os.link(
                fixtures.path(f"mirror/{pkg}.json"),
                pmirror / "json" / pkg
            )

            for p in pkg_files:
                os.makedirs(pmirror / p["path"])
                os.link(
                    fixtures.path(f"mirror/{p['name']}"),
                    os.fspath(pmirror / p["path"] / p["name"])
                )

        with mock.patch.object(amirror.LocalMirror, "get_mirror_path", return_value=pmirror):
            assert pmirror.is_dir()
            yield mirror


@pytest.fixture()
def mock_github(fixtures):
    pth = fixtures.path("github_api_mock.json")
    with open(pth, "r") as fd:
        mock_data = json.loads(fd.read())

    def _callback(request):
        resp = json.dumps(mock_data[request.url])
        return (200, {}, resp)

    def _activate_mock(rsps):
        for url in mock_data.keys():
            rsps.add_callback(
                responses.GET,
                url,
                callback=_callback
            )

    return _activate_mock


@pytest.fixture()
def mock_pypi_rest_api(fixtures):
    pkgs = (
        "https://files.pythonhosted.org/packages/8c/23/848298cccf8e40f5bbb59009b32848a4c38f4e7f3364297ab3c3e2e2cd14/wheel-0.34.2-py2.py3-none-any.whl",
        "https://files.pythonhosted.org/packages/75/28/521c6dc7fef23a68368efefdcd682f5b3d1d58c2b90b06dc1d0b805b51ae/wheel-0.34.2.tar.gz"
    )

    pth = fixtures.path("pypi_api_mock.json")
    with open(pth, "r") as fd:
        mock_data = json.loads(fd.read())


    def _callback_download(request):
        filename = request.url.split("/")[-1]
        file_pth = fixtures.path(f"mirror/{filename}")
        assert os.path.exists(file_pth)
        with open(file_pth, "rb") as fd:
            return (200, {}, fd.read())


    def _callback(request):
        resp = json.dumps(mock_data[request.url])
        return (200, {}, resp)


    def _activate_mock(rsps):
        for url in mock_data.keys():
            rsps.add_callback(
                responses.GET,
                url=url,
                callback=_callback
            )

        for url in pkgs:
            rsps.add_callback(
                responses.GET,
                url=url,
                callback=_callback_download
            )


    return _activate_mock
