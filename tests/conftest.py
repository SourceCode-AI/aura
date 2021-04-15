import os
import re
import sys
import json
import string
import random
import pprint
import inspect
import tempfile
import contextlib
from pathlib import Path
from unittest import mock
from typing import Pattern

from click.testing import CliRunner, Result
import responses
import tqdm
import pytest


os.environ["AURA_NO_CACHE"] = "true"

if "AURA_MIRROR_PATH" in os.environ:
    os.unsetenv("AURA_MIRROR_PATH")


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
        },
        {
            "name": "wheel-0.33.0-py2.py3-none-any.whl",
            "path": "packages/7c/d7/20bd3c501f53fdb0b7387e75c03bd1fce748a1c3dd342fc53744e28e3de1/wheel-0.33.0-py2.py3-none-any.whl"
        }
    )
}


PYPI_STATS = [
    {"package_name": "flask", "downloads": "15321221"},
    {"package_name": "requests", "downloads": "73783549"},
    {"package_name": "pip", "downloads": "53292414"},
    {"package_name": "jinja2", "downloads": "14341233"},
    {"package_name": "botocore", "downloads": "46938232"},
    {"package_name": "pyyaml", "downloads": "37729212"},
    {"package_name": "futures", "downloads": "27441369"},
    {"package_name": "urllib3", "downloads": "65405956"},
    {"package_name": "google-api-core", "downloads": "11263406"}
]


REGEX_TYPE = type(re.compile(""))


cli = None
Detection = None


class MatchFound(ValueError):
    pass


class Fixtures(object):
    BASE_PATH = Path(__file__).parent / "files"

    def path(self, path: str='') -> str:
        return os.fspath(self.BASE_PATH / path)

    def read(self, path):
        with open(self.path(path), 'r') as fp:
            return fp.read()

    def scan_test_file(self, name, decode=True, args=None):
        if name.startswith("mirror://"):
            pth = name
        else:
            pth = os.fspath(self.path(name))

        cmd = ["scan", pth]

        if args:
            cmd += args

        if ("--format" not in cmd) and ("-f" not in cmd):
            cmd += ["--format", "json"]

        result = self.get_cli_output(cmd)
        if decode:
            try:
                return json.loads(result.output)
            except Exception:
                print(result.output, file=sys.stdout)
                raise
        else:
            return result

    def get_cli_output(self, args, check_exit_code=True) -> Result:
        global cli
        if cli is None:
            from aura import cli

        runner = CliRunner(mix_stderr=False)
        result = runner.invoke(cli.cli, args=args)

        if result.exception and (type(result.exception) != SystemExit or check_exit_code):
            raise result.exception

        if check_exit_code:
            assert result.exit_code == 0, (result.stdout, result.stderr)

        return result

    def get_raw_ast(self, src):
        from aura import python_executor
        from aura.analyzers import python_src_inspector

        INSPECTOR_PATH = os.path.abspath(python_src_inspector.__file__)

        out = python_executor.run_with_interpreters(command = [INSPECTOR_PATH, "-"], stdin=bytes(src, "utf-8"))
        return out["ast_tree"]["body"]

    def get_full_ast(self, src):
        """
        Get a full AST tree after all stages has been applied, e.g. rewrite & taint analysis
        """
        from aura.analyzers.python.visitor import Visitor
        from aura.uri_handlers.base import ScanLocation

        with tempfile.NamedTemporaryFile() as fd:
            fd.write(bytes(src, 'utf-8'))
            loc = ScanLocation(
                location=Path(fd.name),
                metadata={"source": "cli"}
            )

            visitor = Visitor.run_stages(location=loc)
            return visitor.tree["ast_tree"]

    def scan_and_match(self, input_file, matches, excludes=None, **kwargs):
        output = self.scan_test_file(input_file, **kwargs)

        for x in matches:
            try:
                assert any(match_rule(h, x) for h in output["detections"]), (x, output["detections"])
            except AssertionError:
                for h in output["detections"]:
                    pprint.pprint(h)
                raise

        if excludes:
            for x in excludes:
                for hit in output["detections"]:
                    assert not match_rule(hit, x), hit

        for hit in output["detections"]:
            assert hit["type"] != "ASTParseError"


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
    # We want to avoid importing the Rule in top level
    # as the tests can change the aura configuration which is influenced by import
    global Detection
    if Detection is None:
        from aura.analyzers.detections import Detection

    if isinstance(source, Detection):
        source = source._asdict()

    # Check if target is a regex and apply it to source string
    if (isinstance(target, Pattern) or isinstance(target, REGEX_TYPE)) and type(source) == str:
        return bool(target.match(source))

    # Check if target is a function (that should return bool)
    if inspect.isfunction(target):
        return target(source)

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
        if type(target[x]) == REGEX_TYPE and type(source[x]) == str:
            return bool(target[x].match(source[x]))

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



def pytest_addoption(parser):
    parser.addoption(
        "--e2e", action="store_true", default=False, help="run e2e tests"
    )


def pytest_collection_modifyitems(config, items):
    if config.getoption("--e2e"):
        # End-to-end tests specified in cli, don't skip e2e tests
        return

    skip_e2e = pytest.mark.skip(reason="Need to specify --e2e to run end-to-end tests")
    for item in items:
        if "e2e" in item.keywords:
            item.add_marker(skip_e2e)


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


@pytest.fixture(scope="function")
def simulate_mirror(fixtures):
    """
    Thjs fixture creates a file/directory structure that simulates an offline PyPI mirror
    Used to test the `mirror://` bandersnatch integration for scanning the whole PyPI repository
    """
    from aura import mirror as amirror

    with tempfile.TemporaryDirectory(prefix="aura_test_mirror_") as mirror:
        pmirror = Path(mirror)
        json_path = pmirror / "json"
        json_path.mkdir(parents=True)

        for pkg, pkg_files in MIRROR_FILES.items():
            # copy the package JSON metadata
            os.symlink(
                fixtures.path(f"mirror/{pkg}.json"),
                json_path / pkg
            )

            for p in pkg_files:
                os.makedirs(pmirror / p["path"])
                os.symlink(
                    fixtures.path(f"mirror/{p['name']}"),
                    os.fspath(pmirror / p["path"] / p["name"])
                )

        with mock.patch.object(amirror.LocalMirror, "get_mirror_path", return_value=pmirror):
            assert pmirror.is_dir()
            assert json_path.is_dir()
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
    mirror_pth = Path(fixtures.path("mirror/"))

    mock_data = {}

    for x in mirror_pth.glob("*.json"):
        mock_data[f"https://pypi.org/pypi/{x.name.split('.')[0]}/json"] = json.loads(x.read_text())


    def _callback_download(request):
        filename = request.url.split("/")[-1]
        file_pth = fixtures.path(f"mirror/{filename}")
        if os.path.exists(file_pth):
            with open(file_pth, "rb") as fd:
                return (200, {'Content-length': str(os.stat(file_pth).st_size)}, fd.read())
        else:
            return (404, {"Content-length": 0}, "")


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

        rsps.add_callback(
            responses.GET,
            url=re.compile(r"https://files.pythonhosted.org/packages/.+"),
            callback=_callback_download
        )


    return _activate_mock


@pytest.fixture()
def mock_pypi_stats():
    import aura.config
    with mock.patch.object(aura.config, "iter_pypi_stats", return_value=PYPI_STATS) as m:
        yield m


@pytest.fixture(scope="function", autouse=True)
def reset_plugins():
    from aura.analyzers.python.readonly import ReadOnlyAnalyzer
    from aura import plugins

    read_only_hooks = ReadOnlyAnalyzer.hooks
    cache = plugins.PLUGIN_CACHE.copy()

    try:
        ReadOnlyAnalyzer.hooks = []
        plugins.PLUGIN_CACHE = {"analyzers": {}}
        yield
    finally:
        ReadOnlyAnalyzer.hooks = read_only_hooks
        plugins.PLUGIN_CACHE = cache


@pytest.fixture(scope="module")
def mock_tqdm_log_write():

    with mock.patch.object(tqdm.tqdm, "write") as m:
        yield m


@pytest.fixture()
def random_text():
    """
    Generate random text
    """
    def _(length: int):
        return "".join([random.choice(string.printable+"\n ") for _ in range(length)])

    return _


@pytest.fixture(scope="function", autouse=True)
def confirm_prompt():
    with mock.patch("click.confirm") as m:
        m.return_value = True
        yield m


@pytest.fixture(scope="function")
def mock_cache(tmp_path):
    with mock.patch("aura.cache.Cache.get_location") as m:
        from aura import cache

        with mock.patch.object(cache.Cache, "DISABLE_CACHE", new=False):

            c_path = tmp_path / "cache"
            c_path.mkdir()
            m.return_value = c_path
            yield m


@pytest.fixture(scope="function", autouse=True)
def reset_mock_responses():
    yield
    responses.reset()
