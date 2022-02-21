import logging
import sys
from pathlib import Path
from unittest import mock

import pytest

from aura import plugins
from aura import utils
from aura import config
from aura import python_executor
from aura import cache
from aura.analyzers.archive import archive_analyzer
from aura.analyzers.stats import analyze as  stats_analyzer
from aura.analyzers.data_finder import StringFinder


def test_path_traversal():
    pth = Path(__file__).absolute().parent
    paths = list(utils.walk(pth))

    for x in paths:
        assert x.is_dir() or x.is_file()


@pytest.mark.parametrize("spec,blacklist,whitelist", (
    ([], [], [archive_analyzer, stats_analyzer, StringFinder]),
    (["stats"], [archive_analyzer, StringFinder], [stats_analyzer]),
    (["archive"], [stats_analyzer, StringFinder], [archive_analyzer]),
    (["string_finder"], [stats_analyzer, archive_analyzer], [StringFinder]),
    (None, [], [archive_analyzer, stats_analyzer, StringFinder]),
))
def test_get_analyzers(spec, blacklist, whitelist):
    analyzers = plugins.get_analyzers(spec)

    for b in blacklist:
        assert all(b != x and b != x.__class__ for x in analyzers), b

    for w in whitelist:
        assert any(w == x or w == x.__class__ for x in analyzers), w


def test_invalid_interpreters(caplog):
    caplog.set_level(logging.ERROR)
    valid = "python3"
    invalid = "invalid_aura_interpreter"
    err_msg = f"Could not find python interpreter `{invalid}`. Configuration is not valid or interpreter is not installed on this system"

    int_cfg = {
        "interpreters": {
            "native": "native",
            valid: valid,
            invalid: invalid
        }
    }

    with mock.patch.dict(config.CFG, int_cfg):
        verified = python_executor.get_interpreters()

    assert "native" in verified
    assert verified["native"] == sys.executable
    assert valid in verified
    assert invalid not in verified
    assert err_msg in caplog.text


def test_ast_pattern_fetching(mock_cache):
    cache.ASTPatternsRequest.default = None

    default = cache.ASTPatternsRequest.get_default()
    assert default is cache.ASTPatternsRequest.default

    assert default.proxy() is not None
    assert cache.ASTPatternsRequest.get_default().proxy() is not None
