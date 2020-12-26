from pathlib import Path

import pytest

from aura import plugins
from aura import utils
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
