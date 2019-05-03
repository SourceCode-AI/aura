from pathlib import Path

from aura import config
from aura import utils


def test_config():
    assert config.CFG.get("aura", "config_type") == "test_value"


def test_path_traversal():
    pth = Path(__file__).absolute().parent
    print(f"Starting: {pth}")
    paths = list(utils.walk(pth))

    for x in paths:
        assert x.is_dir() or x.is_file()

    assert Path(__file__) in paths
