import os
import pprint
from pathlib import Path

from aura import config
from aura import utils


def test_config():
    cfg_path = os.environ.get('AURA_CFG')
    assert cfg_path.split('/')[-1] == 'test_config.ini', cfg_path
    assert config.CFG_PATH == cfg_path

    pprint.pprint(dict(config.CFG))

    assert config.CFG.get("aura", "config_type") == "test_value"


def test_path_traversal():
    pth = Path(__file__).absolute().parent
    print(f"Starting: {pth}")
    paths = list(utils.walk(pth))

    for x in paths:
        assert x.is_dir() or x.is_file()

    assert Path(__file__) in paths
