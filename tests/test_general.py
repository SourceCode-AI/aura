import os
import pprint
from pathlib import Path

from aura import config
from aura import utils


def test_path_traversal():
    pth = Path(__file__).absolute().parent
    paths = list(utils.walk(pth))

    for x in paths:
        assert x.is_dir() or x.is_file()
