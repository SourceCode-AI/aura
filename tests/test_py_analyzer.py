import re
import os
import subprocess
from pathlib import Path

from aura import config
from aura.analyzers.python import visitor


def test_basic_ast(fixtures):
    pth = fixtures.path('basic_ast.py')

    with Path(pth).open('r') as fd:
        data = fixtures.get_raw_ast(fd.read())

    assert isinstance(data, list)
    assert len(data) == 9  # Top level lines with python code


def test_py2k(fixtures):
    pth = fixtures.path('py2k.py')

    with Path(pth).open('r') as fd:
        data = fixtures.get_raw_ast(fd.read())

    assert data
