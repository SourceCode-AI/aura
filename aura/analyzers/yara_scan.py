#-*- coding: utf-8 -*-

import os

from pathlib import Path

import yara

from .rules import yara_match
from ..utils import construct_path


rules = yara.compile(filepath=os.path.join(os.getcwd(), 'rules.yara'))


def analyze(pth: Path, **kwargs):
    pth = os.fspath(pth)

    for m in rules.match(pth, timeout=10):
        strings = set(x[-1] for x in m.strings)
        yield yara_match(
            rule=m.rule,
            location=construct_path(pth, kwargs.get('strip_path'), parent=kwargs.get('parent')),
            strings=strings,
            meta=m.meta
        )
