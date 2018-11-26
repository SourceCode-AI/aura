#-*- coding: utf-8 -*-

from pathlib import Path

from . import fs_struct
from . import yara_scan
from . import python_src


def run_file_analyzers(pth: Path, **kwargs):
    yield from fs_struct.analyze_sensitive(pth, **kwargs)
    yield from fs_struct.analyze_suspicious(pth, **kwargs)
    yield from python_src.analyze(pth, **kwargs)
    yield from yara_scan.analyze(pth, **kwargs)
