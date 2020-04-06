# -*- coding: utf-8 -*-
#  Analyzer for FileSystem structure
import os
import fnmatch
from pathlib import Path
from dataclasses import dataclass

from .rules import Rule
from ..utils import Analyzer
from .. import config
from ..config import CFG


@dataclass
class SensitiveFile(Rule):
    __hash__ = Rule.__hash__
    file_name: str = ""

    def _asdict(self):
        d = {"file_name": self.file_name}
        d.update(Rule._asdict(self))
        return d


@dataclass
class SuspiciousFile(Rule):
    __hash__ = Rule.__hash__
    file_name: str = ""
    file_type: str = ""

    def _asdict(self):
        d = {
            "file_name": self.file_name,
            "file_type": self.file_type,
        }
        d.update(Rule._asdict(self))
        return d


@Analyzer.ID("sensitive_files")
def analyze_sensitive(pth: Path, **kwargs):
    """Find files not intended to be published such as .pypirc leaking user password"""

    if pth.stat().st_size == 0:
        return

    name = pth.name
    str_pth = os.fspath(pth.absolute())

    for pattern in config.SEMANTIC_RULES["sensitive_filenames"]:
        if fnmatch.fnmatch(str_pth, pattern) or str_pth.endswith(pattern):
            yield SensitiveFile(
                file_name=name,
                score=int(CFG.get("score", "contain-sensitive-file")),
                signature=f"sensitive_file#{os.fspath(pth)}",
            )


@Analyzer.ID("suspicious_files")
def analyze_suspicious(pth: Path, **kwargs):
    """Find non-standard files such as *.exe, compiled python code (*.pyc) or hidden files"""
    name = pth.name
    if name.startswith("."):
        f_type = "hidden"

    elif name.endswith(".pyc"):
        if "__pycache__" in pth.parts:
            return

        f_type = "python_bytecode"
    else:
        return

    yield SuspiciousFile(
        file_name=name,
        file_type=f_type,
        score=int(CFG.get("score", "contain-suspicious-file")),
        signature=f"suspicious_file#{os.fspath(pth)}",
    )
