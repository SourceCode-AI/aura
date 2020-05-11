# -*- coding: utf-8 -*-
#  Analyzer for FileSystem structure
import fnmatch
from dataclasses import dataclass

from .rules import Rule
from ..utils import Analyzer
from ..uri_handlers.base import ScanLocation
from .. import config

# TODO: normalize rules
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
def analyze_sensitive(*, location: ScanLocation):
    """Find files not intended to be published such as .pypirc leaking user password"""

    if location.location.stat().st_size == 0:
        return

    name = location.location.name
    str_pth = str(location)

    for pattern in config.SEMANTIC_RULES["sensitive_filenames"]:
        if fnmatch.fnmatch(str_pth, pattern) or str_pth.endswith(pattern):
            # TODO: add test
            yield SensitiveFile(
                message="A potentially sensitive file has been found",
                file_name=name,
                score=config.get_score_or_default("contain-sensitive-file", 0),
                signature=f"sensitive_file#{str_pth}",
            )


@Analyzer.ID("suspicious_files")
def analyze_suspicious(*, location: ScanLocation):
    """Find non-standard files such as *.exe, compiled python code (*.pyc) or hidden files"""
    name = location.location.name
    if name.startswith("."):
        f_type = "hidden"

    elif name.endswith(".pyc"):
        if "__pycache__" in location.location.parts:
            return

        f_type = "python_bytecode"
    else:
        return

    if f_type:
        # TODO: add test
        yield SuspiciousFile(
            message="A potentially sensitive file has been found",
            file_name=name,
            file_type=f_type,
            score=config.get_score_or_default("contain-suspicious-file", 0),
            signature=f"suspicious_file#{str(location)}",
        )
