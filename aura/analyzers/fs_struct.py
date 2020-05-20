# -*- coding: utf-8 -*-
#  Analyzer for FileSystem structure
import fnmatch
from typing import Generator

from .rules import Rule
from ..utils import Analyzer
from ..uri_handlers.base import ScanLocation
from .. import config


@Analyzer.ID("sensitive_files")
def analyze_sensitive(*, location: ScanLocation) -> Generator[Rule, None, None]:
    """Find files not intended to be published such as .pypirc leaking user password"""
    if location.location.stat().st_size == 0:
        return

    for pattern in config.SEMANTIC_RULES["sensitive_filenames"]:
        if fnmatch.fnmatch(location.str_location, pattern) or location.str_location.endswith(pattern):
            yield Rule(
                detection_type="SensitiveFile",
                message = "A potentially sensitive file has been found",
                score=config.get_score_or_default("contain-sensitive-file", 0),
                signature=f"sensitive_file#{str(location)}",
                extra={
                    "pattern": pattern,
                    "file_name": location.location.name,
                },
                location=location.location,
                tags = {"sensitive-file"}
            )


@Analyzer.ID("suspicious_files")
def analyze_suspicious(*, location: ScanLocation) -> Generator[Rule, None, None]:
    """Find non-standard files such as *.exe, compiled python code (*.pyc) or hidden files"""
    if location.location.stat().st_size == 0:
        return

    name = location.location.name
    if name.startswith("."):
        f_type = "hidden_file"

    elif name.endswith(".pyc"):
        if "__pycache__" in location.location.parts:
            return

        f_type = "python_bytecode"
    else:
        return

    if f_type:
        yield Rule(
            detection_type="SuspiciousFile",
            message="A potentially suspicious file has been found",
            score=config.get_score_or_default("contain-suspicious-file", 0),
            signature=f"suspicious_file#{str(location)}",
            extra={
                "file_name": location.location.name,
                "file_type": f_type
            },
            location=location.location,
            tags={f_type}
        )
