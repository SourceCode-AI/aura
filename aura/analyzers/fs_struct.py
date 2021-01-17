# -*- coding: utf-8 -*-
# Analyzer for FileSystem structure
from typing import Iterable

from .detections import Detection
from ..utils import Analyzer
from ..uri_handlers.base import ScanLocation
from ..type_definitions import AnalyzerReturnType
from ..pattern_matching import FilePatternMatcher
from .. import config


FILE_PATTERNS = None


def get_file_patterns() -> Iterable[FilePatternMatcher]:
    global FILE_PATTERNS

    if FILE_PATTERNS is None:
        FILE_PATTERNS = tuple(FilePatternMatcher(x) for x in config.SEMANTIC_RULES.get("files", []))

    return FILE_PATTERNS


def enable_suspicious_files(location: ScanLocation) -> bool:
    flag = location.metadata.get("suspicious_files")
    if flag is not None:
        return flag

    if location.metadata.get("scheme") in ("pypi", "mirror"):
        return True
    else:
        return False


@Analyzer.ID("file_analyzer")
def analyze(*, location: ScanLocation) -> AnalyzerReturnType:
    for p in get_file_patterns():
        if p.match(location):
            location.metadata["tags"] |= set(p._signature.get("tags", []))

    if not location.location.exists():
        return
    elif location.size == 0:
        return

    if "sensitive_file" in location.metadata["tags"]:
        yield Detection(
            detection_type="SensitiveFile",
            message="A potentially sensitive file has been found",
            score=config.get_score_or_default("contain-sensitive-file", 0),
            signature=f"sensitive_file#{str(location)}",
            extra={
                "file_name": location.location.name,
            },
            location=location.location,
            tags = set(location.metadata["tags"])
        )

    if enable_suspicious_files(location):
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
            yield Detection(
                detection_type="SuspiciousFile",
                message="A potentially suspicious file has been found",
                score=config.get_score_or_default("contain-suspicious-file", 0),
                signature=f"suspicious_file#{str(location)}",
                extra={
                    "file_name": location.location.name,
                    "file_type": f_type
                },
                location=location.location,
                tags={f_type} | location.metadata["tags"]
            )
