import os
from dataclasses import dataclass
from pathlib import Path

from .rules import Rule
from ..utils import Analyzer, normalize_path


@dataclass
class FileStats(Rule):
    mime: str = ""

    def _asdict(self):
        d = {"mime": self.mime}
        d.update(Rule._asdict(self))
        return d

    def __hash__(self):
        return hash(self.mime)


@Analyzer.ID("file_stats")
def analyze(pth: Path, mime, metadata, **kwargs):
    """This analyzer collect stats about analyzer files"""
    pth = normalize_path(metadata["normalized_path"])

    hit = FileStats(mime=mime, signature=f"stats#mime#{pth}")
    hit.informational = True
    yield hit
