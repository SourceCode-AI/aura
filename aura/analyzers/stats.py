import os
from dataclasses import dataclass
from pathlib import Path

from .rules import Rule
from ..utils import Analyzer

@dataclass
class FileStats(Rule):
    mime: str = ''

    def _asdict(self):
        d = {
            'mime': self.mime
        }
        d.update(Rule._asdict(self))
        return d

    def __hash__(self):
        return hash(self.mime)


@Analyzer.ID('file_stats')
@Analyzer.description("This analyzer collect stats about analyzer files")
def analyze(pth: Path, **kwargs):
    pth = os.fspath(pth)

    hit = FileStats(
        mime = kwargs['mime'],
        signature = f"stats#mime#{pth}"
    )
    hit.informational = True
    yield hit
