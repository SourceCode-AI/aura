import os
from pathlib import PurePath
from dataclasses import dataclass

from .rules import Rule


@dataclass
class SuspiciousArchiveEntry(Rule):
    pass


def is_suspicious(pth, location):
    if pth.startswith('/'):
        return SuspiciousArchiveEntry(
            location = os.fspath(location),
            extra = {
                'entry_type': 'absolute_path',
                'entry_path': os.fspath(pth)
            },
            score = 50
        )

    elif any(x == '..' for x in PurePath(pth).parts):
        return SuspiciousArchiveEntry(
            location=os.fspath(location),
            extra ={
                'entry_type': 'parent_reference',
                'entry_path': os.fspath(pth)
            },
            score=50
        )

    return None


# TODO: convert to new format
def analyze_tar_archive(archive, location):
    for x in archive:
        pth = x.name
        res = is_suspicious(pth, location)
        if res:
            yield res


def analyze_zip_archive(archive, location):
    for x in archive.infolist():
        pth = x.filename
        res = is_suspicious(pth, location)
        if res:
            yield res
