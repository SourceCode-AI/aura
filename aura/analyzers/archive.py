import os
from collections import namedtuple
from pathlib import PurePath

from .rules import suspicious_entry


def is_suspicious(pth, location):
    if pth.startswith('/'):
        return suspicious_entry(
            location=os.fspath(location),
            type='absolute_path',
            path=pth,
            score=50
        )
    elif any(x == '..' for x in PurePath(pth).parts):
        return suspicious_entry(
            location=os.fspath(location),
            type='parent_reference',
            path=pth,
            score=50
        )
    return None


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
