#-*- coding: utf-8 -*-
# Analyzer for FileSystem structure
from pathlib import Path

from .rules import sensitive_file, suspicious_file
from ..utils import construct_path


sensitive_filenames = (
    '.pypirc',
    'id_rsa'
    '.bash_history',
    '.htpasswd',
)


def analyze_sensitive(pth: Path, **kwargs):
    name = pth.name

    if name in sensitive_filenames and pth.stat().st_size > 0:
        yield sensitive_file(
            name=name,
            location=construct_path(pth, kwargs.get('strip_path'), parent=kwargs.get('parent')),
            score=100
        )


def analyze_suspicious(pth: Path, **kwargs):
    name = pth.name

    if name.startswith('.'):
        f_type = 'hidden'

    elif name.endswith('.pyc'):
        f_type = 'python_bytecode'
    else:
        return

    yield suspicious_file(
        name=name,
        location=construct_path(pth, kwargs.get('strip_path'), parent=kwargs.get('parent')),
        type = f_type,
        score=5
    )
