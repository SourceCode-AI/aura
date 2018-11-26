import os
import json
import subprocess
import traceback
from pathlib import Path

from . import python_src_inspector
from .rules import module_import
from .rules import function_call
from ..utils import construct_path


def get_line_content(pth, line_no, strip=True):
    with open(pth, 'r') as fd:
        for ix, line in enumerate(fd):
            if ix + 1 == line_no:
                if strip:
                    line = line.strip()
                return line


def process_script_data(pth, data, kwargs):
    signatures = python_src_inspector.load_signatures()

    imported = set()
    for m in data['modules'].values():
        if m['module'] not in imported:
            score = 0
            category = 'unknown'

            for section in signatures['modules']:
                if m['module'] not in section['modules']:
                    continue

                score = section.get('score', 0)
                category = section['name']
                break

            imported.add(m['module'])
            yield module_import(
                name=m['module'],
                location=construct_path(pth, kwargs.get('strip_path'), parent=kwargs.get('parent')),
                score=score,
                category=category,
                line_no=m['line_no'],
                line=get_line_content(pth, m['line_no'])
            )

    for c in data['calls']:
        score = 0
        pattern_found = False
        for pattern in signatures['function_calls']:
            if pattern['call'] == c['function']:
                score = pattern.get('score', 0)
                pattern_found = True
                break

        if pattern_found or not kwargs.get('filter', True):
            yield function_call(
                function=c['function'],
                location=construct_path(pth, kwargs.get('strip_path'), parent=kwargs.get('parent')),
                score=score,
                line_no=c['line_no'],
                line=get_line_content(pth, c['line_no'])
            )


def analyze(pth: Path, **kwargs):
    if kwargs.get('mime') != 'text/x-python':
        return
    pth = os.fspath(pth)

    try:
        script_data = python_src_inspector.analyze(pth)
        yield from process_script_data(pth, script_data, kwargs)
    except Exception:
        traceback.print_exc()
        return

