import os
import re
import sys
import hashlib
import shutil
import importlib
import dataclasses
from pathlib import Path
from functools import partial
from typing import Generator

import requests
from click import secho

from .analyzers.python.nodes import ASTNode
from . import config


logger = config.get_logger(__name__)


def walk(location) -> Generator[Path, None, None]:
    if not isinstance(location, Path):
        location = Path(location)

    location = location.absolute()

    for x in location.rglob('*'):
        if x.is_dir():
            continue
        else:
            yield x


def construct_path(pth, strip_path=None, parent=None):
    pth = os.fspath(pth)

    if strip_path:
        strip_path = os.fspath(strip_path)
        if pth.startswith(strip_path):
            size = len(strip_path)
            if strip_path[-1] != '/':
                size += 1

            pth = pth[size:]

    if parent:
        pth = f'{parent}${pth}'

    return pth


def filter_empty_dict(data):
    for key, val in list(data.items()):
        if val is None:
            del data[key]
        elif isinstance(val, str) and len(val) == 0:
            del data[key]
        elif type(val) is list and len(val) == 0:
            del data[key]
        elif type(val) is int and val == 0:
            del data[key]
    return data


def print_tty(msg, *args, **kwargs):
    """
    Print string to stdout only if it's not a pipe or redirect (e.g. tty)
    Additional *args and **kwargs are passed to the `click.secho` function

    :param msg: str to print
    :return: None
    """
    if sys.stdout.isatty():
        secho(msg, *args, **kwargs)


def md5(data, hex=True, block_size=2**20):
    ctx = hashlib.md5()

    if isinstance(data, Path):
        with  data.open('rb') as fd:
            while True:
                file_data = fd.read(block_size)
                if not file_data:
                    break
                ctx.update(file_data)
    else:
        ctx.update(data)

    return ctx.hexdigest() if hex else ctx.digest()


def normalize_name(name):
    """
    Normalize package name as descibed in PEP-503
    https://www.python.org/dev/peps/pep-0503/#normalized-names

    :return:
    """
    return re.sub(r'[-_.]+', '-', name).lower()


def download_file(url, fd):
    """
    Download data from given URL and write it to the file descriptor
    This function is designed for speed as other approaches are not able to utilize full network speed

    :param url: target url to download the data from
    :param fd: Open file-like descriptor
    """
    with requests.get(url, stream=True) as r:
        r.raw.read = partial(r.raw.read, decode_content=True)  # https://github.com/requests/requests/issues/2155
        shutil.copyfileobj(r.raw, fd)  # https://stackoverflow.com/a/39217788
    fd.flush()


def json_encoder(obj):
    if isinstance(obj, (set, tuple)):
        return list(obj)
    elif isinstance(obj, Path):
        return os.fspath(obj.absolute())
    elif isinstance(obj, ASTNode):
        return obj.json
    elif isinstance(obj, bytes):
        return obj.decode('utf-8')
    elif dataclasses.is_dataclass(obj):
        if hasattr(obj, '_asdict'):
            return obj._asdict()
        else:
            return dataclasses.asdict(obj)


def lookup_lines(pth, line_nos:list, strip=True):
    line_nos = sorted(line_nos)
    lines = {}
    if not line_nos:
        return lines

    with open(pth, 'r') as fd:
        for ix, line in enumerate(fd):
            if ix > line_nos[-1]+1:
                break

            line_no = ix + 1

            if line_no in line_nos:
                if strip:
                    line = line.strip()
                lines[line_no] = line
    return lines


def import_hook(name):
    if ':' in name:
        modname, target = name.split(':')
    else:
        modname = name
        target = modname.split('.')[-1]

    module = importlib.import_module(modname)
    return getattr(module, target)


def set_function_attr(**kwargs):
    """
    Simple decorator that adds attributes to the function as defined by kwargs
    """
    def attr_decor(func):
        for n, v in kwargs.items():
            setattr(func, n, v)
        return func
    return attr_decor


def imports_to_tree(items):
    root = {}
    for x in items:
        parts = x.split('.')
        current = root
        for x in parts:
            if x not in current:
                current[x] = {}
            current = current[x]

    return root


def pprint_imports(tree, indent=""):
    last = len(tree) - 1
    for ix, x in enumerate(tree.keys()):
        subitems = tree.get(x, {})

        # https://en.wikipedia.org/wiki/Box-drawing_character
        char = ""
        if ix == last:
            char += "└"
        elif ix == 0:
            char += "┬"
        else:
            char += "├"


        print(f"{indent}{char}{x}")
        if subitems:
            new_indent = " " if ix == last else "│"
            pprint_imports(subitems, indent + new_indent)


class Analyzer:
    @classmethod
    def name(cls, name):
        return set_function_attr(name=name)

    @classmethod
    def ID(cls, identity):
        return set_function_attr(analyzer_id = identity)

    @classmethod
    def type(cls, atype):
        return set_function_attr(analyzer_type = atype)

    @classmethod
    def description(cls, desc):
        return set_function_attr(analyzer_description = desc)
