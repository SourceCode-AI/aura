import os
import re
import sys
import logging
import hashlib
import shutil
from pathlib import Path
from functools import partial
from typing import Generator

import requests
from click import secho


logger = logging.getLogger(__name__)


def walk(location) -> Generator[Path, None, None]:
    if not isinstance(location, Path):
        location = Path(location)

    for x in location.iterdir():
        if x.is_file():
            yield location / x
        elif x.is_dir() or x.is_symlink():
            yield from walk(location/x)
        else:
            continue


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
        with open(data, 'rb') as fd:
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
    with requests.get(url, stream=True) as r:
        r.raw.read = partial(r.raw.read, decode_content=True)  # https://github.com/requests/requests/issues/2155
        shutil.copyfileobj(r.raw, fd)  # https://stackoverflow.com/a/39217788
    fd.flush()


def json_encoder(obj):
    if isinstance(obj, set):
        return list(obj)
