import os
import re
import sys
import codecs
import hashlib
import shutil
import dataclasses
from contextlib import contextmanager
from pathlib import Path
from functools import partial, wraps, lru_cache
from typing import Generator, Union, List

import requests
from click import secho

from .analyzers.python.nodes import ASTNode
from . import config


logger = config.get_logger(__name__)
PKG_NORM_CHARS = re.compile(r"[-_.]+")


def walk(location) -> Generator[Path, None, None]:
    if not isinstance(location, Path):
        location = Path(location)

    location = location.absolute()

    for x in location.glob("*/*"):
        if x.is_dir():
            continue
        else:
            yield x


def print_tty(msg: str, *args, **kwargs) -> None:
    """
    Print string to stdout only if it's not a pipe or redirect (e.g. tty)
    Additional *args and **kwargs are passed to the `click.secho` function

    :param msg: str to print
    :return: None
    """
    if sys.stdout.isatty():
        secho(msg, *args, **kwargs)


@lru_cache()
def md5(
    data: Union[str, bytes, Path], hex=True, block_size=2 ** 20
) -> Union[str, bytes]:
    ctx = hashlib.md5()

    if isinstance(data, Path):
        with data.open("rb") as fd:
            while True:
                file_data = fd.read(block_size)
                if not file_data:
                    break
                ctx.update(file_data)
    else:
        ctx.update(bytes(data))

    return ctx.hexdigest() if hex else ctx.digest()


def normalize_name(name: str) -> str:
    """
    Normalize package name as described in PEP-503
    https://www.python.org/dev/peps/pep-0503/#normalized-names
    """
    return PKG_NORM_CHARS.sub("-", name).lower()


def download_file(url: str, fd) -> None:
    """
    Download data from given URL and write it to the file descriptor
    This function is designed for speed as other approaches are not able to utilize full network speed

    :param url: target url to download the data from
    :param fd: Open file-like descriptor
    """
    with requests.get(url, stream=True) as r:
        r.raw.read = partial(
            r.raw.read, decode_content=True
        )  #  https://github.com/requests/requests/issues/2155
        shutil.copyfileobj(r.raw, fd)  # https://stackoverflow.com/a/39217788
    fd.flush()


def json_encoder(obj):
    if type(obj) in (set, tuple):
        return list(obj)
    elif isinstance(obj, Path):
        return os.fspath(obj.absolute())
    elif isinstance(obj, ASTNode):
        return obj.json
    elif type(obj) == bytes:
        return obj.decode("utf-8")
    elif dataclasses.is_dataclass(obj):
        if hasattr(obj, "_asdict"):
            return obj._asdict()
        else:
            return dataclasses.asdict(obj)


def lookup_lines(pth, line_nos: list, strip=True, encoding="utf-8"):
    line_nos = sorted(line_nos)
    lines = {}
    if not line_nos:
        return lines

    with codecs.open(pth, "r", encoding=encoding) as fd:
        for ix, line in enumerate(fd):
            if ix > line_nos[-1] + 1:
                break

            line_no = ix + 1

            if line_no in line_nos:
                if strip:
                    line = line.strip()
                lines[line_no] = line
    return lines


def set_function_attr(**kwargs):
    """
    Simple decorator that adds attributes to the function as defined by kwargs
    """

    def attr_decor(func):
        for n, v in kwargs.items():
            setattr(func, n, v)
        return func

    return attr_decor


def imports_to_tree(items: list) -> dict:
    """
    Transform a list of imported modules into a module tree
    """
    root = {}
    for x in items:
        parts = x.split(".")
        current = root
        for x in parts:
            if x not in current:
                current[x] = {}
            current = current[x]

    return root


def pprint_imports(tree, indent=""):
    """
    pretty print the module tree
    """
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


@contextmanager
def enrich_exception(*args):
    """
    Intercept an exception and add additional debug information for logging purposes

    :param args: Extra args to add to the exception
    :return: re-raised exception with the extra args
    """
    try:
        yield
    except Exception as exc:
        exc.args += args
        raise


@lru_cache()
def normalize_path(pth: Path, absolute=False, to_str=True):
    if type(pth) == str:
        pth = Path(pth)

    if absolute:
        pth = pth.absolute()

    if to_str:
        return os.fspath(pth)
    else:
        return Path(pth)


class Analyzer:
    """
    Helper class to set the analyzer metadata
    """

    @classmethod
    def name(cls, name):
        return set_function_attr(name=name)

    @classmethod
    def ID(cls, identity):
        return set_function_attr(analyzer_id=identity)

    @classmethod
    def type(cls, atype):
        return set_function_attr(analyzer_type=atype)
