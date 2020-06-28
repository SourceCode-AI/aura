import os
import re
import sys
import codecs
import hashlib
import shutil
import weakref
import dataclasses
from contextlib import contextmanager
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from functools import partial, wraps, lru_cache
from typing import Generator, Union, List, TypeVar, Generic, Mapping, cast, BinaryIO

import tqdm
import requests
from click import secho

from . import config
from . import progressbar


logger = config.get_logger(__name__)
PKG_NORM_CHARS = re.compile(r"[-_.]+")
T = TypeVar("T")


class KeepRefs(Generic[T]):
    """
    A class that would keep references to all created instances
    https://stackoverflow.com/questions/328851/printing-all-instances-of-a-class
    """
    __refs__ = defaultdict(list)

    def __init__(self):
        super(KeepRefs, self).__init__()
        self.__refs__[self.__class__].append(weakref.ref(self))

    @classmethod
    def get_instances(cls) -> Generator[T, None, None]:
        for inst_ref in cls.__refs__[cls]:
            inst = inst_ref()
            if inst is not None:
                yield inst


def walk(location: Union[str, Path]) -> Generator[Path, None, None]:
    if not isinstance(location, Path):
        location = Path(location)

    location = location.absolute()

    for x in location.rglob("*"):
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


def parse_iso_8601(date_string: str) -> datetime:
    if date_string.endswith("Z"):
        date_string = date_string[:-1] + "+00:00"

    return datetime.fromisoformat(date_string)


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
    elif type(data) == str:
        ctx.update(data.encode("utf-8"))
    else:
        ctx.update(data)

    return ctx.hexdigest() if hex else ctx.digest()


def download_file(url: str, fd: BinaryIO) -> None:
    """
    Download data from given URL and write it to the file descriptor
    This function is designed for speed as other approaches are not able to utilize full network speed

    :param url: target url to download the data from
    :param fd: Open file-like descriptor
    """
    def _(*args, pbar, reader, **kwargs):
        #  https://github.com/requests/requests/issues/2155
        data = reader(*args, decode_content=True, **kwargs)
        pbar.update(len(data))
        return data

    with requests.get(url, stream=True) as r:
        pbar = tqdm.tqdm(
            total=int(r.headers['Content-length']),
            unit="bytes",
            unit_scale=True,
            unit_divisor=1024,
            desc="Downloading file",
            disable=progressbar.disable(),
        )
        r.raw.read = partial(
            _,
            reader=r.raw.read,
            pbar=pbar,
        )
        shutil.copyfileobj(r.raw, fd)  # https://stackoverflow.com/a/39217788
    fd.flush()
    pbar.close()


def json_encoder(obj):
    from .analyzers.python.nodes import ASTNode

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


def lookup_lines(
        pth: str,
        line_nos: List[int],
        strip: bool=True,
        encoding: str="utf-8"
) -> Mapping[int, str]:
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
def normalize_path(
        pth: Union[Path, str],
        absolute: bool=False,
        to_str: bool=True
) -> Union[str, Path]:
    if type(pth) == str:
        pth = Path(pth)

    pth = cast(Path, pth)

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
