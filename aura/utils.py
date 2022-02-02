from __future__ import annotations

import os
import re
import codecs
import hashlib
import shutil
import weakref
import mmap
import dataclasses
from contextlib import contextmanager, ExitStack
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from functools import partial, lru_cache
from urllib.parse import urlparse, urlunparse, ParseResult
from zlib import adler32
from typing import Union, List, TypeVar, Generic, Mapping, cast, Dict, Type, Iterable, ByteString, IO

import tqdm
import requests

from . import config
from .bases import JSONSerializable


logger = config.get_logger(__name__)
T = TypeVar("T")

SIZE_UNITS = ["kb", "mb", "gb", "tb", "pb"]


class KeepRefs(Generic[T]):
    """
    A class that would keep references to all created instances
    https://stackoverflow.com/questions/328851/printing-all-instances-of-a-class
    """
    __refs__ : Dict[Type[KeepRefs], List[weakref.ReferenceType[KeepRefs]]] = defaultdict(list)

    def __init__(self):
        super(KeepRefs, self).__init__()
        self.__refs__[self.__class__].append(weakref.ref(self))

    @classmethod
    def get_instances(cls) -> Iterable[T]:
        for inst_ref in cls.__refs__[cls]:
            inst = inst_ref()
            if inst is not None:
                yield inst  # type: ignore[misc]


def walk(location: Union[str, Path]) -> Iterable[Path]:
    if not isinstance(location, Path):
        location = Path(location)

    location = location.absolute()

    for x in location.rglob("*"):
        if x.is_dir():
            continue
        else:
            yield x


def parse_iso_8601(date_string: str) -> datetime:
    if date_string.endswith("Z"):
        date_string = date_string[:-1] + "+00:00"

    return datetime.fromisoformat(date_string).replace(tzinfo=timezone.utc)


@lru_cache()
def md5(
    data: Union[str, ByteString, Path],
    hex=True,
    block_size=2 ** 20
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
        ctx.update(data)  # type: ignore[arg-type]

    return ctx.hexdigest() if hex else ctx.digest()


def download_file(url: str, fd: IO[bytes], session=None) -> None:
    """
    Download data from given URL and write it to the file descriptor
    This function is designed for speed as other approaches are not able to utilize full network speed

    :param url: target url to download the data from
    :param fd: Open file-like descriptor
    """
    def _(*args, pbar, reader, **kwargs):
        # https://github.com/requests/requests/issues/2155
        data = reader(*args, decode_content=True, **kwargs)
        pbar.update(len(data))
        return data

    if session is None:
        session = requests

    r = session.get(url, stream=True)
    content_length = r.headers.get('Content-length', None)
    desc = "Downloading file"

    if content_disposition := r.headers.get("content-disposition"):
        fname = re.findall("filename=(.+)", content_disposition)[0]
        desc = f"Downloading `{fname}`"
    elif "." in (fname := urlparse(url).path.split("/")[-1]):  # Fallback method, attempt to parse the filename from URL
        desc = f"Downloading `{fname}`"

    pbar = tqdm.tqdm(
        total=int(content_length) if content_length is not None else None,
        unit="bytes",
        unit_scale=True,
        unit_divisor=1024,
        desc=desc,
        disable=config.PROGRESSBAR_DISABLED,
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
    elif isinstance(obj, JSONSerializable):
        return obj.to_json()
    elif dataclasses.is_dataclass(obj):
        return dataclasses.asdict(obj)


def lookup_lines(
        pth: str,
        line_nos: List[int],
        strip: bool=True,
        encoding: str="utf-8"
) -> Mapping[int, str]:
    line_nos = sorted(line_nos)
    lines : Dict[int, str] = {}
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


def lzset(indata) -> set:
    """
    Create compression dict using Lempel Ziv algorithm
    Used for estimating similarity using LZJD
    http://conference.scipy.org/proceedings/scipy2019/pdfs/pylzjd.pdf
    """
    s = set()

    with ExitStack() as stack:
        if type(indata) in (str, bytes):
            size = len(indata)
            slicer = indata
        else:
            indata.seek(0, 2)
            size = indata.tell()
            indata.seek(0)
            slicer = stack.enter_context(mmap.mmap(indata.fileno(), 0, prot=mmap.PROT_READ))

        start = 0
        end = 1
        while end <= size:
            b_s = slicer[start:end]
            if b_s not in s:
                s.add(b_s)
                start = end
            end += 1

    return s


def jaccard(a: set, b: set) -> float:
    """
    Compute jaccard similarity of the given two sets

    :return: similarity metric (float) in range [0, 1]
    """
    divisor = len(a | b)
    if divisor == 0:
        return 0.0

    return float(len(a & b)) / divisor


def convert_size(desc: Union[str, int]) -> int:
    if type(desc) == int:
        return desc

    parsed = re.match(r"^(\d+)([kmgtp]b?)?$", desc, flags=re.I)  # type: ignore[type-var]

    if parsed is None:
        raise ValueError(f"Invalid size value specified: `{desc}`")

    g = parsed.groups()

    if len(g) < 1 or len(g) > 2:
        raise ValueError(f"Could not parse the string '{desc}'")

    amount_str: str = g[0]  # type: ignore[assignment]
    if not amount_str.isdigit():
        raise ValueError(f"'{amount_str}' is not a valid number")

    amount: int = int(amount_str)

    if len(g) == 2 and type(g[1]) == str:
        unit = g[1].lower()
        if not unit.endswith("b"):
            unit += "b"

        pos = SIZE_UNITS.index(unit) + 1
    else:
        pos = 0

    return amount * (1024**pos)


def convert_time(desc: int) -> timedelta:  # type: ignore[return]
    if type(desc) == int:
        return timedelta(hours=desc)
    # TODO: add parsing from strings similar to `convert_size`


def remaining_time(end: float) -> float:
    """
    Given an end time, compute remaining time left
    This is used mostly to get time left until the api rate limit resets

    :param end: utc timestamps
    :return: seconds left till the end time is reached
    """
    now = datetime.utcnow().timestamp()
    return 0.0 if end < now else (now - end)


def fast_checksum(data: Union[bytes, str]) -> str:
    """
    Generates a fast checksum for the input data
    This function is not to be used for cryptography but rather for deduplication and similar use cases as the hashing is optimized for speed
    """
    if type(data) == str:
        payload : bytes = data.encode("utf-8")
    else:
        payload : bytes = data  # type: ignore[no-redef]

    return hex(adler32(payload))[2:]  # Omit the `0x` at the start from `hex()`


def isascii(s: str) -> bool:  # TODO: use this to check for non-ascii string definitions and variable names
    """
    Check if string contains only ascii characters

    Inspired by https://stackoverflow.com/questions/196345/how-to-check-if-a-string-in-python-is-in-ascii
    This method was chosen over try-except as it should be faster in our use cases:
    - source code mostly contains short strings which makes `all` faster that correlate with string length
    - try except when fail generates whole stack as part of exception which can be very large when doing SAST analysis and prone to memory leaks
    """
    return all(ord(c) < 128 for c in s)


def sanitize_uri(uri: Union[str, ParseResult]) -> str:
    if isinstance(uri, str):
        parts = tuple(urlparse(uri))
    else:
        parts = tuple(uri)

    if len(parts) > 1 and parts[1]:
        parts = parts[:1] + ("***",) + parts[2:]

    return urlunparse(parts)


class Analyzer:
    """
    Helper class to set the analyzer metadata
    """

    @classmethod
    def ID(cls, identity):
        return set_function_attr(analyzer_id=identity)
