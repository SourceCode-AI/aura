# -*- coding: utf-8 -*-
from __future__ import annotations

import os
import atexit
import urllib.parse
import mimetypes
import tempfile
import shutil
import copy
import hashlib
from abc import ABC, abstractmethod
from itertools import product
from dataclasses import dataclass, field
from pathlib import Path
from difflib import SequenceMatcher
from typing import Union, Optional, Generator, Tuple, Iterable
from warnings import warn

import tlsh
import pkg_resources
import magic

from .. import config
from ..utils import KeepRefs, lookup_lines, lzset, jaccard, walk
from ..exceptions import PythonExecutorError, UnsupportedDiffLocation, FeatureDisabled
from ..analyzers import find_imports
from ..analyzers.detections import DataProcessing, Detection, get_severity


logger = config.get_logger(__name__)
HANDLERS = {}
CLEANUP_LOCATIONS = set()


class URIHandler(ABC):
    scheme: str = "None"
    default = None

    def __init__(self, uri: urllib.parse.ParseResult):
        self.uri = uri

    @classmethod
    def is_supported(cls, parsed_uri):
        return parsed_uri.scheme == cls.scheme

    @classmethod
    def from_uri(cls, uri: str) -> Optional[URIHandler]:
        parsed = urllib.parse.urlparse(uri)
        cls.load_handlers()

        for handler in HANDLERS.values():
            if handler.is_supported(parsed):
                return handler(parsed)

        return cls.default(parsed)

    @classmethod
    def diff_from_uri(cls, uri1: str, uri2: str) -> Tuple[URIHandler, URIHandler]:
        cls.load_handlers()
        parsed1 = urllib.parse.urlparse(uri1)
        parsed2 = urllib.parse.urlparse(uri2)

        for handler1, handler2 in product(HANDLERS.values(), repeat=2):
            if handler1.is_supported(parsed1) and handler2.is_supported(parsed2):
                return (handler1(parsed1), handler2(parsed2))

        return (cls.default(parsed1), cls.default(parsed2))

    @classmethod
    def load_handlers(cls, ignore_disabled=True):
        global HANDLERS

        if not HANDLERS:
            handlers = {}
            for x in pkg_resources.iter_entry_points("aura.uri_handlers"):
                try:
                    hook = x.load()
                    handlers[hook.scheme] = hook
                    if hook.default and not cls.default:
                        cls.default = hook
                except FeatureDisabled as exc:
                    if not ignore_disabled:
                        handlers.setdefault("disabled", {})[x.name] = exc.args[0]

            HANDLERS = handlers
        return HANDLERS

    @property
    def metadata(self) -> dict:
        return {}

    @property
    def exists(self) -> bool:
        return True

    @abstractmethod
    def get_paths(self, metadata: Optional[dict]=None) -> Generator[ScanLocation, None, None]:
        ...

    def get_diff_paths(self, other: URIHandler) -> Generator[Tuple[ScanLocation, ScanLocation], None, None]:
        raise UnsupportedDiffLocation()

    def cleanup(self):
        pass


class PackageProvider(ABC):
    @property
    @abstractmethod
    def package(self):
        ...


class IdenticalName(float):
    """
    Special case for `is_renamed_file` to indicate that name of the file is identical
    while preserving similarity ratio type compatiblity
    """
    pass


@dataclass
class ScanLocation(KeepRefs):
    location: Union[Path, str]
    metadata: dict = field(default_factory=dict)
    cleanup: Union[bool, Path, str] = False
    parent: Optional[ScanLocation] = None
    strip_path: str = ""
    size: Optional[int] = None

    def __post_init__(self):
        assert type(self.parent) != str  # Type guard format change, should be ScanLocation or None now

        if type(self.location) == str:
            self.__str_location = self.location
            self.location = Path(self.location)
        else:
            self.__str_location = os.fspath(self.location)

        if self.cleanup:
            CLEANUP_LOCATIONS.add(self.location)

        self.__str_parent = None
        self._lzset: Optional[set] = None
        self.metadata["path"] = self.location
        self.metadata["normalized_path"] = str(self)
        self.metadata["tags"] = set()

        if self.metadata.get("depth") is None:
            self.metadata["depth"] = 0
            warn("Depth is not set for the scan location", stacklevel=2)

        if self.location.is_file():
            self.size = self.location.stat().st_size
            self.__compute_hashes()
            self.metadata["mime"] = magic.from_file(self.str_location, mime=True)

            if self.metadata["mime"] in ("text/plain", "application/octet-stream", "text/none"):
                self.metadata["mime"] = mimetypes.guess_type(self.__str_location)[0]
            elif self.metadata["mime"] != "text/x-python" and self.is_python_source_code:  # FIXME: not very elegant mime normalization
                self.metadata["mime"] = "text/x-python"

            if self.is_python_source_code and "no_imports" not in self.metadata:
                try:
                    imports = find_imports.find_imports(self.location, metadata=self.metadata)
                    if imports:
                        self.metadata["py_imports"] = imports
                except PythonExecutorError:
                    pass

    def __compute_hashes(self):
        if self.size == 0:  # Can't mmap empty file
            self.metadata["md5"] = "d41d8cd98f00b204e9800998ecf8427e"
            self.metadata["sha1"] = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
            self.metadata["sha256"] = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            self.metadata["sha512"] = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
            return


        tl = tlsh.Tlsh()
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        sha512 = hashlib.sha512()

        with self.location.open("rb") as fd:
            buffer = fd.read(4096)

            while buffer:
                tl.update(buffer)
                md5.update(buffer)
                sha1.update(buffer)
                sha256.update(buffer)
                sha512.update(buffer)
                buffer = fd.read(4096)

        try:
            tl.final()
            self.metadata["tlsh"] = tl.hexdigest()
        except ValueError:  # TLSH needs at least 256 bytes
            pass

        self.metadata["md5"] = md5.hexdigest()
        self.metadata["sha1"] = sha1.hexdigest()
        self.metadata["sha256"] = sha256.hexdigest()
        self.metadata["sha512"] = sha512.hexdigest()

    def __str__(self):
        return self.strip(self.str_location)

    def __hash__(self):
        return hash(self.location)

    def __eq__(self, other: ScanLocation):
        if type(other) != ScanLocation:
            return NotImplemented
        else:
            return self.location == other.location

    @property
    def str_location(self) -> str:
        return self.__str_location

    @property
    def filename(self) -> Optional[str]:
        if self.location.is_file():
            return self.location.name
        else:
            return None

    @property
    def is_python_source_code(self) -> bool:
        return (self.metadata["mime"] in ("text/x-python", "text/x-script.python"))

    @property
    def is_archive(self) -> bool:
        from ..analyzers.archive import SUPPORTED_MIME
        return self.metadata.get("mime") in SUPPORTED_MIME

    @property
    def lzset(self) -> set:
        if self._lzset is None:
            if self.size == 0:  # mmap can't map empty files
                self._lzset = set()
            else:
                try:
                    with self.location.open("rb") as fd:
                        self._lzset = lzset(fd)
                except FileNotFoundError:
                    self._lzset = set()

        return self._lzset

    @property
    def md5(self) -> Optional[str]:
        return self.metadata.get("md5")

    def create_child(self, new_location: Union[str, Path], metadata=None, **kwargs) -> ScanLocation:
        if metadata is None:
            metadata = copy.deepcopy(self.metadata)
            metadata["depth"] = self.metadata["depth"] + 1

        for x in ("mime", "interpreter_path", "interpreter_name"):
            metadata.pop(x, None)

        metadata["analyzers"] = self.metadata.get("analyzers")

        if type(new_location) == str:
            str_loc = new_location
            new_location = Path(new_location)
        else:
            str_loc = os.fspath(new_location)

        if "parent" in kwargs:
            parent = kwargs["parent"]
        elif self.location.is_dir():
            parent = self.parent
        else:
            parent = self.location  # FIXME refactor, parent should be only None or ScanLocation type

        if "strip_path" in kwargs:
            strip_path = kwargs["strip_path"]
        elif str_loc.startswith(os.fspath(tempfile.gettempdir())):
            strip_path = str_loc
        else:
            strip_path = self.strip_path

        child = ScanLocation(
            location=new_location,
            metadata=metadata,
            strip_path=strip_path,
            parent=parent,
            cleanup=kwargs.get("cleanup", False)
        )

        return child

    def strip(self, target: Union[str, Path], include_parent: bool=True) -> str:
        """
        Strip/normalize given path
        Left side part of the target is replaced with the configured strip path
        This is to prevent temporary locations to appear in a part and are instead replaced with a normalize path
        E.g.:
        `/var/tmp/some_extracted_archive.zip/setup.py`
        would become:
        `some_extracted_archive.zip$setup.py`
        which signifies that the setup.py is inside the archive and leaves out the temporary unpack location

        :param target: Path to replace/strip
        :return: normalized path
        """
        if type(target) == str:
            target = Path(target)

        try:
            target = target.relative_to(self.strip_path)
        except ValueError:  # strip_path is not a prefix of target
            pass

        if include_parent and self.parent:
            p = str(self.parent)
            line_no = self.metadata.get("parent_line")
            if line_no is not None:
                p = f"{p}:{line_no}"

            return f"{p}${str(target)}"

        return str(target)

    def should_continue(self) -> Union[bool, Detection]:
        """
        Determine if the processing of this scan location should continue
        Currently, the following reasons can halt the processing:
        - maximum depth was reached (recursive unpacking)

        :return: True if the processing should continue otherwise an instance of Rule that would halt the processing
        """
        max_depth = int(config.CFG["aura"].get("max-depth", 5))
        if self.metadata["depth"] > max_depth:
            d = DataProcessing(
                message = f"Maximum processing depth reached",
                extra = {
                    "reason": "max_depth",
                    "location": str(self)
                },
                location=self.location,
                signature = f"data_processing#max_depth#{str(self)}"
            )
            self.post_analysis([d])
            return d

        return True

    def pprint(self):
        from prettyprinter import pprint as pp
        pp(self)

    def post_analysis(self, detections: Iterable[Detection]):
        encoding = self.metadata.get("encoding") or "utf-8"
        line_numbers = [d.line_no for d in detections if d.line_no is not None and d.line is None]

        lines = lookup_lines(self.str_location, line_numbers, encoding=encoding)

        for d in detections:
            d.tags |= self.metadata["tags"]  # Lookup if we can remove this

            if d.location is None:
                d.location = str(self)
            else:
                d.location = self.strip(d.location)

            if d.scan_location is None:
                d.scan_location = self

            if d.line is None:
                line = lines.get(d.line_no)
                d.line = line

            if d._metadata is None:
                d._metadata = self.metadata

            if d._severity is None:
                d._severity = get_severity(d)

    def is_renamed_file(self, other: ScanLocation, max_depth: Optional[int]=None) -> float:
        max_depth = max_depth or get_diff_depth_limit()
        self_name = self.strip(self.str_location, include_parent=False).lstrip("/")
        other_name = other.strip(other.str_location, include_parent=False).lstrip("/")
        ratio = jaccard(self.lzset, other.lzset)

        if self_name == other_name:
            return IdenticalName(ratio)

        self_paths = self_name.split("/")
        other_paths = other_name.split("/")

        changes = 0
        for op in SequenceMatcher(None, self_paths, other_paths).get_opcodes():
            if op[0] == "equal":
                continue
            changes += max(op[2]-op[1], op[4]-op[3])

        if changes > max_depth:
            # Files not within the max depth
            return 0.0
        elif self.is_archive and other.is_archive:
            return SequenceMatcher(None, self.location.name, other.location.name).ratio()
        else:
            return ratio

    def list_recursive(self) -> Generator[ScanLocation, None, None]:
        for f in walk(self.location):
            yield self.create_child(
                new_location=f,
                strip_path=str(self.location),
                parent=self.parent
            )

    def do_cleanup(self):
        if not self.cleanup:
            return

        if type(self.cleanup) != bool:
            dest = self.cleanup
        else:
            dest = self.location

        if os.path.exists(dest):
            logger.debug(f"cleaning up {dest}")
            shutil.rmtree(dest)

        if dest in CLEANUP_LOCATIONS:
            CLEANUP_LOCATIONS.remove(dest)


def cleanup_locations():
    """
    Iterate over all created locations and delete path tree for those marked with cleanup
    """
    for obj in ScanLocation.get_instances():  # type: ScanLocation
        if not obj.cleanup:
            continue
        else:
            obj.do_cleanup()

    for location in CLEANUP_LOCATIONS:  # type: Union[Path, ScanLocation]
        if isinstance(location, ScanLocation):
            location.do_cleanup()

        elif location.exists():
            logger.debug(f"Cleaning up {location}")
            shutil.rmtree(location)


def get_diff_depth_limit() -> int:
    return config.CFG["diff"].get("depth_limit", 2)


atexit.register(cleanup_locations)
