# -*- coding: utf-8 -*-
from __future__ import annotations

import os
import re
import atexit
import urllib.parse
import mimetypes
import tempfile
import shutil
import copy
from abc import ABC, abstractmethod
from itertools import product
from dataclasses import dataclass, field
from pathlib import Path
from typing import Union, Optional, Generator, Tuple
from warnings import warn

import tlsh
import pkg_resources
import magic

from .. import config
from ..utils import KeepRefs
from ..exceptions import PythonExecutorError, UnsupportedDiffLocation
from ..analyzers import find_imports
from ..analyzers.detections import DataProcessing, Detection


logger = config.get_logger(__name__)
HANDLERS = {}
CLEANUP_LOCATIONS = set()
TEST_REGEX = re.compile(r"^test(_.+|s)?$")  # TODO: move this to config


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
    def load_handlers(cls):
        global HANDLERS

        if not HANDLERS:
            handlers = {}
            for x in pkg_resources.iter_entry_points("aura.uri_handlers"):
                hook = x.load()
                handlers[hook.scheme] = hook
                if hook.default and not cls.default:
                    cls.default = hook

            HANDLERS = handlers
        return HANDLERS

    @property
    def metadata(self) -> dict:
        return {}

    @property
    def exists(self) -> bool:
        return True

    @abstractmethod
    def get_paths(self, metadata: Optional[dict]) -> Generator[ScanLocation, None, None]:
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


@dataclass
class ScanLocation(KeepRefs):
    location: Path
    metadata: dict = field(default_factory=dict)
    cleanup: bool = False
    parent: Optional[str] = None
    strip_path: str = ""
    tlsh: Optional[str] = None
    size: Optional[int] = None

    def __post_init__(self):
        if type(self.location) == str:
            self.__str_location = self.location
            self.location = Path(self.location)
        else:
            self.__str_location = os.fspath(self.location)

        if self.cleanup:
            CLEANUP_LOCATIONS.add(self.location)

        self.__str_parent = None
        self.metadata["path"] = self.location
        self.metadata["normalized_path"] = str(self)

        if not self.metadata.get("flags"):
            self.metadata["flags"] = set()

        if self.metadata.get("depth") is None:
            self.metadata["depth"] = 0
            warn("Depth is not set for the scan location", stacklevel=2)

        for x in self.location.parts:
            if TEST_REGEX.match(x):
                self.metadata["flags"].add("test-code")
                break

        if self.location.is_file():
            with self.location.open("rb") as fd:
                self.tlsh = tlsh.hash(fd.read())

            self.size = self.location.stat().st_size
            self.metadata["mime"] = magic.from_file(self.str_location, mime=True)

            if self.metadata["mime"] in ("text/plain", "application/octet-stream", "text/none"):
                self.metadata["mime"] = mimetypes.guess_type(self.location)[0]

            if self.metadata["mime"] == "text/x-python" and "no_imports" not in self.metadata:
                try:
                    imports = find_imports.find_imports(self.location, metadata=self.metadata)
                    if imports:
                        self.metadata["py_imports"] = imports
                except PythonExecutorError:
                    pass

    def __str__(self):
        return self.strip(self.str_location)

    @property
    def str_location(self) -> str:
        return self.__str_location

    @property
    def str_parent(self) -> Optional[str]:
        if self.parent is None:
            return None

        if self.__str_parent is None:
            if type(self.parent) == str:
                self.__str_parent = self.parent
            else:
                self.__str_parent = os.fspath(self.parent)

        return self.__str_parent

    @property
    def filename(self) -> Optional[str]:
        if self.location.is_file():
            return self.location.name
        else:
            return None

    @property
    def is_python_source_code(self) -> bool:
        return (self.metadata["mime"] == "text/x-python")

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
            parent = self.location

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

    def strip(self, target: Union[str, Path]) -> str:
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
        target: str = os.fspath(target)

        if self.strip_path and target.startswith(self.strip_path):
            size = len(self.strip_path)
            if self.strip_path[-1] != "/":
                size += 1

            target = target[size:]

        if self.parent:
            if not target.startswith(self.str_parent):  # Target might be already stripped
                target = self.str_parent + "$" + target

        return target

    def should_continue(self) -> Union[bool, Detection]:
        """
        Determine if the processing of this scan location should continue
        Currently, the following reasons can halt the processing:
        - maximum depth was reached (recursive unpacking)

        :return: True if the processing should continue otherwise an instance of Rule that would halt the processing
        """
        max_depth = int(config.CFG["aura"].get("max-depth", fallback=5))
        if self.metadata["depth"] > max_depth:
            return DataProcessing(
                message = f"Maximum processing depth reached",
                extra = {
                    "reason": "max_depth",
                    "location": str(self)
                },
                signature = f"data_processing#max_depth#{str(self)}"
            )

        return True

    def pprint(self):
        from prettyprinter import pprint as pp
        pp(self)


def cleanup_locations():
    """
    Iterate over all created locations and delete path tree for those marked with cleanup
    """
    for obj in ScanLocation.get_instances():  # type: ScanLocation
        if not obj.cleanup:
            continue

        if obj.location in CLEANUP_LOCATIONS:
            CLEANUP_LOCATIONS.remove(obj.location)

        if obj.location.exists():
            shutil.rmtree(obj.location)

    for location in CLEANUP_LOCATIONS:  # type: Path
        if location.exists():
            shutil.rmtree(location)


atexit.register(cleanup_locations)
