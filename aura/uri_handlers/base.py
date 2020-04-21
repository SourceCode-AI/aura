# -*- coding: utf-8 -*-
from __future__ import annotations

import os
import urllib.parse
import mimetypes
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Union
from warnings import warn

import pkg_resources
import magic

from .. import config
from ..analyzers import find_imports
from ..analyzers.rules import DataProcessing, Rule


logger = config.get_logger(__name__)
HANDLERS = {}


class URIHandler(ABC):
    scheme: str = "None"
    default = None

    def __init__(self, uri: urllib.parse.ParseResult):
        self.uri = uri

    @classmethod
    def is_supported(cls, parsed_uri):
        return parsed_uri.scheme == cls.scheme

    @classmethod
    def from_uri(cls, uri) -> Union[URIHandler, None]:
        parsed = urllib.parse.urlparse(uri)
        cls.load_handlers()

        for handler in HANDLERS.values():
            if handler.is_supported(parsed):
                return handler(parsed)

        return cls.default(parsed)

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
    def metadata(self):
        return {}

    @property
    def exists(self) -> bool:
        return True

    @abstractmethod
    def get_paths(self):
        raise NotImplementedError("Need to be re-implemented in the child class")

    def cleanup(self):
        pass


class PackageProvider:
    @property
    def package(self):
        raise NotImplementedError("Need to be re-implemented in child class")


@dataclass
class ScanLocation:
    location: Path
    metadata: dict = field(default_factory=dict)
    cleanup: bool = False
    parent: Union[str, None] = None
    strip_path: str = ""

    def __post_init__(self):
        self.location = Path(self.location)

        if self.metadata.get("depth") is None:
            self.metadata["depth"] = 0
            warn("Depth is not set for the scan location", stacklevel=2)

        if Path(self.location).is_file():
            self.metadata["mime"] = magic.from_file(os.fspath(self.location), mime=True)

            if self.metadata["mime"] in ("text/plain", "application/octet-stream"):
                self.metadata["mime"] = mimetypes.guess_type(self.location)[0]

            if self.metadata["mime"] == "text/x-python":
                imports = find_imports.find_imports(self.location, metadata=self.metadata)
                if imports:
                    self.metadata["py_imports"] = imports

    @property
    def filename(self) -> Union[str, None]:
        if self.location.is_file():
            return self.location.name
        else:
            return None

    def create_child(self, new_location: Union[str, Path], metadata=None, **kwargs) -> ScanLocation:
        if metadata is None:
            metadata = self.metadata.copy()
            metadata["depth"] = self.metadata["depth"] + 1

        for x in ("mime", "interpreter_path", "interpreter_name"):
            metadata.pop(x, None)

        child = self.__class__(
            location=Path(new_location),
            metadata=metadata,
            strip_path=kwargs.get("strip_path", self.strip_path),
            parent=kwargs.get("parent", self.parent),
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
        target = os.fspath(target)

        if self.strip_path and target.startswith(self.strip_path):
            size = len(self.strip_path)
            if self.strip_path[-1] != "/":
                size += 1

            target = target[size:]

        if self.parent:
            target = os.fspath(self.parent) + "$" + target

        return target

    def should_continue(self) -> Union[bool, Rule]:
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
                    "reason": "max_depth"
                },
                signature = f"data_processing#max_depth#{os.fspath(self.location)}"
            )

        return True
