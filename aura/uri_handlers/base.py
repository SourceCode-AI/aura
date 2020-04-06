# -*- coding: utf-8 -*-
from __future__ import annotations

import os
import urllib.parse
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Union

import pkg_resources
import magic

from .. import config
from ..analyzers import find_imports


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

        if Path(self.location).is_file():
            self.metadata["mime"] = magic.from_file(os.fspath(self.location), mime=True)
            if self.metadata["mime"] == "text/x-python":
                imports = find_imports.find_imports(self.location)
                if imports:
                    self.metadata["py_imports"] = imports

    @property
    def filename(self) -> Union[str, None]:
        if self.location.is_file():
            return self.location.name
        else:
            return None

    def create_child(self, new_location):
        meta = self.metadata.copy()
        for x in ("mime",):
            meta.pop(x, None)

        child = self.__class__(
            location=new_location,
            metadata=meta,
            strip_path=self.strip_path,
            parent=self.parent,
        )
        return child

    def strip(self, target):
        target = os.fspath(target)

        if self.strip_path and target.startswith(self.strip_path):
            size = len(self.strip_path)
            if self.strip_path[-1] != "/":
                size += 1

            target = target[size:]

        if self.parent:
            target = os.fspath(self.parent) + "$" + target

        return target
