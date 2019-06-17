#-*- coding: utf-8 -*-
import os
import urllib.parse
from dataclasses import dataclass, field
from  pathlib import Path

import pkg_resources

from .. import config

logger = config.get_logger(__name__)
HANDLERS = {}


class URIHandler:
    scheme = None
    default = None

    def __init__(self, uri:urllib.parse.ParseResult):
        self.uri = uri

    @classmethod
    def from_uri(cls, uri):
        uri = urllib.parse.urlparse(uri)
        cls.load_handlers()

        if cls.default and not uri.scheme:
            return cls.default(uri)

        for handler in HANDLERS.values():
            if handler.scheme == uri.scheme:
                return handler(uri)

        logger.error(f"No handler for scheme '{uri}'")

    @classmethod
    def load_handlers(cls):
        global HANDLERS

        if not HANDLERS:
            handlers = {}
            for x in pkg_resources.iter_entry_points('aura.uri_handlers'):
                hook = x.load()
                handlers[hook.scheme] = hook
                if hook.default and not cls.default:
                    cls.default = hook

            HANDLERS = handlers
        return HANDLERS

    @property
    def metadata(self):
        return {}

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
    parent: str = None
    strip_path: str = ''

    def create_child(self, new_location):
        child = self.__class__(
            location = new_location,
            metadata = self.metadata,
            strip_path = self.strip_path,
            parent = self.parent,
        )
        return child

    def strip(self, target):
        target = os.fspath(target)

        if self.strip_path and target.startswith(self.strip_path):
            size = len(self.strip_path)
            if self.strip_path[-1] != '/':
                size += 1

            target = target[size:]

        if self.parent:
            target = os.fspath(self.parent) + '$' + target

        return target
