#-*- coding: utf-8 -*-
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
