#-*- coding: utf-8 -*-

import urllib.parse
import logging

logger = logging.getLogger(__name__)


class URIHandler:
    scheme = None
    default = None

    def __init__(self, uri:urllib.parse.ParseResult):
        self.uri = uri

    @classmethod
    def from_uri(cls, uri):
        uri = urllib.parse.urlparse(uri)

        if cls.default and not uri.scheme:
            return cls.default(uri)

        for handler in cls.__subclasses__():
            if handler.scheme == uri.scheme:
                return handler(uri)

        logger.warning(f"No handler for scheme '{uri.scheme}'")

    def get_paths(self):
        raise NotImplementedError("Need to be re-implemented in the child class")

    def cleanup(self):
        pass


class PackageProvider:
    @property
    def package(self):
        raise NotImplementedError("Need to be re-implemented in child class")
