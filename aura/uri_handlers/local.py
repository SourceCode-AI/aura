#-*- coding: utf-8 -*-
import pathlib
from urllib.parse import ParseResult

from .base import URIHandler


class LocalFileHandler(URIHandler):
    scheme = 'file'

    def __init__(self, uri: ParseResult):
        self.uri = uri
        self.path = pathlib.Path(uri.path)
        self.opts = {}

    def get_paths(self):
        yield self.path


# Set this a the default handler
URIHandler.default = LocalFileHandler
