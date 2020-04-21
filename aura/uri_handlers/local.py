# -*- coding: utf-8 -*-
import pathlib
from urllib.parse import ParseResult

from .base import URIHandler, ScanLocation


class LocalFileHandler(URIHandler):
    scheme = "file"
    help = """
    Local file handler:\n
    Default URI handler, any given URI that is not specifically handled by other handlers is considered to be a local path
    Accept references to either local files or directories\n
    By aware that paths to local directories are not supported by all modules as some of them require direct path to a file\n
    
    Examples:\n
    - ./quarantine\n
    - /tmp/package.tgz\n
    - file:///tmp/pypi-package.egg
    """

    def __init__(self, uri: ParseResult):
        super().__init__(uri)

        self.uri = uri
        self.path = pathlib.Path(uri.path)
        self.opts = {}

    def get_paths(self):
        yield ScanLocation(
            location=self.path,
            metadata={
                "depth": 0
            }
        )

    @property
    def exists(self) -> bool:
        return self.path.exists()


# Set this as the default handler
LocalFileHandler.default = True
