# -*- coding: utf-8 -*-
import pathlib
from itertools import product
from urllib.parse import ParseResult
from typing import Optional, Iterable

from .base import URIHandler, ScanLocation
from ..exceptions import UnsupportedDiffLocation


class LocalFileHandler(URIHandler):
    default = True
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

    def get_paths(self, metadata: Optional[dict]=None) -> Iterable[ScanLocation]:
        yield ScanLocation(
            location=self.path,
            metadata=metadata or {"depth": 0}
        )

    def get_diff_paths(self, other: URIHandler):
        if isinstance(other, LocalFileHandler):
            for loc1, loc2 in product(self.get_paths(), other.get_paths()):
                loc1.metadata["report_imports"] = True
                loc2.metadata["report_imports"] = True

                if loc1.location.is_dir():
                    loc1.strip_path = str(loc1.location.absolute())
                else:
                    loc1.strip_path = str(loc1.location.parent)

                if loc2.location.is_dir():
                    loc2.strip_path = str(loc2.location.absolute())
                else:
                    loc2.strip_path = str(loc2.location.parent)

                yield loc1, loc2
        else:
            raise UnsupportedDiffLocation()

    @property
    def exists(self) -> bool:
        return self.path.exists()
