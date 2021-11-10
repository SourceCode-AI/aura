import datetime
from typing import Set, Optional

from .package_analyzer import Analyzer
from .analyzers.base import PostAnalysisHook
from .analyzers.detections import Detection
from .uri_handlers.base import ScanLocation, URIHandler


class ScanData:
    def __init__(self, scan_location: ScanLocation, uri_handler: Optional[URIHandler]=None):
        self.location = scan_location
        self.handler = uri_handler

        self.metadata = {
            "depth": 0,
            "paths": []
        }

        if uri_handler:
            self.metadata["name"] = str(uri_handler)
            self.metadata["uri_scheme"] = uri_handler.scheme
            self.metadata["uri_input"] = uri_handler.metadata

        self.hits: Set[Detection] = set()

    def scan(self):
        self.metadata["start_time"] = datetime.datetime.utcnow().timestamp()
        # TODO: check if this works when location does not exists as the `commands.scan_worker` is handling that
        hits = set(Analyzer.run(self.location))
        self.hits |= set(PostAnalysisHook.run_hooks(hits, self.metadata))
        self.metadata["end_time"] = datetime.datetime.utcnow().timestamp()

    def as_dict(self) -> dict:
        # TODO
        data = {
            "metadata": self.metadata
        }
        return data
