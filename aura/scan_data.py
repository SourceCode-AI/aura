import datetime

from .package_analyzer import Analyzer
from .analyzers.base import PostAnalysisHook
from .uri_handlers.base import ScanLocation


class ScanData:
    def __init__(self, scan_location: ScanLocation, uri_handler=None):
        self.location = scan_location
        self.handler = uri_handler

        self.metadata = {
            "depth": 0,
            "paths": []
        }

        if uri_handler:
            self.metadata["uri_scheme"] = uri_handler.scheme
            self.metadata["uri_input"] = uri_handler.metadata

        self.hits = []


    def scan(self):
        self.metadata["start_time"] = datetime.datetime.utcnow().timestamp()
        # TODO: check if this works when location does not exists as the `commands.scan_worker` is handling that
        hits = tuple(Analyzer.run(self.location))
        self.hits.extend(PostAnalysisHook.run_hooks(hits, self.metadata))
        self.metadata["end_time"] = datetime.datetime.utcnow().timestamp()

    def as_dict(self) -> dict:
        # TODO
        data = {
            "metadata": self.metadata
        }
        return data
