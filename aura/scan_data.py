import datetime
from typing import Set, Optional, Sequence, Tuple

from .package_analyzer import Analyzer
from .analyzers.base import PostAnalysisHook
from .analyzers.detections import Detection
from .uri_handlers.base import ScanLocation, URIHandler
from .bases import JSONSerializable
from . import __version__


class ScanData(JSONSerializable):
    def __init__(self, scan_location: ScanLocation, uri_handler: Optional[URIHandler]=None, filter_cfg=None):
        self.location = scan_location
        self.handler = uri_handler
        self.filter_cfg = filter_cfg

        self.metadata = {
            "depth": 0,
            "paths": []
        }

        if uri_handler:
            self.metadata["name"] = self.location.metadata.get("name") or str(uri_handler)
            self.metadata["uri_scheme"] = uri_handler.scheme
            self.metadata["uri"] = str(uri_handler)

        for k, v in self.location.metadata.items():
            if k not in self.metadata and type(v) == str:
                self.metadata[k] = v

        self.hits: Set[Detection] = set()

    def scan(self):
        self.metadata["start_time"] = datetime.datetime.utcnow().timestamp()
        # TODO: check if this works when location does not exists as the `commands.scan_worker` is handling that
        hits = tuple(Analyzer.run(self.location))
        post_analysis_hits = set(PostAnalysisHook.run_hooks(hits, self.metadata))

        if self.filter_cfg:
            self.hits = set(self.filter_cfg.filter_detections(post_analysis_hits))
        else:
            self.hits = post_analysis_hits

        self.metadata["end_time"] = datetime.datetime.utcnow().timestamp()

    def to_dict(self) -> dict:
        score = 0
        tags = set()
        imported_modules = set()

        for x in self.hits:
            tags |= x.tags
            score += x.score
            if x.name == "ModuleImport":
                imported_modules.add(x.extra["name"])

        data = {
            "detections": [x.to_dict() for x in self.hits],
            "tags": tags,
            "imported_modules": imported_modules,
            "metadata": self.metadata,
            "score": score,
            "name": self.metadata["name"],
            "version": __version__
        }
        return data
