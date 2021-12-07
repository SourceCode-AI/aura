import datetime
from typing import Set, Optional, Sequence, Tuple

from .package_analyzer import Analyzer
from .analyzers.base import PostAnalysisHook
from .analyzers.detections import Detection
from .uri_handlers.base import ScanLocation, URIHandler
from . import __version__


class ScanData:
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

    def as_dict(self) -> dict:
        score = 0
        tags = set()
        imported_modules = set()

        for x in self.hits:
            tags |= x.tags
            score += x.score
            if x.name == "ModuleImport":
                imported_modules.add(x.extra["name"])

        data = {
            "detections": [x._asdict() for x in self.hits],
            "tags": tags,
            "imported_modules": imported_modules,
            "metadata": self.metadata,
            "score": score,
            "name": self.metadata["name"],
            "version": __version__
        }
        return data


# TODO: this is a fallback for the refactor of the new ScanData format for output formats
#       existing code should be updated to not use this if possible
def merge_scans(scans: Sequence[ScanData]) -> Tuple[dict, Set[Detection]]:
    all_hits = set()

    start = end = 0

    for scan in scans:
        start = min(scan.metadata["start_time"], start)
        end = max(scan.metadata["end_time"], end)
        all_hits |= set(scan.hits)

    meta = scans[0].metadata.copy()
    meta["start_time"] = start
    meta["end_time"] = end

    return (meta, all_hits)
