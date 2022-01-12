from __future__ import annotations

from typing import List, Iterable

from .python.readonly import ReadOnlyAnalyzer
from .detections import Detection
from ..type_definitions import AnalyzerType


class NodeAnalyzerV2:
    def reset_hook(self):
        pass

    def post_analysis(self, analyzer: ReadOnlyAnalyzer):  # TODO: check why is this here
        pass


class PostAnalysisHook:
    _hooks: List[PostAnalysisHook] = []

    @classmethod
    def run_hooks(cls, detections: Iterable[Detection], metadata: dict) -> Iterable[Detection]:
        for hook in PostAnalysisHook._hooks:
            detections = hook.post_analysis(detections, metadata)

        return detections

    def post_analysis(self, detections: Iterable[Detection], metadata: dict) -> Iterable[Detection]:
        return detections
