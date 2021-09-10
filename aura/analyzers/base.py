from abc import ABCMeta
from typing import List

from .python.readonly import ReadOnlyAnalyzer
from .detections import Detection
from .. import exceptions
from ..uri_handlers.base import ScanLocation
from ..utils import Analyzer   # Imported for convenience


class NodeAnalyzerV2(metaclass=ABCMeta):
    def reset_hook(self):
        pass

    def post_analysis(self, analyzer: ReadOnlyAnalyzer):  # TODO: check why is this here
        pass


class PostAnalysisHook:
    _hooks = []

    @classmethod
    def run_hooks(cls, detections: List[Detection], metadata: dict) -> List[Detection]:
        for hook in PostAnalysisHook._hooks:
            detections = hook.post_analysis(detections, metadata)

        return detections

    def post_analysis(self, detections: List[Detection], metadata: dict) -> List[Detection]:
        return detections
