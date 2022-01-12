import typing as t
from pathlib import Path
from typing import Callable, Generator, Union, NewType

from .analyzers.detections import Detection
#rom .analyzers.base import NodeAnalyzerV2
from .worker_executor import Wait


class ScanLocationType:
    ...


AnalyzerReturnType = Generator[Union[ScanLocationType, Detection], None, None]
AnalyzerFunction = Callable[[ScanLocationType], AnalyzerReturnType]
#AnalyzerType = Union[NodeAnalyzerV2, AnalyzerFunction]
AnalyzerType = Union[AnalyzerFunction, object]
AnalysisQueueItem = Union[ScanLocationType, t.Literal[Wait]]
ReleaseInfo = NewType("ReleaseInfo", dict)
DiffType = NewType("DiffType", object)
DiffAnalyzerType = NewType("DiffAnalyzerType", object)
