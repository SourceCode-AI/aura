from typing import Callable, Generator, Union, NewType

from .analyzers.detections import Detection
from .analyzers.base import NodeAnalyzerV2
from .uri_handlers.base import ScanLocation


AnalyzerReturnType = Generator[Union[ScanLocation, Detection], None, None]
AnalyzerFunction = Callable[[ScanLocation], AnalyzerReturnType]
AnalyzerType = Union[NodeAnalyzerV2, AnalyzerFunction]
ReleaseInfo = NewType("ReleaseInfo", dict)
DiffType = NewType("DiffType", object)
DiffAnalyzerType = NewType("DiffAnalyzerType", object)

