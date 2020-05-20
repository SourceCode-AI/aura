from typing import Callable, Generator, Union


from .analyzers.rules import Rule
from .analyzers.base import NodeAnalyzerV2
from .uri_handlers.base import ScanLocation


AnalyzerFunction = Callable[[ScanLocation], Generator[Rule, None, None]]
AnalyzerType = Union[NodeAnalyzerV2, AnalyzerFunction]
