import typing

from ..detections import Detection
from ...uri_handlers.base import ScanLocation
from .visitor import Visitor
from .nodes import Context


class ReadOnlyAnalyzer(Visitor):
    stage_name = "read_only"
    hooks = []

    def __init__(self, *, location: ScanLocation):
        super().__init__(location=location)
        self.convergence = None

    def __call__(self) -> typing.Generator[Detection, None, None]:
        if not self.hooks:
            return
        elif not self.location.is_python_source_code:
            return
        try:
            for x in self.hooks:
                x.post_analysis(self)

            yield from self.hits

        finally:
            for x in self.hooks:
                x.reset_hook()

    def _visit_node(self, context: Context):
        node_type = "node_" + type(context.node).__name__

        for hook in self.hooks:
            handler = getattr(hook, node_type, None)
            if handler is not None:
                self.hits.extend(handler(context=context))
            elif hasattr(hook, "_visit_node"):
                self.hits.extend(hook._visit_node(context=context))
