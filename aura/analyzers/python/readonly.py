import typing as t

from ..detections import Detection
from .visitor import Visitor
from .nodes import Context
from ...type_definitions import ScanLocationType


class ReadOnlyAnalyzer(Visitor):
    stage_name = "read_only"
    hooks = []
    __slots__ = Visitor.__slots__

    def __init__(self, *, location: ScanLocationType):
        super().__init__(location=location)
        self.convergence = None

    def __call__(self) -> t.Iterable[Detection]:
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
            if (handler := hook.defined_node_types.get(node_type)):
                self.hits.extend(handler(context=context))

            self.hits.extend(hook._visit_node(context=context))
