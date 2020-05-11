import typing

from .. import rules
from .visitor import Visitor
from .nodes import Context


class ReadOnlyAnalyzer(Visitor):
    stage_name = "read_only"
    hooks = []

    def __call__(self) -> typing.Generator[rules.Rule, None, None]:
        if not self.hooks:
            return
        elif self.location.metadata["mime"] != "text/x-python":
            return
        try:
            for x in self.hooks:
                x.post_analysis(self)

            for x in self.hits:
                if x.location is None:
                    x.location = self.location.location

            rules.Rule.lookup_lines(self.hits, location=self.location)
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
