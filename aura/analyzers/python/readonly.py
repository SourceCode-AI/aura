import os
import typing
from pathlib import Path

from .. import rules
from .taint.visitor import TaintAnalysis
from .visitor import Visitor
from .nodes import Context


class ReadOnlyAnalyzer(Visitor):
    hooks = []

    def load_tree(self, source: Path):
        if self.tree is None:
            cached = TaintAnalysis.from_cache(source=source, metadata=self.metadata)
            if not cached.traversed:
                cached.traverse()

            self.tree = cached.tree

    def __call__(self, pth: Path) -> typing.Iterator[rules.Rule]:
        if not self.hooks:
            return
        elif self.kwargs.get("mime") != "text/x-python" and not os.fspath(
            self.path
        ).endswith(".py"):
            return
        try:
            self.load_tree(source=pth)
            self.traverse()

            for x in self.hooks:
                x.post_analysis(self)

            for x in self.hits:
                if x.location is None:
                    x.location = os.fspath(pth)

            rules.Rule.lookup_lines(self.hits)
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
