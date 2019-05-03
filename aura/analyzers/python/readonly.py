import typing
from pathlib import Path


from .. import rules
from .rewrite_ast import ASTRewrite
from .visitor import Visitor
from .nodes import Context
from ...utils import lookup_lines, construct_path


class ReadOnlyAnalyzer(Visitor):
    hooks = []

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.hits = []
        self.path = kwargs['metadata']['path']

    def load_tree(self, source: Path):
        if self.tree is None:
            cached = ASTRewrite.from_cache(source=source, metadata=self.metadata)
            if not cached.traversed:
                cached.traverse()

            self.tree = cached.tree

    def __call__(self, pth: Path) -> typing.Iterator[rules.Rule]:
        if not self.hooks:
            return
        elif self.kwargs.get('mime') != 'text/x-python':
            return
        try:
            self.load_tree(source=pth)
            self.traverse()

            for x in self.hooks:
                x.post_analysis(self)

            lines = [x.line_no for x in self.hits if x.line_no is not None]
            lines_lookup = lookup_lines(pth, lines)
            for x in self.hits:
                if x.location is None:
                    x.location = construct_path(
                        pth,
                        self.kwargs.get('strip_path'),
                        parent=self.kwargs.get('parent')
                    )

                if x.line_no in lines_lookup and not x.line:
                    x.line = lines_lookup[x.line_no]

                yield x

        finally:
            for x in self.hooks:
                x.reset_hook()

    def _visit_node(self, context:Context):
        node_type = 'node_' + type(context.node).__name__

        for hook in self.hooks:
            handler = getattr(hook, node_type, None)
            if handler is not None:
                self.hits.extend(handler(context=context))
            elif hasattr(hook, '_visit_node'):
                self.hits.extend(hook._visit_node(context=context))
