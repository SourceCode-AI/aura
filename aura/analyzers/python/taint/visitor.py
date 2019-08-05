import pprint
import fnmatch
from pathlib import Path

from ..nodes import *
from ..visitor import Visitor
from ..rewrite_ast import ASTRewrite
from .... import config


class TaintAnalysis(Visitor):
    def load_tree(self, source: Path):
        if self.tree is None:
            cached = ASTRewrite.from_cache(source=source, metadata=self.metadata)
            if not cached.traversed:
                cached.traverse()
            self.tree = cached.tree
            del cached

    def _visit_node(self, context:Context):
        if not isinstance(context.node, ASTNode):
            return

        funcs = (
            self.__mark_flask_route,
            self.__mark_sinks,
            self.__mark_sources,
            self.__propagate_taint,
        )

        for x in funcs:
            x(context=context)
            if context.visitor.modified:
                return

    def __mark_flask_route(self, context):
        if not isinstance(context.node, FunctionDef):
            return

        if not len(context.node.decorator_list) > 0:
            return

        for dec in context.node.decorator_list:
            if isinstance(dec, Call) and isinstance(dec.func, Attribute) and dec.func.attr == 'route':
                if 'flask_route' not in context.node.tags:
                    context.node.tags.add('flask_route')
                    context.visitor.modified = True
                    return

    def __mark_sinks(self, context):
        f_name = context.node.full_name
        if f_name is None:
            return

        if f_name in config.SEMANTIC_RULES.get('taint_sinks', []) and 'taint_sink' not in context.node.tags:
            context.node.tags.add('taint_sink')
            context.visitor.modified = True

    def __mark_sources(self, context):
        f_name = context.node.full_name

        if not (isinstance(f_name, str) and 'taint_source' not in context.node.tags):
            return

        for source in config.SEMANTIC_RULES.get('taint_sources', []):
            if source == f_name or fnmatch.fnmatch(f_name, source):
                context.node.tags.add('taint_source')
                context.node._taint_class = Taints.TAINTED
                context.visitor.modified = True
                return

    def __propagate_taint(self, context):
        if isinstance(context.node, Attribute) and isinstance(context.node.source, ASTNode):
            t = context.node.source._taint_class

            if 'taint_source' in context.node.source.tags and context.node._taint_class != Taints.TAINTED:
                context.node._taint_class = Taints.TAINTED
                context.visitor.modified = True
                return
            elif t != Taints.UNKNOWN and t != context.node._taint_class:
                context.node._taint_class = t
                context.visitor.modified = True
                return
        elif isinstance(context.node, Call):
            args_taints = []
            for x in context.node.args:
                args_taints.append(x._taint_class)
            for x in context.node.kwargs.values():
                args_taints.append(x._taint_class)

            if not args_taints:
                return

            call_taint = max(args_taints)
            if call_taint != context.node._taint_class:
                context.node._taint_class = call_taint
                context.visitor.modified = True
                return
        elif isinstance(context.node, Var):
            var_taint = max(
                context.node._taint_class,
                getattr(context.node.value, '_taint_class', Taints.UNKNOWN)
            )

            if var_taint != context.node._taint_class:
                context.node._taint_class = var_taint
                context.visitor.modified = True
                return
