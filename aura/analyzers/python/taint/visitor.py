from pathlib import Path

from ..nodes import *
from ..visitor import Visitor
from ..rewrite_ast import ASTRewrite


TAINT_SOURCES = (
    'flask.request',
)

TAINT_SINKS = (
    'flask.make_response',
    'flask.jsonify',
    'json.dumps',
    'os.system',
    'subprocess.Popen',
)


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
            self.__mark_safe_constants,
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

        if f_name in TAINT_SINKS and 'taint_sink' not in context.node.tags:
            context.node.tags.add('taint_sink')
            context.visitor.modified = True

    def __mark_sources(self, context):
        f_name = context.node.full_name

        if f_name in TAINT_SOURCES and 'taint_source' not in context.node.tags:
            context.node.tags.add('taint_source')
            context.visitor.modified = True
            return

    def __mark_safe_constants(self, context):
        if isinstance(context.node, (String, Number)):
            if context.node._taint_class != Taints.SAFE:
                context.node._taint_class = Taints.SAFE
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
