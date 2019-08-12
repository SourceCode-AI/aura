"""
Perform execution flow analysis
Lookup module imports and function calls according to semantic rules
"""

from fnmatch import fnmatch

from ..base import NodeAnalyzerV2
from ...utils import Analyzer
from .rewrite_ast import ASTRewrite
from .taint.visitor import TaintAnalysis
from .nodes import *
from ..rules import FunctionCall, ModuleImport
from ... import config


@Analyzer.ID("execution_flow")
@Analyzer.description("Analyze code execution flow to find semantic module imports and function calls")
class ExecutionFlow(NodeAnalyzerV2):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.reset_hook()

    def load_tree(self, source):
        if self.tree is None:
            cached = TaintAnalysis.from_cache(source=source, metadata=self.metadata)
            if not cached.traversed:
                cached.traverse()
            self.tree = cached.tree
            del cached

    def _visit_node(self, context:Context):
        yield from []  # Convert this function to empty generator
        if isinstance(context.node, Call):
            name = context.node.full_name

            if isinstance(name, str):
                for x in config.SEMANTIC_RULES['function_calls']:
                    yield from self.__check_call(name, context, x)
        elif isinstance(context.node, Import):
            yield from self.__check_import(context)
        else:
            pass
            #print(type(context.node))

    def __check_call(self, name, context, signature):
        if not fnmatch(name, signature['call']):
            return

        node = context.node

        hit = FunctionCall(
            function = name,
            score = signature.get('score', 0),
            line_no = node.line_no,
            node = node,
            tags = set(signature.get('tags', [])),
            signature = f"function_call#{name}/{node.line_no}#{context.visitor.path}"
        )
        node.tags |= hit.tags
        hit.informational = (hit.score == 0)
        yield hit

    def __check_import(self, context):
        node = context.node
        #node.pprint()

        for norm in node.get_modules():
            hit = ModuleImport(
                root = norm,
                name = norm,
                line_no = node.line_no,
                node = node,
                signature = f"module_import#{norm}#{context.visitor.path}"
            )

            try:
                for cat in config.SEMANTIC_RULES['modules']:
                    for module in cat['modules']:
                        if fnmatch(module, norm) or fnmatch(module, norm):
                            score = cat.get('score', 0)
                            tags = set(cat.get('tags', []))
                            hit.score += score
                            hit.tags |= tags
                            node.tags |= tags
                            hit.categories.add(cat['name'])
            except Exception:
                raise

            hit.informational = (hit.score == 0)

            yield hit

    def post_analysis(self, analyzer):
        analyzer.hits.extend(self.hits)

    def reset_hook(self):
        self.hits = []
