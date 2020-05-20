"""
Perform execution flow analysis
Lookup module imports and function calls according to semantic rules
"""

from fnmatch import fnmatch

from ..base import NodeAnalyzerV2
from ...utils import Analyzer
from .nodes import *
from ..rules import Rule
from ... import config


@Analyzer.ID("execution_flow")  # Rename
class ExecutionFlow(NodeAnalyzerV2):
    """Analyze code execution flow to find semantic module imports and function calls"""
    def node_Import(self, context):
        node = context.node

        for norm in node.get_modules():
            hit = Rule(
                detection_type="ModuleImport",
                message = f"Module '{norm}' import in a source code",
                extra = {
                    "root": norm,
                    "name": norm,
                    "categories": set()
                },
                line_no=node.line_no,
                node=node,
                signature=f"module_import#{norm}#{context.visitor.normalized_path}",
            )

            try:
                for cat in config.SEMANTIC_RULES["modules"]:
                    for module in cat["modules"]:
                        if fnmatch(module, norm) or fnmatch(module, norm):
                            score = cat.get("score", 0)
                            tags = set(cat.get("tags", []))
                            hit.score += score
                            hit.tags |= tags
                            node.tags |= tags
                            hit.extra["categories"].add(cat["name"])
            except Exception:
                raise

            hit.informational = hit.score == 0
            yield hit
