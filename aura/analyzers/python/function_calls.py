from ..base import NodeAnalyzerV2
from ...utils import Analyzer
from ..rules import Rule
from ... import config
from ... import pattern_matching


class FunctionCall(Rule):
    pass


@Analyzer.ID("function_calls")
class FunctionCallAnalyzer(NodeAnalyzerV2):
    """Match signatures defined for function calls against passed arguments"""

    def node_Call(self, context):
        for s in config.SEMANTIC_RULES.get("function_definitions", []):
            sig = pattern_matching.FunctionDefinitionPattern(s)
            match = sig.match(context.node)
            if match is None:
                continue

            sig_id = sig.signature.get("_id") or sig.signature["name"]

            hit = FunctionCall(
                score = sig.signature.get("score", 0),
                message = sig.signature["message"],
                line_no = context.node.line_no,
                node=context.node,
                tags=set(sig.signature.get("tags", [])),
                extra = {
                    "function": context.node.full_name
                },
                signature=f"function_call#{sig_id}/{context.node.line_no}#{context.visitor.path}"
            )

            hit.informational = (hit.score == 0)
            context.node.tags |= hit.tags
            yield hit
