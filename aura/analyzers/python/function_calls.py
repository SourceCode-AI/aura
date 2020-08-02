from ..base import NodeAnalyzerV2
from ...utils import Analyzer
from ..detections import Detection
from ... import config
from ... import pattern_matching


@Analyzer.ID("function_calls")
class FunctionCallAnalyzer(NodeAnalyzerV2):
    """Match signatures defined for function calls against passed arguments"""

    def __init__(self, *args, **kwargs):
        super(FunctionCallAnalyzer, self).__init__(*args, **kwargs)

        self.__function_defs = []
        for func_def in config.SEMANTIC_RULES.get("function_definitions", []):
            self.__function_defs.append(pattern_matching.FunctionDefinitionPattern(func_def))

    def node_Call(self, context):
        for sig in self.__function_defs:
            match = sig.match_node(context)
            if not match:
                continue

            sig_id = sig.signature.get("_id") or sig.signature["name"]

            hit = Detection(
                detection_type="FunctionCall",  # TODO: search for potential usages and fix to use generic detection
                score = sig.signature.get("score", 0),
                message = sig.signature["message"],
                node=context.node,
                tags=set(sig.signature.get("tags", [])) | {sig_id},
                extra = {
                    "function": context.node.cached_full_name
                },
                signature=f"function_call#{sig_id}/{context.node.line_no}#{context.visitor.normalized_path}"
            )

            hit.informational = (hit.score == 0)
            context.node.tags |= hit.tags
            yield hit
