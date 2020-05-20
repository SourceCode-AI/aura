import math

from .. import base
from .. import detect_redos
from ..rules import Rule
from ...utils import Analyzer
from ... import config


ENTROPY_THRESHOLD = float(config.CFG.get("aura", "shanon_entropy", fallback=0.0))


@Analyzer.ID("misc")
class MiscAnalyzer(base.NodeAnalyzerV2):
    """Various checks mostly for best-practices"""

    def node_String(self, context):
        val = str(context.node)
        entropy = calculate_entropy(val)

        if ENTROPY_THRESHOLD > 0 and entropy >= ENTROPY_THRESHOLD:
            hit = Rule(
                message="A string with high shanon entropy was found",
                extra={
                    "type": "high_entropy_string",
                    "entropy": entropy,
                    "string": val,
                },
                signature=f"misc#high_entropy#{context.visitor.normalized_path}#{context.node.line_no}",
                node=context.node
            )
            hit.line_no = context.node.line_no
            yield hit

        # ReDoS Detection
        # DoS attack via catastrophic regex backtracking
        # Inspired by:
        # https://github.com/dlint-py/dlint/blob/master/docs/linters/DUO138.md
        # https://github.com/dlint-py/dlint/blob/master/dlint/linters/bad_re_catastrophic_use.py

        try:
            if detect_redos.catastrophic(val):
                hit = Rule(
                    message = "Possible catastrophic ReDoS",
                    extra = {
                        "type": "redos",
                        "regex": val,
                    },
                    signature = f"misc#redos#{context.visitor.normalized_path}#{context.node.line_no}",
                    node=context.node,
                    tags={"redos"}
                )
                yield hit
        except RecursionError:
            yield Rule(
                detection_type="Misc",
                message="Recursion limit exceeded when scanning regex pattern for ReDoS",
                extra={
                    "regex": val
                },
                signature=f"misc#redos_recursion_error#{context.visitor.normalized_path}#{context.node.line_no}",
                node=context.node
            )

    def node_FunctionDef(self, context):
        if type(context.node.name) != str:
            return
        if not context.node.name in ("__reduce__", "__reduce_ex__"):
            return

        # TODO look maybe for a suspicious function calls inside the reduce method

        hit = Rule(
            message = f"Usage of {context.node.name} in an object indicates a possible pickle exploit",
            signature = f"pickleploit#{context.visitor.normalized_path}#{context.node.line_no}",
            line_no = context.node.line_no,
            score = 100,
            tags = {context.node.name}
        )
        yield hit


def calculate_entropy(data: str, iterator=lambda: range(255)) -> float:
    """
    Calculate shanon entropy of the string
    """
    if not data:
        return 0

    entropy = 0
    for x in iterator():
        p_x = float(data.count(chr(x))) / len(data)
        if p_x > 0:
            entropy += -p_x * math.log(p_x, 2)

    return entropy
