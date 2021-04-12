import math

from .. import base
from .. import detect_redos
from ..detections import Detection
from ...utils import Analyzer, fast_checksum
from ... import config


ENTROPY_THRESHOLD = float(config.CFG["aura"].get("shanon_entropy", 0.0))


@Analyzer.ID("misc")
class MiscAnalyzer(base.NodeAnalyzerV2):
    """Various checks mostly for best-practices"""

    def node_String(self, context):
        val = str(context.node)
        entropy = calculate_entropy(val)

        if ENTROPY_THRESHOLD > 0 and entropy >= ENTROPY_THRESHOLD:
            hit = Detection(
                detection_type="HighEntropyString",
                message="A string with high shanon entropy was found",
                extra={
                    "type": "high_entropy_string",
                    "entropy": entropy,
                    "string": val,
                },
                signature=f"misc#high_entropy#{fast_checksum(val)}#{context.signature}",
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
                hit = Detection(
                    detection_type="ReDoS",
                    message = "Possible catastrophic ReDoS",
                    extra = {
                        "type": "redos",
                        "regex": val,
                    },
                    signature = f"misc#redos#{fast_checksum(val)}#{context.signature}",
                    node=context.node,
                    tags={"redos"}
                )
                yield hit
        except RecursionError:
            yield Detection(
                detection_type="Misc",
                message="Recursion limit exceeded when scanning regex pattern for ReDoS",
                extra={
                    "regex": val
                },
                signature=f"misc#redos_recursion_error#{fast_checksum(val)}#{context.signature}",
                node=context.node
            )

    def node_FunctionDef(self, context):
        if type(context.node.name) != str:
            return
        if not context.node.name in ("__reduce__", "__reduce_ex__"):
            return

        # TODO look maybe for a suspicious function calls inside the reduce method

        hit = Detection(
            message = f"Usage of {context.node.name} in an object indicates a possible pickle exploit",
            signature = f"misc#pickleploit#{context.signature}",
            node = context.node,
            score = 100,
            tags = {context.node.cached_full_name, "pickleploit"}
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
