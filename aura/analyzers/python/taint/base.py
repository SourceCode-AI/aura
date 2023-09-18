from itertools import groupby
from typing import Optional, cast

from ..nodes import Taints, ASTNode, TaintLog, Context, NodeType, ReturnStmt
from ...base import NodeAnalyzerV2
from ...detections import Detection
from ....bases import ASTAnalyzer
from .... import config


class TaintDetection(NodeAnalyzerV2, ASTAnalyzer):
    """Analyze propagation of tainted data into sinks"""
    analyzer_id = "taint_analysis"

    def __generate_hit(self, context) -> Detection:
        log = TaintLog.extract_log(context.node)
        log = [x[0] for x in groupby(log)]  # Remove consecutive duplicate logs

        return Detection(
            detection_type="TaintAnomaly",
            score=config.get_score_or_default("taint-anomaly", 10),
            message="Tainted input is passed to the sink",
            node=context.node,
            line_no=context.node.line_no,
            signature=f"taint_anomaly#{context.visitor.normalized_path}#{context.node.line_no}",
            extra={
                'taint_log': log
            },
            tags = {"vuln:taint"}
        )

    def node_Call(self, context):
        if "taint_sink" not in context.node.tags:
            return

        if context.node._taint_class == Taints.TAINTED:
            yield self.__generate_hit(context=context)
            return

        for x in context.node.args:  # type: NodeType
            if not isinstance(x, ASTNode):
                continue

            if x._taint_class == Taints.TAINTED:
                yield self.__generate_hit(context=context)

    def node_ReturnStmt(self, context: Context):
        node = cast(ReturnStmt, context.node)

        if not node._taint_class == Taints.TAINTED:
            return

        ctx : Optional[Context] = context
        while ctx:
            if isinstance(ctx.node, ASTNode) and "flask_route" in ctx.node.tags:
                yield self.__generate_hit(context=context)
                return
            else:
                ctx = ctx.parent
