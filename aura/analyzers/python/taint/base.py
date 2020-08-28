from itertools import groupby

from ..nodes import Taints, ASTNode, TaintLog
from ...base import NodeAnalyzerV2
from ...detections import Detection
from ....utils import Analyzer


@Analyzer.ID("taint_analysis")
class TaintDetection(NodeAnalyzerV2):
    """Analyze propagation of tainted data into sinks"""

    def __generate_hit(self, context) -> Detection:
        log = TaintLog.extract_log(context.node)
        log = [x[0] for x in groupby(log)]  # Remove consecutive duplicate logs

        return Detection(
            detection_type="TaintAnomaly",
            score=10,
            message="Tainted input is passed to the sink",
            node=context.node,
            line_no=context.node.line_no,
            signature=f"taint_anomaly#{context.visitor.normalized_path}#{context.node.line_no}",
            extra={
                'taint_log': log
            }
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

    def node_ReturnStmt(self, context):
        if not context.node._taint_class == Taints.TAINTED:
            return

        ctx = context  # type: Context
        while ctx:
            if isinstance(ctx.node, ASTNode) and "flask_route" in ctx.node.tags:
                yield self.__generate_hit(context=context)
                return
            else:
                ctx = ctx.parent
