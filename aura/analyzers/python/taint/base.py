from ..nodes import Taints
from ...base import NodeAnalyzerV2
from ...rules import Rule
from ....utils import Analyzer


class TaintAnomaly(Rule):
    pass


@Analyzer.ID('taint_analysis')
@Analyzer.description("Analyze propagation of tainted data into sinks")
class TaintDetection(NodeAnalyzerV2):
    def __generate_hit(self, context) -> TaintAnomaly:
        return TaintAnomaly(
            score = 10,
            message = "Tainted input is passed to the sink",
            node = context.node,
            line_no = context.node.line_no,
            signature = f"taint_anomaly#{context.visitor.path}#{context.node.line_no}"
        )

    def node_Call(self, context):
        if 'taint_sink' not in context.node.tags:
            return

        for x in context.node.args:  # type: NodeType
            if x._taint_class == Taints.TAINTED:
                yield self.__generate_hit(context=context)

