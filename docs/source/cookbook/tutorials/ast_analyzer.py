from aura.analyzers.base import NodeAnalyzerV2, Analyzer
from aura.analyzers.detections import Detection
from aura.analyzers.python.nodes import FunctionDef, Context
from aura.type_definitions import AnalyzerReturnType


@Analyzer.ID('nested_function_def')
class CustomAnalyzer(NodeAnalyzerV2):
    """Detect nested function definitions"""

    # Hook to a specific type of a node
    def node_FunctionDef(self, context: Context) -> AnalyzerReturnType:
        parent: Context = context.parent

        while parent is not None:
            if isinstance(parent.node, FunctionDef):
                detection = Detection(
                    detection_type="NestedFunctionDef",
                    score = 5,
                    message = "Nested function definition detected",
                    signature = f"nested_function_def#{context.visitor.normalized_path}#{context.node.line_no}",
                    node = context.node
                )
                yield detection
                break
            parent = parent.parent
