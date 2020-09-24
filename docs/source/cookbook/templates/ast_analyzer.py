from aura.analyzers.base import NodeAnalyzerV2, Analyzer
from aura.analyzers.python.nodes import Context
from aura.type_definitions import AnalyzerReturnType


# A unique ID is required to identify the analyzer
@Analyzer.ID('custom_analyzer')
class CustomAnalyzer(NodeAnalyzerV2):
    """Some description, this is automatically displayed when running aura info"""

    # This function is called when visiting any type of the AST node
    def _visit_node(self, context: Context) -> AnalyzerReturnType:
        print(f"It works (generic): {context.node}")
        yield from []

    # Hook to a specific type of a node
    def node_Call(self, context: Context) -> AnalyzerReturnType:
        print(f"It works (node_Call): {context.node}")
        yield from []
