from aura.analyzers import base
from aura.utils import Analyzer


# A unique ID is required to identify the analyzer
@Analyzer.ID('custom_analyzer')
class CustomAnalyzer(base.NodeAnalyzerV2):
    """Some description, this is automatically displayed when running aura info"""

    # Hook to a specific type of a node
    def node_Call(self, context):
        print(f"It works: {context.node}")
        yield from []
