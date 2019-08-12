from aura.analyzers import base
from aura.utils import Analyzer


@Analyzer.ID('custom_analyzer')
@Analyzer.description("Some description")
class CustomAnalyzer(base.NodeAnalyzerV2):
    def node_Call(self, context):
        print(f"It works: {context.node}")
        yield from []
