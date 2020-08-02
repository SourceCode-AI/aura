from aura.analyzers import base
from aura.utils import Analyzer
from aura.analyzers.detections import Detection


# A unique ID is required to identify the analyzer
@Analyzer.ID('custom_analyzer')
class CustomAnalyzer(base.NodeAnalyzerV2):
    """Some description, this is automatically displayed when running aura info"""

    # Hook to a specific type of a node
    def node_String(self, context):
        yield Detection(
            detection_type = "CustomAnalyzer",
            signature = f"str#{context.visitor.normalized_path}#{context.node.line_no}",
            message = "String detection",
            extra = {
                "string_content": str(context.node)
            },
            tags = {"custom_tag",}
        )
