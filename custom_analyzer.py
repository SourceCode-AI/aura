from aura.analyzers import base
from aura.bases import ASTAnalyzer
from aura.analyzers.detections import Detection


class CustomAnalyzer(base.NodeAnalyzerV2, ASTAnalyzer):
    """Some description, this is automatically displayed when running aura info"""
    analyzer_id = "custom_analyzer"

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
