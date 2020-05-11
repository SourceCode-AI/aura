from aura.analyzers.base import NodeAnalyzerV2, Analyzer
from aura.analyzers.rules import Rule


class ClassAnalyzer(NodeAnalyzerV2):
    def __call__(self, **kwargs):
        _id = "class_analyzer_response"
        yield Rule(
            detection_type=_id,
            message=_id,
            signature=_id
        )


@Analyzer.ID("patch_analyzer_id")
def path_analyzer(**kwargs):
    _id = "path_analyzer_response"
    yield Rule(
        detection_type=_id,
        message=_id,
        signature=_id
    )
