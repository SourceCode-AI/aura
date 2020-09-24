from aura.analyzers.base import Analyzer
from aura.analyzers.detections import Detection
from aura.uri_handlers.base import ScanLocation
from aura.type_definitions import AnalyzerReturnType


@Analyzer.ID("file_permission_check")
def file_permission_analyzer(location: ScanLocation) -> AnalyzerReturnType:
    """
    This is a description for my analyzer, it will be automatically displayed in the `aura info` output
    """
    detection = Detection(
        detection_type="FilePermissions",
        location=str(location),
        signature=f"file_permissions#{str(location)}",
        message="",  # will be replaced by file checks below
        score=10
    )

    if location.location.owner() == "root":  # Check if the file is owned by root
        detection.message = "File is owned by root"
        yield detection

    if location.location.stat().st_mode & 0o777:  # Check if the file permissions are too open
        detection.message = "File permissions are too open (777)"
        yield detection
