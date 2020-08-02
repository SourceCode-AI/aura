from ..uri_handlers.base import ScanLocation

from .detections import Detection
from ..utils import Analyzer, md5



@Analyzer.ID("file_stats")
def analyze(*, location: ScanLocation):
    """This analyzer collect stats about analyzer files"""

    loc = str(location)

    info = {
        "mime": location.metadata["mime"],
        "size": location.location.stat().st_size,
        "md5": md5(location.location)
    }

    if location.tlsh:
        info["tlsh"] = location.tlsh

    yield Detection(
        detection_type="FileStats",
        message = "Statistics about files scanned by aura",
        informational=True,
        extra=info,
        location=loc,
        signature=f"file_stats#{loc}"
    )
