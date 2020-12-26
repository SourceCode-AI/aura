from ..uri_handlers.base import ScanLocation

from .detections import Detection
from ..utils import Analyzer, md5



@Analyzer.ID("file_stats")
def analyze(*, location: ScanLocation):
    """This analyzer collect stats about analyzer files"""
    l = location
    while l:
        if l.metadata.get("source") == "diff":
            return
        l = l.parent

    loc = str(location)  # TODO: refactor this line

    info = {
        "mime": location.metadata["mime"],
        "size": location.size,
    }

    for x in ("tlsh", "md5", "sha1", "sha256", "sha512"):
        if x in location.metadata:
            info[x] = location.metadata[x]

    yield Detection(
        detection_type="FileStats",
        message = "Statistics about files scanned by aura",
        informational=True,
        extra=info,
        location=loc,
        signature=f"file_stats#{loc}"
    )
