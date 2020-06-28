from ..uri_handlers.base import ScanLocation

from .rules import Rule
from ..utils import Analyzer



@Analyzer.ID("file_stats")
def analyze(*, location: ScanLocation):
    """This analyzer collect stats about analyzer files"""

    loc = str(location)

    info = {
        "mime": location.metadata["mime"],
        "size": location.location.stat().st_size
    }

    if location.tlsh:
        info["tlsh"] = location.tlsh

    yield Rule(
        detection_type="FileStats",
        message = "Statistics about files scanned by aura",
        informational=True,
        extra=info,
        location=loc,
        signature=f"file_stats#{loc}"
    )
