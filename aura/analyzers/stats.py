from ..uri_handlers.base import ScanLocation

from .rules import Rule
from ..utils import Analyzer



@Analyzer.ID("file_stats")
def analyze(*, location: ScanLocation):
    """This analyzer collect stats about analyzer files"""

    loc = str(location)

    yield Rule(
        detection_type="FileStats",
        message = "Statistics about files scanned by aura",
        informational=True,
        extra={
            "mime": location.metadata["mime"],
            "size": location.location.stat().st_size
        },
        location=loc,
        signature=f"file_stats#{loc}"
    )
