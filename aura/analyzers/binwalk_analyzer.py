import re

from .. import config
from .base import AnalyzerDeactivated
from .detections import Detection
from ..uri_handlers.base import ScanLocation
from ..utils import Analyzer, md5


try:
    import binwalk
except ImportError:
    raise AnalyzerDeactivated(
        "You must install binwalk python module to enable this integration"
    )

FILTER_MODE = None
FILE_FILTERING = None


def can_process_location(location: ScanLocation) -> bool:
    global FILTER_MODE, FILE_FILTERING

    if config.CFG["binwalk"].get("enabled", True) is False:
        return False

    if FILTER_MODE is None:
        FILTER_MODE = config.CFG["binwalk"]["mode"]
        FILE_FILTERING = []

        for x in config.CFG["binwalk"].get("mimetypes", []):
            if x.startswith("^"):
                FILE_FILTERING.append(re.compile(x))
            else:
                FILE_FILTERING.append(x)

    mime = location.metadata.get("mime", "")
    if not mime:
        return True

    if FILTER_MODE == "blacklist":
        for f in FILE_FILTERING:
            if type(f) == str:
                if mime == f:
                    return False
            else:
                if f.match(mime):
                    return False
        return True
    else:
        for f in FILE_FILTERING:
            if type(f) == str:
                if mime == f:
                    return True
            else:
                if f.match(mime):
                    return True
        return False


@Analyzer.ID("binwalk")
def analyze(*, location: ScanLocation):
    """
    Binwalk integration
    """
    if not can_process_location(location):
        return

    for module in binwalk.scan(str(location.location), signature=True, quiet=True):
        for result in module.results:
            yield Detection(
                detection_type="Binwalk",
                message = f"{result.module}: {result.description}",
                signature = f"binwalk#{result.offset}/{md5(result.description)}#{str(location)}",
                location=location.location,
                extra = {
                    "offset": result.offset,
                    "module": result.module
                },
                tags = {"binwalk", f"binwalk_{result.module.lower()}"}
            )
