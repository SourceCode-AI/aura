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

@Analyzer.ID("binwalk")
def analyze(*, location: ScanLocation):
    """
    Binwalk integration
    """
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
