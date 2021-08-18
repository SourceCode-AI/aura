from importlib import metadata

from ..utils import Analyzer
from ..uri_handlers.base import ScanLocation
from ..type_definitions import AnalyzerReturnType
from .. import sbom


@Analyzer.ID("python_dists")
def analyze(*, location: ScanLocation) -> AnalyzerReturnType:
    if location.location.name != "METADATA":
        return
    elif not (pth:=location.location.parent).name.endswith(".dist-info"):
        return

    dist = metadata.PathDistribution(pth)

    if sbom.is_enabled():
        component = sbom.dist_to_component(dist)
        yield from sbom.yield_sbom_component(
            component=component,
            location=location,
            tags={"sbom:distribution"}
        )

