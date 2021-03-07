from .. import package
from ..uri_handlers.base import ScanLocation
from .detections import Detection
from ..utils import Analyzer
from ..type_definitions import AnalyzerReturnType


@Analyzer.ID("package_enrichment")
def analyze(*, location: ScanLocation) -> AnalyzerReturnType:
    if not (pkg_name:=location.metadata.get("package_name")):
        return

    pkg = package.PypiPackage.from_pypi(pkg_name)
    pkg_score = pkg.score

    extra = {
        "source_url": pkg.source_url,
        "homepage_url": pkg.homepage_url,
        "documentation_url": pkg.documentation_url,
        "latest_release": pkg.get_latest_release(),
        "score": pkg_score.get_score_matrix(),
        "reverse_dependencies": package.get_reverse_dependencies(pkg_name=pkg_name)
    }

    yield Detection(
        detection_type="PackageInformation",
        message="Package information",
        informational=True,
        extra=extra,
        signature=f"package_enrichment#{pkg_name}",
        tags={"package_info"}
    )
