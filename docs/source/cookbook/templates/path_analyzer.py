from aura.analyzers.base import Analyzer
from aura.analyzers.detections import Detection
from aura.uri_handlers.base import ScanLocation
from aura.type_definitions import AnalyzerReturnType


# The analyzer receives a ScanLocation object that points to the input file for the analyzer and
# includes also metadata information about the file, environment and configuration
# Analyzer yields either a Detection instance which means a detection that analyzer would like to report back to framework and display to the user
# or a ScanLocation which points to a file/directory that the analyzer wants to add to the pipeline queue for scanning

@Analyzer.ID("analyzer_id")  # A unique analyzer identification
def my_analyzer(*, location: ScanLocation) -> AnalyzerReturnType:
    """
    This is a description for my analyzer, it will be automatically displayed in the `aura info` output
    """
    yield from []
