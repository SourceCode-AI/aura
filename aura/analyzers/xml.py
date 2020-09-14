from typing import Generator
from xml.etree.ElementTree import ParseError

from ..exceptions import PluginDisabled

try:
    from defusedxml import cElementTree
except ImportError:
    raise PluginDisabled(
        "defusedxml package is not installed"
    )

from defusedxml import (
    DTDForbidden,
    EntitiesForbidden,
    ExternalReferenceForbidden,
    NotSupportedError
)

from .detections import Detection
from ..utils import Analyzer
from ..uri_handlers.base import ScanLocation
from ..config import get_score_or_default


ALLOWED_MIMES = (
    'text/html',
    'text/xml',
    # The XML file might not be big/structure enough to be identified by mime
    'text/plain'
)


def scan(location: ScanLocation, **mode) -> Generator[Detection, None, None]:
    """
    Attempt to parse the XML using defused XML and the mode options to turn protections on/off
    When an exception is raised for supported XML problems a detection is yielded back to the analyzer
    """
    try:
        cElementTree.parse(location.str_location, **mode)
    except EntitiesForbidden:
        yield Detection(
            detection_type = "MalformedXML",
            message = "Malformed or malicious XML",
            score = get_score_or_default("malformed-xml-entities", 100),
            extra = {
                "type": "entities"
            },
            location=location.location,
            signature = f"malformed_xml#entities#{str(location)}",
            tags = {"malformed_xml", "xml_entities"}
        )
    except DTDForbidden:
        yield Detection(
            detection_type = "MalformedXML",
            message = "Malformed or malicious XML",
            score = get_score_or_default("malformed-xml-dtd", 20),
            extra = {
                "type": "dtd"
            },
            location=location.location,
            signature = f"malformed_xml#dtd#{str(location)}",
            tags = {"malformed_xml", "xml_dtd"}
        )
    except ExternalReferenceForbidden:
        yield Detection(
            detection_type = "MalformedXML",
            message = "Malformed or malicious XML",
            score = get_score_or_default("malformed-xml-external-reference", 100),
            extra = {
                "type": "external_reference"
            },
            location=location.location,
            signature = f"malformed_xml#external_reference#{str(location)}",
            tags = {"malformed_xml", "xml_external_reference"}
        )
    except NotSupportedError:
        pass
    except ParseError:
        pass
    except Exception:
        pass


@Analyzer.ID("xml")
def analyze(location: ScanLocation):
    """
    Detect malformed or potentially malicious XML files
    """
    if location.str_location.endswith(".xml"):
        pass
    elif location.metadata["mime"] not in ALLOWED_MIMES:
        return

    # Parsing will stop at the first error so we can't set `True` to all the options as it will shadow the problem
    # We want to catch also combinations of problems so enumerate each option
    yield from scan(location, forbid_dtd=True, forbid_entities=False, forbid_external=False)
    yield from scan(location, forbid_dtd=False, forbid_entities=True, forbid_external=False)
    yield from scan(location, forbid_dtd=False, forbid_entities=False, forbid_external=True)

