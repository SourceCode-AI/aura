import os
from pathlib import Path
from dataclasses import dataclass
from xml.etree.ElementTree import ParseError

from defusedxml import cElementTree

from defusedxml import (
    DTDForbidden,
    EntitiesForbidden,
    ExternalReferenceForbidden,
    NotSupportedError
)

from .rules import Rule
from ..utils import Analyzer
from ..config import get_score_or_default


ALLOWED_MIMES = (
    'text/html',
    'text/xml',
    # The XML file might not be big/structure enough to be identified by mime
    'text/plain'
)


@dataclass
class MalformedXML(Rule):
    message = "Malformed or malicious XML"
    __hash__ = Rule.__hash__


def scan(pth: str, **mode):
    try:
        cElementTree.parse(pth, **mode)
    except EntitiesForbidden:
        hit = MalformedXML(
            score = get_score_or_default("malformed-xml-entities", 100),
            extra = {
                "type": "entities"
            },
            signature = f"malformed_xml#entities#{pth}",
            tags = {"malformed_xml", "xml_entities"}
        )
        yield hit
    except DTDForbidden:
        hit = MalformedXML(
            score = get_score_or_default("malformed-xml-dtd", 20),
            extra = {
                "type": "dtd"
            },
            signature = f"malformed_xml#dtd#{pth}",
            tags = {"malformed_xml", "xml_dtd"}
        )
        yield hit
    except ExternalReferenceForbidden:
        hit = MalformedXML(
            score = get_score_or_default("malformed-xml-external-reference", 100),
            extra = {
                "type": "external_reference"
            },
            signature = f"malformed_xml#external_reference#{pth}",
            tags = {"malformed_xml", "xml_external_reference"}
        )
        yield hit
    except NotSupportedError:
        pass
    except ParseError:
        pass
    except Exception:
        pass


@Analyzer.ID("xml")
def analyze(pth: Path, **kwargs):
    """
    Detect malformed or potentially malicious XML files
    """
    pth = os.fspath(pth)
    mime = kwargs.get('mime')
    if pth.endswith('.xml'):
        pass
    elif mime not in ALLOWED_MIMES:
        return

    # Parsing will stop at the first error
    # We want to catch also combinations of problems so enumerate each option
    yield from scan(pth, forbid_dtd=True, forbid_entities=False, forbid_external=False)
    yield from scan(pth, forbid_dtd=False, forbid_entities=True, forbid_external=False)
    yield from scan(pth, forbid_dtd=False, forbid_entities=False, forbid_external=True)

