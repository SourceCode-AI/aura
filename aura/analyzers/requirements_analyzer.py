import os
import re
import codecs
import sys
import locale
from typing import List, Tuple, Text, Iterable

import chardet
from packaging.requirements import Requirement, InvalidRequirement

from .detections import Detection
from ..utils import Analyzer
from ..uri_handlers.base import ScanLocation
from ..config import get_score_or_default
from ..exceptions import NoSuchPackage
from .. import package
from .. import sbom


FILENAME = re.compile(r"^.*requirements.*\.txt$")
URL = re.compile("^(https?|ftp)://.*$", flags=re.I)
ENCODING_RE = re.compile(br'coding[:=]\s*([-\w.]+)')
BOMS: List[Tuple[bytes, Text]] = [
    (codecs.BOM_UTF8, 'utf-8'),
    (codecs.BOM_UTF16, 'utf-16'),
    (codecs.BOM_UTF16_BE, 'utf-16-be'),
    (codecs.BOM_UTF16_LE, 'utf-16-le'),
    (codecs.BOM_UTF32, 'utf-32'),
    (codecs.BOM_UTF32_BE, 'utf-32-be'),
    (codecs.BOM_UTF32_LE, 'utf-32-le'),
]


def auto_decode(data: bytes) -> str:
    """
    This function is copied from pip._internal.utils.encoding

    Check a bytes string for a BOM to correctly detect the encoding
    Fallback to locale.getpreferredencoding(False) like open() on Python3
    """
    for bom, encoding in BOMS:
        if data.startswith(bom):
            return data[len(bom):].decode(encoding)
    try:
        # Lets check the first two lines as in PEP263
        for line in data.split(b'\n')[:2]:
            if line[0:1] == b'#' and (encoding_match:=ENCODING_RE.search(line)):
                encoding = encoding_match.groups()[0].decode('ascii')
                return data.decode(encoding)

        return data.decode(
            locale.getpreferredencoding(False) or sys.getdefaultencoding(),
        )
    except UnicodeDecodeError:
        encoding = chardet.detect(data)["encoding"]
        return data.decode(encoding)


def check_unpinned(requirement: Requirement, location: ScanLocation) -> Iterable[Detection]:
    if len(requirement.specifier) == 0:
        yield Detection(
            detection_type="UnpinnedPackage",
            message=f"Package {requirement.name} is unpinned",
            signature=f"req_unpinned#{str(location)}#{requirement.name}",
            score=get_score_or_default("requirement-unpinned", 10),
            extra={
                "package": requirement.name
            },
            tags={"sbom:unpinned_package"},
            location=location.location
        )


def check_outdated(requirement: Requirement, location: ScanLocation) -> Iterable[Detection]:
    pypi = package.PypiPackage.from_cached(requirement.name)

    versions = tuple(requirement.specifier.filter(pypi.info["releases"].keys()))

    if versions:
        pypi.opts["version"] = versions[-1]

    latest = pypi.get_latest_release()
    spec_set = requirement.specifier

    if sbom.is_enabled():
        component = sbom.get_component(pypi)

        yield from sbom.yield_sbom_component(
            component=component,
            location=location,
            tags={"sbom:package_requirement"}
        )

    if latest not in spec_set:
        yield Detection(
            detection_type="OutdatedPackage",
            message=f"Package {requirement.name}{str(spec_set)} is outdated, newest version is {latest}",
            signature=f"req_outdated#{str(location)}#{requirement.name}#{str(spec_set)}#{latest}",
            score=get_score_or_default("requirement-outdated", 5),
            location=location.location,
            extra={
                "package": requirement.name,
                "specs": str(spec_set),
                "latest": latest
            },
            tags={"sbom:outdated_package"}
        )


@Analyzer.ID("requirements_file_analyzer")
def analyze_requirements_file(*, location: ScanLocation) -> Iterable[Detection]:
    """
    Analyzer the requirements.txt file and lookup for outdated packages
    """
    if not FILENAME.match(os.fspath(location.location)):
        return

    norm_pth = str(location)

    try:
        with location.location.open("rb") as fd:
            decoded = auto_decode(fd.read())
    except (UnicodeDecodeError, TypeError):
        yield Detection(
            detection_type="InvalidRequirement",
            message=f"Unable to decode the requirements file into unicode",
            signature = f"req_invalid#unicode_decode#{norm_pth}",
            extra = {
                "reason": "unicode_decode_error"
            },
            tags = {"sbom:invalid_requirement", "error:unicode_decode"},
            location=location.location
        )
        return

    for idx, req_line in enumerate(decoded.split("\n")):
        req_line = req_line.strip()

        if not req_line:
            continue
        elif req_line.startswith("#"):
            continue

        if "#" in req_line:
            req_line = req_line.split("#")[0].strip()

        if URL.match(req_line):
            yield Detection(
                detection_type="InvalidRequirement",
                message = f"Can't process requirement with a remote URL",
                signature = f"req_invalid#remote_url#{norm_pth}/{idx}",
                extra = {
                    "reason": "remote_url"
                },
                score = get_score_or_default("requirement-remote-url", 20),
                tags = {"sbom:invalid_requirement", "sbom:remote_url"},
                location = location.location,
                line_no=idx,
                line=req_line
            )
            continue

        try:
            req = Requirement(req_line)

            yield from check_unpinned(req, location)
            yield from check_outdated(req, location)
        except (ValueError, NoSuchPackage, InvalidRequirement) as exc:
            yield Detection(
                detection_type="InvalidRequirement",
                message = f"Could not parse the requirement for analysis",
                signature = f"req_invalid#{norm_pth}/{idx}",
                extra = {
                    "reason": "cant_parse",
                    "line": req_line.strip(),
                    "line_no": idx,
                    "exc_message": exc.args[0],
                    "exc_type": exc.__class__.__name__
                },
                score = get_score_or_default("requirement-invalid", 0),
                tags = {"sbom:invalid_requirement", "error:cant_parse"}
            )
