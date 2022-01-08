import base64
import hashlib
from importlib import metadata
from typing import cast, Union
from pathlib import Path

from .detections import Detection
from ..utils import Analyzer
from ..uri_handlers.base import ScanLocation
from ..type_definitions import AnalyzerReturnType
from ..config import get_score_or_default
from .. import sbom


def get_checksum(alg: str, path: Union[metadata.PackagePath, Path]) -> str:
    h = hashlib.new(alg)
    path = cast(Path, path)
    with path.open("rb") as fd:
        h.update(fd.read())

    return base64.urlsafe_b64encode(h.digest()).decode("ascii").rstrip("=")


@Analyzer.ID("python_dists")
def analyze(*, location: ScanLocation) -> AnalyzerReturnType:
    """
    Analyze integrity of python distributions and generate their SBOM
    """
    dist_info = location.location.parent

    if location.location.name != "METADATA":
        return
    elif not dist_info.name.endswith(".dist-info"):
        return

    if not (location.location.parent / "RECORD").exists():
        yield Detection(
            detection_type="PythonDistribution",
            location=location.location,
            score=get_score_or_default("dist-records-missing", 100),
            message = f"Python distribution anomaly, RECORDs file is missing",
            tags={"anomaly:dist:missing_record"},
            signature=f"dist#missing_records#{location.location}"
        )
        return

    dist = metadata.PathDistribution(dist_info)

    if sbom.is_enabled():
        component = sbom.dist_to_component(dist)
        yield from sbom.yield_sbom_component(
            component=component,
            location=location,
            tags={"sbom:distribution"}
        )

    existing_files = set()

    try:
        if not (dist_files:=dist.files):
            dist_files = []
        else:
            dist_files = list(dist_files)
    except UnicodeDecodeError:
        yield Detection(
            detection_type="PythonDistribution",
            location=location.location,
            message=f"Python distribution anomaly, unable to open the RECORDs file",
            signature=f"dist#record_file_error#{location}",
            tags={"anomaly:dist:record_file_error"}
        )
        return

    for dist_file in dist_files:
        fpath = cast(Path, dist_file.locate())
        existing_files.add(fpath)

        if not fpath.exists():
            yield Detection(
                detection_type="PythonDistribution",
                location=location.location,
                score=get_score_or_default("dist-missing-file", 100),
                message=f"Python distribution anomaly, file listed in RECORDs is missing",
                tags={"anomaly:dist:missing_file"},
                extra={
                    "record": str(dist_file),
                    "full_path": fpath,
                },
                signature=f"dist#missing_file#{location}"
            )
            continue

        if not dist_file.hash:
            continue

        target_checksum = get_checksum(dist_file.hash.mode, fpath)

        if target_checksum != dist_file.hash.value:
            yield Detection(
                detection_type="PythonDistribution",
                location=location.location,
                score=get_score_or_default("dist-invalid-record-checksum", 100),
                message=f"Python distribution anomaly, invalid checksum for a file record",
                extra={
                    "record_checksum": dist_file.hash.value,
                    "real_checksum": target_checksum,
                    "algorithm": dist_file.hash.mode,
                    "record": str(dist_file)
                },
                tags={"anomaly:dist:invalid_checksum"},
                signature=f"dist#record_checksum#{target_checksum}#{location}"
            )



    if location.metadata.get("check_full_content") or (location.location.parent / "WHEEL").exists():
        content_root = location.location.parent.parent

        for x in content_root.glob("**/*"):
            if x.is_dir():
                continue

            if x.name == "setup.py":
                yield Detection(
                    detection_type="PythonDistribution",
                    location=x,
                    score=get_score_or_default("dist-contain-setup-py", 100),
                    message=f"PythonDistribution",
                    tags={"anomaly:dist:setup.py"},
                    signature=f"dist#setup.py#{location.strip(x)}"
                )

            if x.absolute() not in existing_files:
                yield Detection(
                    detection_type="PythonDistribution",
                    location=x,
                    score=get_score_or_default("dist-file-not-listed-in-records", 10),
                    message=f"Python distribution contains a file not listed in the RECORDs file",
                    extra={
                        "record": location.strip(x),
                    },
                    tags={"anomaly:dist:unlisted_file"},
                    signature=f"dist#unlisted_file#{location.strip(x)}"
                )
