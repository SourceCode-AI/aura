import os
import io
import csv
import base64
import hashlib
from pathlib import Path
from typing import Generator

import chardet

from .detections import Detection
from ..utils import Analyzer, normalize_path
from ..uri_handlers.base import ScanLocation
from ..config import get_score_or_default
from ..type_definitions import AnalyzerReturnType


def get_checksum(alg: str, path: Path) -> str:
    h = hashlib.new(alg)
    with path.open("rb") as fd:
        h.update(fd.read())

    return base64.urlsafe_b64encode(h.digest()).decode("ascii").rstrip("=")


@Analyzer.ID("wheel")
def analyze_wheel(*, location: ScanLocation) -> AnalyzerReturnType:
    """Find anomalies in the Wheel packages that could be caused by manipulation or using a non-standard tools"""
    parts = location.location.parts

    if len(parts) < 3 or location.location.name != "WHEEL":
        return
    elif not parts[-2].endswith(".dist-info"):
        return

    wheel_root = location.location.parents[1].absolute()
    dist_info = location.location.parents[0]

    required_files = ("WHEEL", "METADATA", "RECORD")
    for x in required_files:
        if not (dist_info / x).is_file():
            continue

    record_entries = set()
    record_path = dist_info / "RECORD"

    if not record_path.exists():
        yield Detection(
            detection_type="Wheel",
            location=location.location,
            score = get_score_or_default("wheel-records-missing", 100),
            message = f"Wheel anomaly, RECORD file is missing in dist-info",
            tags = {"anomaly", "wheel", "wheel_missing_records"},
            signature = f"wheel#missing_records#{location.strip(record_path)}"
        )
        return

    try:
        with record_path.open(mode="r", newline=os.linesep) as rfd:
            records_content = rfd.read()
    except UnicodeDecodeError:
        with record_path.open(mode="rb") as rfd:
            records_raw: bytes = rfd.read()
            try:
                records_encoding = chardet.detect(records_raw)["encoding"]
                records_content = records_raw.decode(records_encoding)
            except (TypeError, UnicodeDecodeError):
                yield Detection(
                    detection_type="Wheel",
                    location=location.location,
                    message="Unable to decode the wheel RECORDs file",
                    tags={"anomaly", "wheel", "unicode_decode_error"},
                    signature=f"wheel#record_decode_err#{location.strip(record_path)}"
                )
                return

    records_io = io.StringIO(records_content)
    reader = csv.reader(records_io, delimiter=",", quotechar='"')
    for record in reader:
        full_pth = wheel_root.joinpath(record[0])

        if not full_pth.exists():
            yield Detection(
                location=location.location,
                detection_type="Wheel",
                score=get_score_or_default("wheel-missing-file", 100),
                message = "Wheel anomaly detected, file listed in RECORDs but not present in wheel",
                tags = {"anomaly", "wheel", "wheel_missing_file"},
                extra = {
                    "record": record[0]
                },
                signature=f"wheel#missing_file#{record[0]}#{full_pth}"
            )
            continue

        record_entries.add(full_pth)
        if full_pth.samefile(record_path):
            continue

        try:
            alg, checksum = record[1].split("=")
        except ValueError:  # not enough values to unpack
            continue
        except IndexError:  # Record does not have the `=` sign
            yield Detection(
                detection_type="Wheel",
                location=location.location,
                message="Malformed record entry",
                extra = {
                    "record": record
                },
                tags = {"anomaly", "wheel"},
                signature = f"wheel#malformed_record#{full_pth}#{record}"
            )
            continue
        try:
            target_checksum = get_checksum(alg, full_pth)
        except ValueError as exc:
            yield Detection(
                detection_type="Wheel",
                location=location.location,
                score=get_score_or_default("wheel-invalid-record-checksum", 100),
                message=f"Wheel anomaly detected, {exc.args[0]}",
                tags={"anomaly", "wheel"},
                extra={
                    "exception_type": type(exc).__name__,
                    "exception_message": exc.args[0]
                },
                signature=f"wheel#exc#{type(exc).__name__}#{exc.args[0]}#{location.strip(full_pth)}"
            )
        else:
            if target_checksum != checksum:
                yield Detection(
                    detection_type="Wheel",
                    location=location.location,
                    score=get_score_or_default("wheel-invalid-record-checksum", 100),
                    message="Wheel anomaly detected, invalid record checksum",
                    tags={"anomaly", "wheel"},
                    extra={
                        "real_checksum": target_checksum,
                        "record_checksum": checksum,
                        "algorithm": alg
                    },
                    signature=f"wheel#record_checksum#{target_checksum}#{location.strip(full_pth)}",
                )

    for x in wheel_root.glob("*/setup.py"):
        hit_path = normalize_path(wheel_root / x)
        hit = Detection(
            detection_type="Wheel",
            location=location.location,
            score=get_score_or_default("wheel-contain-setup-py", 100),
            message="Found setup.py in a wheel archive",
            tags={"wheel", "anomaly", "setup.py"},
            signature=f"wheel#setup.py#{location.strip(hit_path)}",
        )
        yield hit

    for x in wheel_root.glob("**/*"):
        # Ignore files under the *.dist-info directory
        if dist_info in x.parents or x.is_dir():
            continue

        if x not in record_entries:
            hit = Detection(
                detection_type="Wheel",
                location=location.location,
                score=get_score_or_default("wheel-file-not-listed-in-records", 10),
                message="Wheel contain a file not listed in the RECORDs",
                extra={
                    "record": location.strip(x)  #TODO: normalize path
                },
                tags={"wheel", "anomaly", "missing_record_file"},
                signature=f"wheel#missing_record_file#{location.strip(x)}",
            )
            yield hit
