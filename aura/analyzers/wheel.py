import os
import csv
import base64
import hashlib
from pathlib import Path
from dataclasses import dataclass

from . import rules
from ..utils import Analyzer


@dataclass
class Wheel(rules.Rule):
    __hash__ = rules.Rule.__hash__


def get_checksum(alg: str, path: Path):
    h = hashlib.new(alg)
    with path.open("rb") as fd:
        h.update(fd.read())

    return base64.urlsafe_b64encode(h.digest()).decode("ascii").rstrip("=")


@Analyzer.ID("wheel")
def analyze_wheel(pth: Path, **kwargs):
    """Find anomalies in the Wheel packages that could be caused by manipulation or using a non-standard tools"""
    parts = pth.parts

    if len(parts) < 3 or pth.parts[-1] != "WHEEL":
        return
    elif not parts[-2].endswith(".dist-info"):
        return

    wheel_root = pth.parents[1].absolute()
    dist_info = pth.parents[0]

    required_files = ("WHEEL", "METADATA", "RECORD")
    for x in required_files:
        if not (dist_info / x).is_file():
            continue

    record_entries = set()

    with (dist_info / "RECORD").open(mode="r", newline=os.linesep) as rfd:
        reader = csv.reader(rfd, delimiter=",", quotechar='"')
        for record in reader:
            full_pth = wheel_root.joinpath(record[0])
            record_entries.add(full_pth)
            if full_pth.samefile(dist_info / "RECORD"):
                continue

            try:
                alg, checksum = record[1].split("=")
            except ValueError:  # not enough values to unpack
                continue

            target_checksum = get_checksum(alg, full_pth)
            if target_checksum != checksum:
                hit = Wheel(
                    score=10,
                    message="Wheel anomaly detected, invalid record checksum",
                    tags={"anomaly", "wheel"},
                    signature=f"wheel#record_checksum#{target_checksum}#{full_pth}",
                )
                yield hit

            # print(record)

    for x in wheel_root.glob("*/setup.py"):
        hit_path = os.fspath(wheel_root / x)
        hit = Wheel(
            score=100,
            message="Found setup.py in a wheel archive",
            tags={"wheel", "anomaly", "setup.py"},
            signature=f"wheel#setup.py#{hit_path}",
        )
        yield hit

    for x in wheel_root.glob("**/*"):
        # Ignore files under the *.dist-info directory
        if dist_info in x.parents or x.is_dir():
            continue

        if x not in record_entries:
            hit = Wheel(
                score=100,
                message="Wheel contain a file not listed in the RECORDs",
                tags={"wheel", "anomaly", "missing_record_file"},
                signature=f"wheel#missing_record_file#{x}",
            )
            yield hit
