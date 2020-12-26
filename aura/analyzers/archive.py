import os
import tempfile
import tarfile
import zipfile
from pathlib import Path
from typing import Generator, Union

from .detections import Detection
from ..uri_handlers.base import ScanLocation
from .. import config
from .. import utils
from ..type_definitions import AnalyzerReturnType


SUPPORTED_MIME = (
    "application/x-gzip",
    "application/gzip",
    "application/x-bzip2",
    "application/zip",
)

logger = config.get_logger(__name__)



class ArchiveAnomaly(Detection):
    @classmethod
    def from_generic_exception(cls, location: ScanLocation, exc: Exception):
        return cls(
            detection_type=cls.__name__,
            location = location.location,
            message="Could not open the archive for analysis",
            signature=f"archive_anomaly#read_error#{location.location}",
            score=config.get_score_or_default("corrupted-archive", 10),
            extra={
                "reason": "archive_read_error",
                "exc_message": exc.args[0],
                "exc_type": exc.__class__.__name__,
                "mime": location.metadata["mime"]
            },
        )


def is_suspicious(pth, location):
    norm = utils.normalize_path(pth)

    if pth.startswith("/"):
        return Detection(
            message = "Archive contains an absolute path item",
            detection_type="SuspiciousArchiveEntry",
            location=utils.normalize_path(location),
            signature=f"suspicious_archive_entry#absolute_path#{norm}#{location}",
            extra={"entry_type": "absolute_path", "entry_path": norm},
            score=config.get_score_or_default("suspicious-archive-entry-absolute-path", 50),
        )

    elif any(x == ".." for x in Path(pth).parts):
        return Detection(
            message = "Archive contains an item with parent reference",
            detection_type="SuspiciousArchiveEntry",
            location=utils.normalize_path(location),
            signature=f"suspicious_archive_entry#parent_reference#{norm}#{location}",
            extra={"entry_type": "parent_reference", "entry_path": norm},
            score=config.get_score_or_default("suspicious-archive-entry-parent-reference", 50),
        )

    return None


def filter_zip(
    arch: zipfile.ZipFile, path, max_size=None
) -> Generator[Union[zipfile.ZipInfo, Detection], None, None]:
    if max_size is None:
        max_size = config.get_maximum_archive_size()

    for x in arch.infolist():  # type: zipfile.ZipInfo
        pth = x.filename

        res = is_suspicious(x.filename, path)
        if res is not None:
            yield res
            continue
        elif max_size is not None and x.file_size > max_size:
            hit = ArchiveAnomaly(
                location=path,
                message="Archive contain a file that exceed the configured maximum size",
                signature=f"archive_anomaly#size#{path}#{pth}",
                extra={
                    "archive_path": pth,
                    "reason": "file_size_exceeded",
                    "size": x.file_size,
                    "limit": max_size
                },
            )
            yield hit
        else:
            yield x


def filter_tar(
    arch: tarfile.TarFile, path, max_size=None
) -> Generator[Union[tarfile.TarInfo, Detection], None, None]:
    if max_size is None:
        config.get_maximum_archive_size()

    for member in arch.getmembers():
        pth = member.name

        res = is_suspicious(pth, path)
        if res is not None:
            yield res
        elif member.isdir():
            yield member
        elif member.issym() or member.islnk():
            # https://en.wikipedia.org/wiki/Tar_(computing)#Tarbomb
            yield Detection(
                detection_type="ArchiveAnomaly",
                message="Archive contain a member that is a link.",
                signature=f"archive_anomaly#link#{path}#{pth}",
                score=config.get_score_or_default("archive-member-is-link", 100),
                extra = {
                    "archive_path": pth,
                    "reason": "member_is_link"
                }
            )
            continue
        elif member.isfile():
            if max_size is not None and member.size > max_size:
                hit = Detection(
                    detection_type="ArchiveAnomaly",
                    location=path,
                    message="Archive contain a file that exceed the configured maximum size",
                    score = config.get_score_or_default("archive-file-size-exceeded", 100),
                    signature=f"archive_anomaly#size#{path}#{pth}",
                    extra={
                        "archive_path": pth,
                        "reason": "file_size_exceeded",
                        "size": member.size,
                        "limit": max_size
                    },
                )
                yield hit
                continue
            else:
                yield member
        else:
            continue


def process_zipfile(path, tmp_dir) -> AnalyzerReturnType:
    with zipfile.ZipFile(file=path, mode="r") as fd:
        for x in filter_zip(arch=fd, path=path):
            if isinstance(x, zipfile.ZipInfo):
                fd.extract(member=x, path=tmp_dir)
            else:
                yield x


def process_tarfile(path, tmp_dir) -> AnalyzerReturnType:
    with tarfile.open(name=path, mode="r:*") as fd:
        for x in filter_tar(arch=fd, path=path):
            if isinstance(x, tarfile.TarInfo):
                fd.extract(member=x, path=tmp_dir, set_attrs=False)
            else:
                yield x


def extract(location: ScanLocation, destination) -> AnalyzerReturnType:
    if location.metadata["mime"] == "application/zip":
        yield from process_zipfile(path=location.location, tmp_dir=destination)
    else:
        yield from process_tarfile(path=location.location, tmp_dir=destination)


def archive_analyzer(*, location: ScanLocation) -> AnalyzerReturnType:
    """
    Archive analyzer that looks for suspicious entries and unpacks the archive for recursive analysis
    """
    if location.location.is_dir():
        return
    elif location.metadata.get("source") == "diff":
        return

    mime = location.metadata["mime"]
    if mime not in SUPPORTED_MIME:
        return

    tmp_dir = tempfile.mkdtemp(prefix="aura_pkg__sandbox", suffix=os.path.basename(location.location))
    logger.info("Extracting to: '{}' [{}]".format(tmp_dir, mime))

    yield location.create_child(
        parent=location,
        new_location=tmp_dir,
        cleanup=True,
    )

    try:
        yield from extract(location=location, destination=tmp_dir)
    except (tarfile.ReadError, zipfile.BadZipFile, EOFError) as exc:
        yield ArchiveAnomaly.from_generic_exception(location, exc)


def diff_archive(diff) -> AnalyzerReturnType:
    if diff.operation not in "RM":
        return
    elif not (diff.a_scan.location.is_file() and diff.b_scan.location.is_file()):
        return
    elif diff.a_scan.metadata["md5"] == diff.b_scan.metadata["md5"]:
        return

    a_hits = list(archive_analyzer(location=diff.a_scan))
    a_locations = [x for x in a_hits if type(x) == ScanLocation]
    a_hits = [x for x in a_hits if type(x) != ScanLocation]

    b_hits = list(archive_analyzer(location=diff.b_scan))
    b_locations = [x for x in b_hits if type(x) == ScanLocation]
    b_hits = [x for x in b_hits if type(x) != ScanLocation]

    # Yield all anomaly detections
    yield from a_hits
    yield from b_hits

    # Check if we should recurse diff into archives
    if len(a_locations) == 0 and len(b_locations) == 0:
        return

    # Create a new scan location
    new_a_location = a_locations[0] if a_locations else diff.a_scan
    new_b_location = b_locations[0] if b_locations else diff.b_scan
    new_a_location.metadata["b_scan_location"] = new_b_location
    yield new_a_location
