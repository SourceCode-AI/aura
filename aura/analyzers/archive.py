import os
import tempfile
import tarfile
import zipfile
import mimetypes
from pathlib import Path
from dataclasses import dataclass
from typing import Generator, Union

import magic

from .rules import Rule
from ..uri_handlers.base import ScanLocation
from .. import config
from .. import utils


SUPPORTED_MIME = (
    "application/x-gzip",
    "application/gzip",
    "application/x-bzip2",
    "application/zip",
)

logger = config.get_logger(__name__)


@dataclass
class SuspiciousArchiveEntry(Rule):
    __hash__ = Rule.__hash__


@dataclass
class ArchiveAnomaly(Rule):
    __hash__ = Rule.__hash__


def is_suspicious(pth, location):
    norm = utils.normalize_path(pth)

    if pth.startswith("/"):
        return SuspiciousArchiveEntry(
            location=utils.normalize_path(location),
            signature=f"suspicious_archive_entry#absolute_path#{norm}#{location}",
            extra={"entry_type": "absolute_path", "entry_path": norm},
            score=config.get_score_or_default("suspicious-archive-entry-absolute-path", 50),
        )

    elif any(x == ".." for x in Path(pth).parts):
        return SuspiciousArchiveEntry(
            location=utils.normalize_path(location),
            signature=f"suspicious_archive_entry#parent_reference#{norm}#{location}",
            extra={"entry_type": "parent_reference", "entry_path": norm},
            score=config.get_score_or_default("suspicious-archive-entry-parent-reference", 50),
        )

    return None


def filter_zip(
    arch: zipfile.ZipFile, path, max_size=None
) -> Generator[Union[zipfile.ZipInfo, ArchiveAnomaly], None, None]:
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
) -> Generator[Union[tarfile.TarInfo, ArchiveAnomaly], None, None]:
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
            # TODO: generate a hit
            # https://en.wikipedia.org/wiki/Tar_(computing)#Tarbomb
            continue
        elif member.isfile():
            if max_size is not None and member.size > max_size:
                hit = ArchiveAnomaly(
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


def process_zipfile(path, tmp_dir) -> Generator[ArchiveAnomaly, None, None]:
    with zipfile.ZipFile(file=path, mode="r") as fd:
        for x in filter_zip(arch=fd, path=path):
            if isinstance(x, zipfile.ZipInfo):
                fd.extract(member=x, path=tmp_dir)
            else:
                yield x


def process_tarfile(path, tmp_dir) -> Generator[ArchiveAnomaly, None, None]:
    with tarfile.open(name=path, mode="r:*") as fd:
        for x in filter_tar(arch=fd, path=path):
            if isinstance(x, tarfile.TarInfo):
                fd.extract(member=x, path=tmp_dir, set_attrs=False)
            else:
                yield x


def archive_analyzer(pth: Path, metadata, location: ScanLocation, **kwargs):
    """
    Archive analyzer that looks for suspicious entries and unpacks the archive for recursive analysis
    """
    if pth.is_dir():
        return

    if "mime" in metadata:
        mime = metadata["mime"]
    else:
        mime = magic.from_file(utils.normalize_path(pth), mime=True)

    if mime == "application/octet-stream":
        mime = mimetypes.guess_type(pth)[0]

    if mime not in SUPPORTED_MIME:
        return

    tmp_dir = tempfile.mkdtemp(prefix="aura_pkg__sandbox", suffix=os.path.basename(pth))
    logger.info("Extracting to: '{}' [{}]".format(tmp_dir, mime))

    yield location.create_child(
        new_location=tmp_dir,
        cleanup=True,
        strip_path=tmp_dir,
        parent=pth
    )

    try:
        if mime == "application/zip":
            yield from process_zipfile(path=pth, tmp_dir=tmp_dir)
        elif mime in SUPPORTED_MIME:
            yield from process_tarfile(path=pth, tmp_dir=tmp_dir)
        else:
            return
    except (tarfile.ReadError, zipfile.BadZipFile) as exc:
        yield ArchiveAnomaly(
            location=pth,
            message = "Could not open the archive for analysis",
            signature = f"archive_anomaly#read_error#{pth}",
            score = config.get_score_or_default("corrupted-archive", 10),
            extra = {
                "reason": "archive_read_error",
                "exc_message": exc.args[0],
                "exc_type": exc.__class__.__name__,
                "mime": mime
            },
        )
