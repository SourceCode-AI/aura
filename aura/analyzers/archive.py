import os
import tempfile
import tarfile
import zipfile
from pathlib import Path
from dataclasses import dataclass
from typing import Generator

import magic

from .rules import Rule
from ..uri_handlers import base
from .. import config


SUPPORTED_MIME = (
    'application/x-gzip',
    # FIXME: 'application/gzip',
    'application/x-bzip2',
    'application/zip',
)

logger = config.get_logger(__name__)


@dataclass
class SuspiciousArchiveEntry(Rule):
    __hash__ = Rule.__hash__


@dataclass
class ArchiveAnomaly(Rule):
    __hash__ = Rule.__hash__


def is_suspicious(pth, location):
    if pth.startswith('/'):
        return SuspiciousArchiveEntry(
            location = os.fspath(location),
            signature=f"suspicious_archive_entry#absolute_path#{os.fspath(pth)}#{location}",
            extra = {
                'entry_type': 'absolute_path',
                'entry_path': os.fspath(pth)
            },
            score = 50
        )

    elif any(x == '..' for x in Path(pth).parts):
        return SuspiciousArchiveEntry(
            location=os.fspath(location),
            signature=f"suspicious_archive_entry#parent_reference#{os.fspath(pth)}#{location}",
            extra ={
                'entry_type': 'parent_reference',
                'entry_path': os.fspath(pth)
            },
            score=50
        )

    return None


def list_zipfile(path):
    dirs = set()
    content = []

    with zipfile.ZipFile(path, 'r') as fd:
        for x in fd.infolist():
            item = {'path': x.filename}
            if x.is_dir():
                if x.filename in dirs:
                    continue

                item['type'] = 'd'
                dirs.add(x.filename)
            else:
                f_pth = Path(x.filename)
                item['type'] = 'f'
                item['size'] = x.file_size
                item['name'] = f_pth.name

                for d in f_pth.parents:
                    d = os.fspath(d)
                    if d not in dirs:
                        content.append({'path': d, 'type': 'd'})
                        dirs.add(d)

            if item['name'] not in dirs:
                content.append(item)

    return content


def filter_zip(arch:zipfile.ZipFile, path, max_size=None) -> Generator[zipfile.ZipInfo, None, None]:
    for x in arch.infolist():  # type: zipfile.ZipInfo
        pth = x.filename

        res = is_suspicious(x.filename, path)
        if res is not None:
            yield res
            continue
        elif max_size is not None and x.file_size > max_size:
            hit = ArchiveAnomaly(
                location=path,
                message='Archive contain a file that exceed the configured maximum size',
                signature=f"archive_anomaly#size#{path}#{pth}",
                extra={
                    'archive_path': pth
                }
            )
            yield hit
        else:
            yield x


def filter_tar(arch:tarfile.TarFile, path, max_size=None) -> Generator[tarfile.TarInfo, None, None]:
    for member in arch.getmembers():
        pth = member.name

        res = is_suspicious(pth, path)
        if res is not None:
            yield res
        elif member.isdir():
            yield member
        elif member.isfile():
            if max_size is not None and member.size > max_size:
                hit = ArchiveAnomaly(
                    location=path,
                    message='Archive contain a file that exceed the configured maximum size',
                    signature=f"archive_anomaly#size#{path}#{pth}",
                    extra={
                        'archive_path': pth
                    }
                )
                yield hit
                continue
            else:
                yield member
        else:
            continue


def archive_analyzer(pth:Path, metadata, **kwargs):
    if pth.is_dir():
        return

    if 'mime' in metadata:
        mime = metadata['mime']
    else:
        mime = magic.from_file(os.fspath(pth), mime=True)

    if mime not in SUPPORTED_MIME:
        return


    max_size = int(config.CFG['aura']['rlimit-fsize'])
    tmp_dir = tempfile.mkdtemp(prefix='aura_pkg__sandbox', suffix=os.path.basename(pth))
    logger.info("Extracting to: '{}' [{}]".format(tmp_dir, mime))

    location = base.ScanLocation(
        location = tmp_dir,
        cleanup=True,
        strip_path=tmp_dir,
        parent=pth,
        metadata = {
            'depth': metadata.get('depth', 0) + 1
        },
    )

    yield location

    if mime == 'application/zip':
        members = []

        with zipfile.ZipFile(file=pth, mode='r') as fd:
            for x in filter_zip(arch=fd, path=pth, max_size=max_size):
                if isinstance(x, zipfile.ZipInfo):
                    members.append(x)
                else:
                    yield x

            fd.extractall(path=tmp_dir, members=members)

    elif mime in SUPPORTED_MIME:
        members = []

        with tarfile.TarFile(name=pth, mode='r') as fd:
            for x in filter_tar(arch=fd, path=pth, max_size=max_size):
                if isinstance(x, tarfile.TarInfo):
                    members.append(x)
                else:
                    yield x

            fd.extractall(path=tmp_dir, members=members)
    else:
        return
