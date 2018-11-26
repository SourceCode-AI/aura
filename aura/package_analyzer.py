import os
import sys
import shutil
import logging
import tarfile
import zipfile
import tempfile

from pathlib import Path, PurePath
from typing import Generator

import magic
from blinker import signal

from . import utils
from .analyzers import run_file_analyzers
from .analyzers import archive as archive_analyzer


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


class Analyzer(object):
    def __init__(self, location, callback:signal=None):
        self.location = location
        self.callback = callback

    def run(self, location=None, strip_path=None, parent=None):
        if location is None:
            location = self.location

        if location.is_dir():
            for f in utils.walk(location):
                self._run_on_file(f, strip_path=strip_path, parent=parent)
        else:
            self._run_on_file(location, strip_path=strip_path, parent=parent)

    def _run_on_file(self, pth: Path, strip_path=None, parent=None):
        m = magic.from_file(os.fspath(pth), mime=True)
        if m in Unpacker.supported_mime_types:
            archive = Unpacker(pth, callback=self.callback, mime=m)
            if parent:
                parent = parent + '$' + pth.name
            else:
                parent = pth.name
            self.run(location=archive.location, strip_path=archive.location, parent=parent)
        elif m == 'text/plain':
            return
        else:
            for x in run_file_analyzers(pth, strip_path=strip_path, parent=parent, mime=m):
                if self.callback:
                    self.callback.send(x)


class Unpacker(object):
    supported_mime_types = (
        'application/x-gzip',
        'application/x-bzip2',
        'application/zip'
    )

    def __init__(self, path: Path, callback:signal=None, mime=None):
        self.path = path
        self.callback = callback
        self.tmp_dir = tempfile.mkdtemp(prefix='pkg_sandbox', suffix=os.path.basename(path))
        if mime is None:
            mime = magic.from_file(os.fspath(path), mime=True)

        try:
            if mime == 'application/zip':
                self.extract_zipfile(path)
            elif mime in ('application/x-gzip', 'application/x-bzip2'):
                self.extract_tarfile(path)
            else:
                raise ValueError("Unknown archive '{}' with type: '{}'".format(path, mime))
        except Exception:
            if os.path.exists(self.tmp_dir):
                shutil.rmtree(self.tmp_dir)
            raise

    @property
    def location(self):
        return Path(self.tmp_dir)

    def extract_tarfile(self, path):
        tar = tarfile.open(path, 'r:*')

        if self.callback:
            for x in archive_analyzer.analyze_tar_archive(tar, path):
                self.callback.send(x)

        logger.info("Extracting to: {}".format(self.tmp_dir))
        tar.extractall(path=self.tmp_dir, members=self._filter_tar(tar))
        tar.close()

    def extract_zipfile(self, path):
        with zipfile.ZipFile(path) as fd:

            if self.callback:
                for x in archive_analyzer.analyze_zip_archive(fd, path):
                    self.callback.send(x)

            logger.info("Extracting to: {}".format(self.tmp_dir))
            fd.extractall(path=self.tmp_dir, members=self._filter_zip(fd))

    def _filter_tar(self, members):
        for member in members:
            pth = member.name
            if pth.startswith('/') or '..' in PurePath(pth).parts:
                continue
            if member.isdir():
                yield member
            elif member.isfile():
                yield member
            else:
                continue

    def _filter_zip(self, arch: zipfile.ZipFile) -> Generator[zipfile.ZipInfo, None, None]:
        for x in arch.infolist():  # type: zipfile.ZipInfo
            pth = x.filename

            if pth.startswith('/') or '..' in PurePath(pth).parts:
                continue
            else:
                yield x

    def __del__(self):
        if Path(self.tmp_dir).exists():
            shutil.rmtree(self.tmp_dir)


if __name__ == '__main__':
    location = Path(os.path.abspath(sys.argv[1]))

    sandbox = Analyzer(location)
    sandbox.run(strip_path=location)