import os
import sys
import shutil
import queue
import tarfile
import zipfile
import tempfile
import dataclasses
import multiprocessing

from pathlib import Path, PurePath
from typing import Generator, List

import magic

from . import utils
from . import config
from .analyzers import base, rules
from .analyzers import archive as archive_analyzer
from .analyzers.python.readonly import ReadOnlyAnalyzer


logger = config.get_logger(__name__)


@dataclasses.dataclass
class ArchiveAnomaly(rules.Rule):
    __hash__ = rules.Rule.__hash__


class Analyzer(object):
    fork = config.CFG.getboolean("aura", "async", fallback=True)

    def __init__(self, location):
        self.location = location

    def run(self, location=None, strip_path=None, parent=None, metadata=None):
        if metadata is None:
            metadata = {}

        if location is None:
            location = self.location

        m = multiprocessing.Manager()
        worker_pool = multiprocessing.Pool()
        files_queue = m.Queue()
        hits = m.Queue()
        cleanup = m.Queue()
        results = []

        if location.is_dir():
            for f in utils.walk(location):
                files_queue.put({'path': f})
        else:
            files_queue.put({'path': location})

        try:
            while files_queue.qsize() or sum([not x.ready() for x in results]):
                try:
                    item = files_queue.get(False, 1)
                    kwargs = {
                        'queue': files_queue,
                        'hits': hits,
                        'cleanup': cleanup,
                        'strip_path': strip_path,
                        'parent': parent,
                        'metadata': metadata,
                        'analyzers': None
                    }

                    kwargs.update(item)
                    if self.fork:
                        results.append(worker_pool.apply_async(func=self._worker, kwds=kwargs))
                    else:
                        self._worker(**kwargs)
                except queue.Empty:
                    continue
                except Exception:
                    # TODO: move error logging to worker
                    #extra = str({'metadata': metadata, 'item': item, 'parent': parent})
                    #logger.exception(f"An error occurred while processing file '{item}'; extra: " + extra)
                    raise

            worker_pool.close()
            worker_pool.join()

            # Re-raise the exceptions if any occurred during the processing
            for x in results:
                if not x.successful():
                    x.get()

            hits_items = []
            while hits.qsize():
                hits_items.append(hits.get())

            return hits_items
        finally:
            while cleanup.qsize():
                x = cleanup.get()
                if os.path.exists(x):
                    shutil.rmtree(x)

    @classmethod
    def _worker(cls,
                 path: Path,
                 queue:multiprocessing.Queue,
                 hits:multiprocessing.Array,
                 cleanup: multiprocessing.Array,
                 analyzers=None,
                 strip_path=None,
                 parent=None,
                 metadata=None):
        try:
            if metadata is None:
                metadata = {}

            m = magic.from_file(os.fspath(path), mime=True)

            logger.debug(f"Analyzing file '{path}' {m}")

            if m in Unpacker.supported_mime_types:  # It's a supported archive/package that can be extracted
                archive = Unpacker(path, mime=m)
                cleanup.put(archive.tmp_dir)
                if parent:  #  Construct normalized path for human view
                    parent = parent + '$' + path.name
                else:
                    parent = path.name

                for x in utils.walk(archive.location):
                    queue.put({
                        'path': x,
                        'strip_path': archive.location,
                        'parent': parent,
                        'metadata': metadata
                    })
                for x in archive.hits:
                    hits.put(x)
            # elif m in ('text/plain', 'application/octet-stream'):  # Skip generic file types
            # TODO: let analyzer specify mime_types
            #    return
            else:
                # Run analyzers on a file
                if analyzers is None:
                    analyzers = cls.__run_default_analyzers

                for x in analyzers(path=path, strip_path=strip_path, parent=parent, mime=m, metadata=metadata):
                    hits.put(x)
        finally:
            pass

    @classmethod
    def __run_default_analyzers(cls, path, **kwargs):
        for analyzer in base.get_analyzers().values():
            yield from analyzer(pth=path, **kwargs)

        a = ReadOnlyAnalyzer(path=path, **kwargs)
        yield from a(path)



class Unpacker(object):
    supported_mime_types = (
        'application/x-gzip',
        'application/x-bzip2',
        'application/zip'
    )

    def __init__(self, path: Path, mime=None):
        self.max_fsize = None
        if config.CFG['aura'].get('rlimit-fsize'):
            self.max_fsize = int(config.CFG['aura']['rlimit-fsize'])

        self.path = path
        self.hits = []

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

    @classmethod
    def get_content(cls, path: Path, mime=None):
        content = None

        if mime is None:
            mime = magic.from_file(os.fspath(path), mime=True)

        if mime == 'application/zip':
            content = cls.list_zipfile(path)
        elif mime in ('application/x-gzip', 'application/x-bzip2'):
            content = cls.list_tarfile(path)

        data = {
            'content': content,
            'filename': path.name
        }

        return data

    @classmethod
    def list_zipfile(cls, path):
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

                    for d in enum_dirs(f_pth.parent):
                        if d not in dirs:
                            content.append({'path': d, 'type': 'd'})
                            dirs.add(d)


                if item['name'] not in dirs:
                    content.append(item)

        return content

    @classmethod
    def list_tarfile(cls, path):
        tar = tarfile.open(path, 'r:*')
        content = []

        try:
            for x in tar.getmembers():
                item = {'path': x.name}

                if x.isdir():
                    item['type'] = 'd'
                else:
                    item['type'] = 'f'
                    item['size'] = x.size
                    item['name'] = Path(x.name).name

                content.append(item)
        finally:
            tar.close()

        return content

    @property
    def location(self):
        return Path(self.tmp_dir)

    def extract_tarfile(self, path):
        tar = tarfile.open(path, 'r:*')

        try:
            for x in archive_analyzer.analyze_tar_archive(tar, path):
                self.hits.append(x)

            logger.info("Extracting to: {}".format(self.tmp_dir))
            tar.extractall(path=self.tmp_dir, members=self._filter_tar(tar))
        finally:
            tar.close()

    def extract_zipfile(self, path):
        with zipfile.ZipFile(path) as fd:
            for x in archive_analyzer.analyze_zip_archive(fd, path):
                self.hits.append(x)

            logger.info("Extracting to: {}".format(self.tmp_dir))
            fd.extractall(path=self.tmp_dir, members=self._filter_zip(fd))

    def _filter_tar(self, members: List[tarfile.TarInfo]):
        for member in members:
            pth = member.name
            if pth.startswith('/') or '..' in PurePath(pth).parts:
                continue
            if member.isdir():
                yield member
            elif member.isfile():
                yield member
            elif self.max_fsize and member.size > self.max_fsize:
                hit = ArchiveAnomaly(
                    location = self.path,
                    message='Archive contain a file that exceed the configured maximum size',
                    signature=f"archive_anomaly#size#{self.path}#{pth}",
                    extra={
                        'archive_path': pth
                    }
                )
                self.hits.append(hit)
                continue
            else:
                continue

    def _filter_zip(self, arch: zipfile.ZipFile) -> Generator[zipfile.ZipInfo, None, None]:
        for x in arch.infolist():  # type: zipfile.ZipInfo
            pth = x.filename

            if pth.startswith('/') or '..' in PurePath(pth).parts:
                continue
            elif self.max_fsize and x.file_size > self.max_fsize:
                hit = ArchiveAnomaly(
                    location=self.path,
                    message='Archive contain a file that exceed the configured maximum size',
                    signature = f"archive_anomaly#size#{self.path}#{pth}",
                    extra={
                        'archive_path': pth
                    }
                )
                self.hits.append(hit)
                continue
            else:
                yield x


def enum_dirs(path: Path):
    dirparts = path.parts

    for i in range(len(dirparts)):
        pth = '/'.join(dirparts[:i + 1])
        yield pth


if __name__ == '__main__':
    location = Path(os.path.abspath(sys.argv[1]))

    sandbox = Analyzer(location)
    sandbox.run(strip_path=location)
