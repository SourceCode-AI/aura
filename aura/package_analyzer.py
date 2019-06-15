"""
This module contains a package analysis functionality
It will recursively traverse input files and run the configured analyzers on them
Produced hits from analyzers are collected for later processing
"""

import os
import re
import shutil
import queue
import dataclasses
import multiprocessing

from pathlib import Path

import magic

from . import utils
from . import config
from . import plugins
from .uri_handlers import base
from .analyzers import rules


logger = config.get_logger(__name__)
TEST_REGEX = re.compile(r'^test(_.+|s)?$')


@dataclasses.dataclass
class ArchiveAnomaly(rules.Rule):
    __hash__ = rules.Rule.__hash__


class Analyzer(object):
    fork = config.CFG.getboolean('aura', 'async', fallback=True)

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

        files_queue.put({'path': location})

        try:
            while files_queue.qsize() or sum([not x.ready() for x in results]):
                try:
                    item = files_queue.get(False, 1)
                    item_path = Path(item['path'])
                    if item_path.is_dir():
                        for f in utils.walk(item_path):
                            item['path'] = f
                            files_queue.put(item)
                        continue

                    kwargs = {
                        'queue': files_queue,
                        'hits': hits,
                        'cleanup': cleanup,
                        'strip_path': strip_path,
                        'parent': parent,
                        'metadata': metadata
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
                if isinstance(x, Path):
                    x = os.fspath(x)
                if os.path.exists(x):
                    shutil.rmtree(x)

    @classmethod
    def _worker(cls,
                 path: Path,
                 queue:multiprocessing.Queue,
                 hits:multiprocessing.Array,
                 cleanup: multiprocessing.Array,
                 strip_path=None,
                 parent=None,
                 metadata=None):
        try:
            if metadata is None:
                metadata = {}

            if not isinstance(metadata.get('flags'), set):
                metadata['flags'] = set()

            if metadata.get('depth') is None:
                metadata['depth'] = 0  # TODO: add depth support for archive unpacker

            if 'path' not in metadata:
                metadata['path'] = path

            m = magic.from_file(os.fspath(path), mime=True)

            for x in path.parts:  # TODO: move this somewhere else
                if TEST_REGEX.match(x):
                    metadata['flags'].add('test_suite')
                    break

            logger.debug(f"Analyzing file '{path}' {m}")
            # TODO: let analyzer specify mime_types
            #    return

            analyzers = plugins.get_analyzer_group(metadata.get('analyzers', []))

            for x in analyzers(path=path, strip_path=strip_path, parent=parent, mime=m, metadata=metadata):
                if isinstance(x, base.ScanLocation):
                    scan_data = {'path': x.location}

                    for attr in ('strip_path', 'parent'):
                        if attr in x.metadata:
                            scan_data[attr] = x.metadata.pop(attr)

                    scan_data['metadata'] = x.metadata

                    if x.cleanup:
                        cleanup.put(x.location)

                    queue.put(scan_data)
                else:
                    x.tags |= metadata['flags']  #  TODO: remove once moved somewhere else
                    hits.put(x)
        finally:
            pass
