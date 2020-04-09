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
from collections import defaultdict

import magic

from . import utils
from . import config
from . import plugins
from . import worker_executor
from .uri_handlers import base
from .analyzers import rules
from .analyzers.find_imports import TopologySort


logger = config.get_logger(__name__)
TEST_REGEX = re.compile(r"^test(_.+|s)?$")


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

        if metadata.get("fork") is True:
            executor = worker_executor.MultiprocessingExecutor()
        else:
            executor = worker_executor.LocalExecutor()

        files_queue = executor.manager.Queue()
        hits = executor.manager.Queue()
        cleanup = executor.manager.Queue()
        results = []

        files_queue.put(base.ScanLocation(location=location))

        try:
            while files_queue.qsize() or sum([not x.ready() for x in results]):
                try:

                    item = files_queue.get(False, 1)

                    if isinstance(item, worker_executor.Wait):
                        executor.wait()
                        continue

                    item_path = Path(item.location)

                    if item_path.is_dir():
                        collected = self.scan_directory(item=item, item_path=item_path)

                        for x in collected:
                            files_queue.put(x)

                        files_queue.put(worker_executor.Wait())
                        executor.wait()
                        continue

                    kwargs = {
                        "location": item,
                        "queue": files_queue,
                        "hits": hits,
                        "cleanup": cleanup,
                        "metadata": metadata,
                    }

                    if self.fork or metadata.get("fork", False):
                        results.append(
                            executor.apply_async(func=self._worker, kwds=kwargs)
                        )
                    else:
                        self._worker(**kwargs)
                except queue.Empty:
                    executor.wait()
                    continue
                except Exception:
                    # TODO: move error logging to worker
                    # extra = str({'metadata': metadata, 'item': item, 'parent': parent})
                    # logger.exception(f"An error occurred while processing file '{item}'; extra: " + extra)
                    raise

            executor.close()
            executor.join()

            # Re-raise the exceptions if any occurred during the processing
            #for x in results:
            for x in executor.jobs:
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
    def _worker(
        cls,
        location: base.ScanLocation,
        queue: multiprocessing.Queue,
        hits: multiprocessing.Array,
        cleanup: multiprocessing.Array,
        metadata=None,
    ):
        try:
            if metadata is None:
                metadata = {}

            path = location.location

            if not isinstance(metadata.get("flags"), set):
                metadata["flags"] = set()

            if metadata.get("depth") is None:
                metadata["depth"] = 0  #  TODO: add depth support for archive unpacker

            if "parent" not in metadata:
                metadata["parent"] = path

            metadata["path"] = path
            metadata["normalized_path"] = location.strip(location.location)

            m = magic.from_file(os.fspath(path), mime=True)

            for x in path.parts:  # TODO: move this somewhere else
                if TEST_REGEX.match(x):
                    metadata["flags"].add("test-code")
                    break

            logger.debug(f"Analyzing file '{path}' {m}")
            # TODO: let analyzer specify mime_types
            #    return

            analyzers = plugins.get_analyzer_group(metadata.get("analyzers", []))

            for x in analyzers(path=path, mime=m, metadata=metadata):

                if isinstance(x, base.ScanLocation):
                    if x.cleanup:
                        cleanup.put(x.location)

                    queue.put(x)
                else:
                    if x.location:
                        x.location = location.strip(x.location)
                    x.tags |= metadata[
                        "flags"
                    ]  #  TODO: remove once moved somewhere else
                    if x._metadata is None:
                        x._metadata = metadata

                    hits.put(x)
        finally:
            pass

    def scan_directory(self, item, item_path):
        logger.info(f"Collecting files in a directory '{item_path}")
        topo = TopologySort()
        collected = []

        for f in utils.walk(item_path):
            new_item = item.create_child(f)
            collected.append(new_item)
            topo.add_node(Path(new_item.location).absolute())

        logger.debug("Computing import graph")

        for x in collected:
            if not x.metadata.get('py_imports'):
                continue

            node = Path(x.location).absolute()
            topo.add_edge(node, x.metadata['py_imports']['dependencies'])

        topology = topo.sort()

        collected.sort(
            key=lambda x: topology.index(x.location) if x.location in topology else 0
        )
        logger.debug("Topoplogy sorting finished")

        return collected
