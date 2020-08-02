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
from typing import Union
from contextlib import contextmanager

from . import utils
from . import config
from . import plugins
from . import worker_executor
from . import progressbar
from .uri_handlers import base
from .analyzers.detections import Detection
from .analyzers.find_imports import TopologySort


logger = config.get_logger(__name__)


class Analyzer(object):
    fork = config.CFG.getboolean("aura", "async", fallback=True)

    def __init__(self, location):
        self.location = location

    @contextmanager
    def run(self):

        if self.location.metadata.get("fork") is True:
            executor = worker_executor.MultiprocessingExecutor()
        else:
            executor = worker_executor.LocalExecutor()

        hits_items = []
        files_queue = executor.create_queue()
        hits = executor.create_queue()
        cleanup = executor.create_queue()
        progress = progressbar.QueueProgressBar(queue=files_queue, desc="Analyzing files")
        files_queue.put(self.location)

        try:
            while files_queue.qsize() or sum([not x.ready() for x in executor.jobs]):
                progress._update_queue()
                try:
                    item: Union[worker_executor.Wait, base.ScanLocation] = files_queue.get(False, 1)

                    if item is False or isinstance(item, worker_executor.Wait):
                        executor.wait()
                        continue

                    should_continue: Union[bool, Detection] = item.should_continue()
                    # Equals True if it's ok to process this item
                    # Otherwise returns `Rule` indicating why processing of this location should be halted
                    if should_continue is not True:
                        hits_items.append(should_continue)
                        continue

                    if item.location.is_dir():
                        collected = self.scan_directory(item=item)

                        for x in collected:
                            files_queue.put(x)

                        files_queue.put(worker_executor.Wait())
                        executor.wait()
                        continue

                    kwargs = {
                        "location": item,
                        "queue": files_queue,
                        "hits": hits,
                        "cleanup": cleanup
                    }
                    executor.apply_async(func=self._worker, kwds=kwargs)

                except queue.Empty:
                    executor.wait()
                    continue
                except Exception:
                    raise

            progress._update_queue()
            executor.close()
            executor.join()

            # Re-raise the exceptions if any occurred during the processing
            #for x in results:
            for x in executor.jobs:
                if not x.successful():
                    x.get()

            while hits.qsize():
                hits_items.append(hits.get())

            yield hits_items
        finally:
            progress.close()
            while cleanup.qsize():
                x = cleanup.get()
                if type(x) != str:
                    x = os.fspath(x)
                if os.path.exists(x):
                    shutil.rmtree(x)

    @classmethod
    def _worker(
        cls,
        location: base.ScanLocation,
        queue: queue.Queue,
        hits: multiprocessing.Array,
        cleanup: queue.Queue,
    ):
        try:
            logger.debug(f"Analyzing file '{location.str_location}' {location.metadata.get('mime')}")
            # TODO: let analyzer specify mime_types
            #    return

            analyzers = plugins.get_analyzer_group(location.metadata.get("analyzers", []))

            for x in analyzers(location=location):
                if isinstance(x, base.ScanLocation):
                    if x.cleanup:
                        cleanup.put(x.location)

                    queue.put(x)
                else:
                    if x.location:
                        x.location = location.strip(x.location)
                    x.tags |= location.metadata[
                        "flags"
                    ]  #  TODO: remove once moved somewhere else
                    if x._metadata is None:
                        x._metadata = location.metadata

                    hits.put(x)
        finally:
            pass

    def scan_directory(self, item: base.ScanLocation):
        logger.info(f"Collecting files in a directory '{item.str_location}")
        topo = TopologySort()
        collected = []

        for f in utils.walk(item.location):
            new_item = item.create_child(
                f,
                parent=item.parent,
                strip_path=item.strip_path
            )
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
