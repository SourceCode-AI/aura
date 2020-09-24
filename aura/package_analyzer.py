"""
This module contains a package analysis functionality
It will recursively traverse input files and run the configured analyzers on them
Produced hits from analyzers are collected for later processing
"""

import os
import shutil
from pathlib import Path
from typing import Union, Tuple, List
from collections import deque

from . import utils
from . import config
from . import plugins
from . import worker_executor
from .uri_handlers import base
from .analyzers.detections import Detection
from .analyzers.find_imports import TopologySort


logger = config.get_logger(__name__)


class Analyzer(object):
    fork = config.CFG["aura"].get("async", True)

    def __init__(self, location):
        self.location = location

    def run(self):
        cleanup = []
        hits_items = []
        files_queue = deque()
        executor = worker_executor.AuraExecutor(job_queue=files_queue)
        files_queue.append(self.location)
        files_queue.append(worker_executor.Wait)

        try:
            while len(files_queue) or bool(executor):
                try:
                    item: Union[worker_executor.Wait, base.ScanLocation] = files_queue.popleft()
                except IndexError:  # Queue is empty
                    executor.wait()
                    item = False

                if item is False or item is worker_executor.Wait:
                    for f in executor:
                        locations, detections = f.result()
                        for loc in locations:  # type: base.ScanLocation
                            if loc.cleanup:
                                cleanup.append(loc.location)

                            files_queue.append(loc)

                        hits_items.extend(detections)
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
                        files_queue.append(x)

                    files_queue.append(worker_executor.Wait)
                    continue

                executor.submit(self.analyze, location=item)

            yield from hits_items
        finally:
            for x in cleanup:
                if type(x) != str:
                    x = os.fspath(x)
                if os.path.exists(x):
                    shutil.rmtree(x)

    @staticmethod
    def analyze(location: base.ScanLocation) -> Tuple[List[base.ScanLocation], List[Detection]]:
        locations = []
        detections = []

        logger.debug(f"Analyzing file '{location.str_location}' {location.metadata.get('mime')}")
        analyzers = plugins.get_analyzer_group(location.metadata.get("analyzers", []))

        for x in analyzers(location=location):
            if isinstance(x, base.ScanLocation):
                locations.append(x)
            else:
                x.scan_location = location
                detections.append(x)

        location.post_analysis(detections)

        return (locations, detections)

    @staticmethod
    def scan_directory(item: base.ScanLocation):
        logger.debug(f"Collecting files in a directory '{item.str_location}")
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
        logger.debug("Topology sorting finished")

        return collected
