"""
This module contains a package analysis functionality
It will recursively traverse input files and run the configured analyzers on them
Produced hits from analyzers are collected for later processing
"""

import os
import shutil
from pathlib import Path
from typing import Union, Tuple, List, Iterable, Optional, Coroutine
from collections import deque

from . import utils
from . import config
from . import plugins
from . import worker_executor
from .uri_handlers import base
from .analyzers.detections import Detection
from .analyzers.find_imports import TopologySort
from .type_definitions import AnalysisQueueItem


logger = config.get_logger(__name__)


class Analyzer:
    @classmethod
    def run(
            cls,
            initial_locations: Union[base.ScanLocation, Iterable[base.ScanLocation]]
    ) -> Coroutine[Detection, Optional[AnalysisQueueItem], None]:
        cleanup = []
        files_queue = deque()
        executor = worker_executor.AuraExecutor(job_queue=files_queue)

        if isinstance(initial_locations, base.ScanLocation):
            initial_locations = (initial_locations,)

        for x in initial_locations:
            detections = tuple(cls.run_input_hooks(location=x))
            files_queue.append(x)
            for d in detections:
                comm = yield d
                if comm:
                    files_queue.append(comm)

        files_queue.append(worker_executor.Wait)

        try:
            while len(files_queue) or bool(executor):
                try:
                    item: AnalysisQueueItem = files_queue.popleft()
                except IndexError:  # Queue is empty
                    executor.wait()
                    item = False

                if item is False or item is worker_executor.Wait:
                    for f in executor:
                        locations, detections = f.result()
                        for loc in locations:  # type: base.ScanLocation
                            if loc.cleanup:
                                cleanup.append(loc)

                            files_queue.append(loc)

                        for x in detections:
                            comm = yield x
                            if comm:
                                files_queue.append(comm)
                    continue

                should_continue: Union[bool, Detection] = item.should_continue()
                # Equals True if it's ok to process this item
                # Otherwise returns `Rule` indicating why processing of this location should be halted
                if should_continue is not True:
                    comm = yield should_continue
                    if comm:
                        files_queue.append(comm)
                    continue

                if item.location.is_dir():
                    collected = cls.scan_directory(item=item)

                    for x in collected:
                        files_queue.append(x)

                    files_queue.append(worker_executor.Wait)
                    continue

                executor.submit(cls.analyze, location=item)
        finally:
            for x in cleanup:
                if isinstance(x, base.ScanLocation):
                    x.do_cleanup()
                    continue

                if type(x) != str:
                    x = os.fspath(x)
                if os.path.exists(x):
                    logger.debug(f"Cleaning up location: {x}")
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
    def run_input_hooks(location: base.ScanLocation) -> Iterable[Detection]:
        analyzers = plugins.load_entrypoint("aura.input_hooks")

        for input_hook in analyzers["entrypoints"].values():
            yield from input_hook(location=location)

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
