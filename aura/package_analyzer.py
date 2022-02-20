"""
This module contains a package analysis functionality
It will recursively traverse input files and run the configured analyzers on them
Produced hits from analyzers are collected for later processing
"""

import typing as t
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
from .tracing import tracer


logger = config.get_logger(__name__)


class Analyzer:
    @classmethod
    def run(
            cls,
            initial_locations: Union[base.ScanLocation, Iterable[base.ScanLocation]]
    ) -> t.Generator[Detection, Optional[AnalysisQueueItem], None]:
        cleanup = []
        files_queue: t.Deque[AnalysisQueueItem] = deque()
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
                    item = worker_executor.Wait

                if item is worker_executor.Wait:
                    with tracer.start_as_current_span("executor-waiting"):
                        for f in executor:
                            locations, detections = f.result()
                            for loc in locations:  # type: base.ScanLocation
                                if loc.cleanup:
                                    cleanup.append(loc)

                                files_queue.append(loc)

                            for worker_detection in detections:  # type: Detection
                                comm = yield worker_detection
                                if comm:
                                    files_queue.append(comm)
                        continue

                item = t.cast(base.ScanLocation, item)
                should_continue: Union[bool, Detection] = item.should_continue()
                # Equals True if it's ok to process this item
                # Otherwise returns `Rule` indicating why processing of this location should be halted
                if isinstance(should_continue, Detection):
                    comm = yield should_continue
                    if comm:
                        files_queue.append(comm)
                    continue

                if isinstance(item, base.ScanLocation) and item.location.is_dir():
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

    @staticmethod
    def analyze(location: base.ScanLocation) -> Tuple[List[base.ScanLocation], List[Detection]]:
        locations = []
        detections = []
        with tracer.start_as_current_span("analyze-file") as span:
            span.set_attribute("location", location.str_location)
            logger.debug(f"Analyzing file '{location.str_location}' {location.metadata.get('mime')}")
            analyzers = plugins.get_analyzer_group(location.metadata.get("analyzers", []))

            for x in analyzers(location=location):
                if isinstance(x, base.ScanLocation):
                    locations.append(x)
                else:
                    x.scan_location = location
                    detections.append(x)

            with tracer.start_as_current_span("post-analysis"):
                location.post_analysis(detections)

            return (locations, detections)

    @staticmethod
    def run_input_hooks(location: base.ScanLocation) -> Iterable[Detection]:
        analyzers = plugins.load_entrypoint("aura.input_hooks")

        for hook_name, input_hook in analyzers["entrypoints"].items():
            with tracer.start_as_current_span("run-input-hook") as span:
                span.set_attribute("input-hook-name", hook_name)
                yield from input_hook(location=location)

    @staticmethod
    def scan_directory(item: base.ScanLocation):
        with tracer.start_as_current_span("scanning-directory") as span:
            span.set_attribute("location", item.str_location)
            logger.debug(f"Collecting files in a directory '{item.str_location}")
            topo = TopologySort()
            collected = []

            sort_imports = config.CFG["aura"].get("sort_by_imports")

            for f in utils.walk(item.location):
                new_item = item.create_child(
                    f,
                    parent=item.parent,
                    strip_path=item.strip_path
                )
                collected.append(new_item)
                if sort_imports:
                    topo.add_node(Path(new_item.location).absolute())

            if sort_imports:
                with tracer.start_as_current_span("import-graph-topology"):
                    logger.debug("Computing import graph")

                    for x in collected:
                        if not (py_imports:=x.py_imports):
                            continue

                        node = Path(x.location).absolute()
                        topo.add_edge(node, py_imports['dependencies'])

                    topology = topo.sort()

                    collected.sort(
                        key=lambda x: topology.index(x.location) if x.location in topology else 0
                    )
                    logger.debug("Topology sorting finished")

            return collected
