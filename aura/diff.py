# -*- coding: utf-á -*-
"""
Utilities for computing diffs
"""

import os
import re
import difflib
from typing import Union, Optional, List, Iterable
from dataclasses import dataclass

from .exceptions import UnsupportedDiffLocation
from .type_definitions import DiffType, DiffAnalyzerType

from . import config
from . import plugins
from .output.table import Table

from .analyzers.detections import Detection
from .package_analyzer import Analyzer
from .uri_handlers.base import ScanLocation, URIHandler, IdenticalName


@dataclass()
class Diff():
    operation: str
    a_scan: Optional[ScanLocation]
    b_scan: Optional[ScanLocation]
    a_ref: Optional[str] = None  # TODO: remove the ref pointers
    b_ref: Optional[str] = None
    diff: Optional[str] = None
    similarity: float = 0.0

    new_detections: Optional[List[Detection]] = None
    removed_detections: Optional[List[Detection]] = None

    def __post_init__(self):
        assert self.operation in ("A", "D", "M", "R")
        assert 0.0 <= self.similarity <= 1.0

    @classmethod
    def from_added(cls, loc: ScanLocation):
        data = {
            "operation": "A",
            "a_scan": None,
            "b_scan": loc,
        }
        return cls(**data)

    @classmethod
    def from_removed(cls, loc: ScanLocation):
        data = {
            "operation": "D",
            "a_scan": loc,
            "b_scan": None,
        }
        return cls(**data)

    @classmethod
    def from_modified(cls, a_loc: ScanLocation, b_loc: ScanLocation, similarity: Optional[float]=None, content_diff: Optional[str]=None):
        data = {
            "operation": "M",
            "a_scan": a_loc,
            "b_scan": b_loc
        }

        if content_diff is None and a_loc.metadata["md5"] != b_loc.metadata["md5"]:
            # FIXME: add handling for binary and empty files
            try:
                a_content = a_loc.location.read_text().splitlines(keepends=True)
                b_content = b_loc.location.read_text().splitlines(keepends=True)
                content_diff = difflib.unified_diff(a_content, b_content, fromfile=str(a_loc), tofile=str(b_loc))
            except UnicodeDecodeError:  # FIXME: thrown when file is a binary file
                pass
            else:
                if similarity is None:
                    similarity = difflib.SequenceMatcher(None, a_content, b_content).ratio()

                # TODO: Use OS line ending instead of hardcoded unix '\n'
                data["diff"] = "".join(content_diff)
        else:
            data["diff"] = content_diff

        data["similarity"] = similarity or 0.0
        return cls(**data)

    def add_detections(self, a_detections: List[Detection], b_detections: List[Detection]):
        duplicates = set(x.diff_hash for x in a_detections) & set(x.diff_hash for x in b_detections)
        self.new_detections = [x for x in b_detections if x.diff_hash not in duplicates]
        self.removed_detections = [x for x in a_detections if x.diff_hash not in duplicates]

    def as_dict(self) -> dict:
        d = {
            "operation": self.operation,
            "diff": self.diff,
            "similarity": self.similarity
        }

        if self.a_scan is not None:
            d.update({
                "a_ref": str(self.a_scan),
                "a_md5": self.a_scan.metadata.get("md5"),
                "a_mime": self.a_scan.metadata.get("mime"),
                "a_size": self.a_scan.size,
            })

        if self.b_scan is not None:
            d.update({
                "b_ref": str(self.b_scan),
                "b_md5": self.b_scan.metadata.get("md5"),
                "b_mime": self.b_scan.metadata.get("mime"),
                "b_size": self.b_scan.size,
            })

        if self.new_detections:
            d["new_detections"] = [x._asdict() for x in self.new_detections]

        if self.removed_detections:
            d["removed_detections"] = [x._asdict() for x in self.removed_detections]

        return d

    def pprint(self):
        from prettyprinter import pprint as pp
        pp(self)


class DiffAnalyzer():
    def __init__(self):
        self.hits = []
        self.diffs = []
        self.tables = []
        self.same_files = set()

    @classmethod
    def get_diff_hooks(cls) -> dict:
        data = plugins.load_entrypoint("aura.diff_hooks")
        return data["entrypoints"]

    def on_same_file(self, sender):  # TODO: transition to the new diff mechanism
        size = os.stat(sender).st_size
        self.same_files.add((sender, size))

    def diff_hook(self, diff: Diff):
        for hook in self.get_diff_hooks().values():
            for output in hook(diff=diff):
                if type(output) == ScanLocation:
                    self.compare(a_path=output, b_path=output.metadata["b_scan_location"])
                else:
                    self.hits.append(output)

        self.diffs.append(diff)

    def compare(
        self,
        a_path: Union[ScanLocation, URIHandler, List[ScanLocation]],
        b_path: Union[ScanLocation, URIHandler, List[ScanLocation]],
    ):
        # TODO: add a check if one is URIHandler and the other one is Path or ScanLocation
        if isinstance(a_path, URIHandler) and isinstance(b_path, URIHandler):
            try:
                for item in a_path.get_diff_paths(b_path):
                    if isinstance(item, Table):
                        self.tables.append(item)
                        continue

                    loc1, loc2 = item
                    self.compare(loc1, loc2)

            except UnsupportedDiffLocation:
                for item in b_path.get_diff_paths(a_path):
                    if isinstance(item, Table):
                        self.tables.append(item)
                        continue

                    loc2, loc1 = item
                    self.compare(loc1, loc2)

            return
        elif type(a_path) == list and type(b_path) == list:
            self._diff_files(a_path, b_path)
        elif a_path.location.is_file() and b_path.location.is_file():
            self._diff_files([a_path], [b_path])
        elif b_path.location.is_dir() and a_path.location.is_dir():
            self._diff_dirs(a_path, b_path)
        else:
            # TODO: be able to compare an archive and a directory
            raise ValueError(f"FS type mismatch: {str(a_path)}, {str(b_path)}")

    def analyze_changes(self):
        locations = {}

        for d in self.diffs:
            # Files are exactly same, skip analysis
            if d.a_scan is not None and d.b_scan is not None and d.a_scan.md5 == d.b_scan.md5:
                continue

            if d.a_scan:
                d.a_scan.metadata["source"] = "diff"
                locations[d.a_scan] = {}

            if d.b_scan:
                d.b_scan.metadata["source"] = "diff"
                locations[d.b_scan] = {}

        detections = tuple(Analyzer.run(locations.keys()))
        diff_refs = {}
        orphans = []

        loc_refs = {}

        for d in detections:
            loc = d.scan_location

            while loc:
                if loc in locations:
                    loc_refs.setdefault(loc, []).append(d)
                    diff_refs[d] = loc  # TODO: check if this is used and if not then remove
                    break

                loc = loc.parent
            else:
                orphans.append(d)

        for diff in self.diffs:
            a_detections = []
            b_detections = []
            if diff.a_scan:
                a_detections = loc_refs.get(diff.a_scan, [])
            if diff.b_scan:
                b_detections = loc_refs.get(diff.b_scan, [])

            diff.add_detections(a_detections, b_detections)

    def _diff_dirs(self, a_path: ScanLocation, b_path: ScanLocation):
        a_files = list(a_path.list_recursive())
        b_files = list(b_path.list_recursive())
        self._diff_files(a_files=a_files, b_files=b_files)

    def _diff_files(self, a_files: List[ScanLocation], b_files: List[ScanLocation]):
        closure = FileMatcher(left_files=a_files, right_files=b_files).get_closure()

        for a in closure["added"]:
            self.diff_hook(Diff.from_added(a))
        for r in closure["removed"]:
            self.diff_hook(Diff.from_removed(r))

        for (a, b, ratio) in closure["modified"]:
            self.diff_hook(Diff.from_modified(a_loc=a, b_loc=b, similarity=ratio))

    def pprint(self):
        from .output import text
        out = text.TextDiffOutput()
        out.output_diff(self.diffs)


class FileMatcher:
    def __init__(
            self,
            left_files: Iterable[ScanLocation],
            right_files: Iterable[ScanLocation],
            threshold: Optional[float]=None
    ):
        self.threshold = threshold or self.get_similarity_threshold()
        self.left = set(left_files)
        self.right = set(right_files)

    def find_file_modifications(self) -> list:
        modified = []
        right = set(self.right)

        for l in self.left:
            closest_ratio, closest_file = None, None

            for r in right:
                ratio = l.is_renamed_file(other=r)
                if type(ratio) == IdenticalName:
                    closest_ratio = ratio
                    closest_file = r
                    break
                elif l.is_archive and r.is_archive and ratio > 0:
                    closest_ratio = ratio
                    closest_file = r
                elif ratio < self.threshold:
                    continue
                elif closest_ratio is None:
                    closest_ratio = ratio
                    closest_file = r
                elif ratio > closest_ratio:
                    closest_ratio = ratio
                    closest_file = r

            if closest_file:
                modified.append((l, closest_file, closest_ratio))
                right.remove(closest_file)

        return modified

    def get_closure(self):
        modified = self.find_file_modifications()
        modified_locations = [x[0] for x in modified]
        modified_locations.extend(x[1] for x in modified)
        removed = [x for x in self.left if x not in modified_locations]
        added = [x for x in self.right if x not in modified_locations]

        return {"added": added, "modified": modified, "removed": removed}

    @classmethod
    def get_similarity_threshold(cls) -> float:
        return config.CFG["diff"].get("similarity_threshold", 0.60)
