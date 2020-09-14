# -*- coding: utf-á -*-
"""
Utilities for computing diffs
"""

import os
import re
import tempfile
import shutil
import pprint
from typing import Union, Optional, List
from pathlib import Path
from collections import defaultdict
from dataclasses import dataclass

from .exceptions import UnsupportedDiffLocation, FeatureDisabled
from .type_definitions import DiffType, DiffAnalyzerType

try:
    import magic
    import tlsh
    from git import Repo, Diff as GitDiff, Blob
except ImportError as exc:
    raise FeatureDisabled("Feature is disabled because one or more python packages are not installed: `GitPython`, `python-tlsh`") from exc


from . import utils
from . import plugins
from .output.table import Table

from .analyzers.detections import Detection
from .package_analyzer import Analyzer
from .uri_handlers.base import ScanLocation, URIHandler


DIFF_EXCLUDE = re.compile(r"^Binary files .+ differ$")


@dataclass()
class Diff(DiffType):
    operation: str
    a_size: Optional[int]
    b_size: Optional[int]
    a_scan: ScanLocation
    b_scan: ScanLocation
    a_ref: Optional[str] = None
    b_ref: Optional[str] = None
    a_md5: Optional[str] = None
    b_md5: Optional[str] = None
    a_mime: Optional[str] = None
    b_mime: Optional[str] = None
    diff: str = ''
    similarity: float = 0.0

    new_detections: Optional[List[Detection]] = None
    removed_detections: Optional[List[Detection]] = None

    def __post_init__(self):
        assert self.operation in ("A", "D", "M", "R")
        # a_path, b_path = self.a_path, self.b_path
        #
        # if a_path and b_path:
        #     a_content = self.a_path.read_bytes()
        #     b_content = self.b_path.read_bytes()
        #     self.similarity = sim_hash.normalized_similarity(a_content, b_content)

    @property
    def a_path(self) -> Optional[Path]:
        if self.a_scan.location.is_file():
            return self.a_scan.location
        elif self.a_ref is None:
            return None
        else:
            return self.a_scan.location / self.a_ref

    @property
    def b_path(self) -> Optional[Path]:
        if self.b_scan.location.is_file():
            return self.b_scan.location
        elif self.b_ref is None:
            return None
        else:
            return self.b_scan.location / self.b_ref

    @classmethod
    def from_git_diff(cls, git_diff: GitDiff, a_path: ScanLocation, b_path: ScanLocation):
        if git_diff.a_path is None or git_diff.new_file:
            operation = "A"  #  Added
        elif git_diff.b_path is None or git_diff.deleted_file:
            operation = "D"  #  Deleted
        elif not git_diff.diff:
            operation = "R"  #  Renamed
        else:
            operation = "M"  # Modified

        data = {
            "operation": operation,
            # Relative paths to the repository
            "a_scan": a_path,
            "b_scan": b_path,
        }

        if git_diff.diff and operation in "MR":
            data["diff"] = git_diff.diff.decode().strip()
            if DIFF_EXCLUDE.match(data["diff"]):
                data.pop("diff")

        if git_diff.a_path is not None and operation != "A":
            if a_path.location.is_file():
                a_fs_path = a_path.location
            else:
                a_fs_path = a_path.location / git_diff.a_path

            data["a_ref"] = a_path.strip(git_diff.a_path)
            data["a_md5"] = utils.md5(a_fs_path)
            data["a_mime"] = magic.from_file(os.path.realpath(a_fs_path), mime=True)
            data["a_size"] = a_fs_path.stat().st_size
        else:
            data["a_size"] = 0

        if git_diff.b_path is not None and operation != "D":
            if b_path.location.is_file():
                b_fs_path = b_path.location
            else:
                b_fs_path = b_path.location / git_diff.b_path

            data["b_ref"] = b_path.strip(git_diff.b_path)
            data["b_md5"] = utils.md5(b_fs_path)
            data["b_mime"] = magic.from_file(os.path.realpath(b_fs_path), mime=True)
            data["b_size"] = b_fs_path.stat().st_size
        else:
            data["b_size"] = 0

        if data.get("a_md5") and data["a_md5"] == data.get("b_md5"):
            data["similarity"] = 1.0
        elif git_diff.a_blob and git_diff.b_blob:
            a_content = git_diff.a_blob.data_stream.read()
            b_content = git_diff.b_blob.data_stream.read()
            h1 = tlsh.hash(a_content)
            h2 = tlsh.hash(b_content)
            if h1 and h2:
                data["similarity"] = (300.0 - tlsh.diffxlen(h1, h2)) / 300

        return cls(**data)

    def add_detections(self, a_detections: List[Detection], b_detections: List[Detection]):
        duplicates = set(x.diff_hash for x in a_detections) & set(x.diff_hash for x in b_detections)
        self.new_detections = [x for x in b_detections if x.diff_hash not in duplicates]
        self.removed_detections = [x for x in a_detections if x.diff_hash not in duplicates]

    def pprint(self):
        from prettyprinter import pprint as pp
        pp(self)


class DiffAnalyzer(DiffAnalyzerType):
    def __init__(self):
        self.hits = []
        self.diffs = []
        self.tables = []
        self.same_files = set()

    @classmethod
    def get_diff_hooks(cls) -> dict:
        data = plugins.load_entrypoint("aura.diff_hooks")
        return data["entrypoints"]

    def on_diff(self, sender, ctx):
        if isinstance(sender, GitDiff):
            self._on_diff_type_diff(sender, ctx)
        elif type(sender) == dict:
            self._on_diff_type_dict(sender, ctx)

    def on_same_file(self, sender):
        size = os.stat(sender).st_size
        self.same_files.add((sender, size))

    def _on_diff_type_diff(self, sender: GitDiff, ctx: dict):
        d = Diff.from_git_diff(git_diff=sender, a_path=ctx["a_path"], b_path=ctx["b_path"])
        for hook_name, hook in self.get_diff_hooks().items():
            for output in hook(diff=d):
                if type(output) == ScanLocation:
                    self.compare(a_path=output, b_path=output.metadata["b_scan_location"])
                else:
                    self.hits.append(output)

        self.diffs.append(d)

    def _on_diff_type_dict(self, sender, ctx):
        pprint.pprint(sender)

    def compare(
        self,
        a_path: Union[ScanLocation, URIHandler],
        b_path: Union[ScanLocation, URIHandler],
        ctx=None,
        detections=False
    ):
        # TODO: add a check if one is URIHandler and the other one is Path or ScanLocation
        if isinstance(a_path, URIHandler) and isinstance(b_path, URIHandler):
            try:
                for item in a_path.get_diff_paths(b_path):
                    if isinstance(item, Table):
                        self.tables.append(item)
                        continue

                    loc1, loc2 = item
                    self.compare(loc1, loc2, detections=detections)
                    if detections:
                        if type(detections) in (list, tuple):
                            loc1.metadata["analyzers"] = detections
                            loc2.metadata["analyzers"] = detections

                        DiffDetections(self.diffs, loc1, loc2)

            except UnsupportedDiffLocation:
                for item in b_path.get_diff_paths(a_path):
                    if isinstance(item, Table):
                        self.tables.append(item)
                        continue

                    loc2, loc1 = item
                    self.compare(loc1, loc2, detections=detections)
                    if detections:
                        if type(detections) in (list, tuple):
                            loc1.metadata["analyzers"] = detections
                            loc2.metadata["analyzers"] = detections

                        DiffDetections(self.diffs, loc1, loc2)

            return
        elif a_path.location.is_file() and b_path.location.is_file():
            self._diff_files(a_path, b_path, ctx)
        elif b_path.location.is_dir() and a_path.location.is_dir():
            self._diff_dirs(a_path, b_path, ctx)
        else:
            # TODO: be able to compare an archive and a directory
            raise ValueError(f"FS type mismatch: {str(a_path)}, {str(b_path)}")

        if detections:
            _ = DiffDetections(self.diffs, a_path, b_path)

    def _diff_dirs(self, a_path: ScanLocation, b_path: ScanLocation, ctx):
        self._diff_git(a_path, b_path, ctx)

    def _diff_files(self, a_path: ScanLocation, b_path: ScanLocation, ctx):
        self._diff_git(a_path, b_path, ctx)

    def _diff_git(self, a_path: ScanLocation, b_path: ScanLocation, ctx=None):
        """
        Diff files/dirs by using temporary git commits which works like this:

        1. Create a temporary empty git repository
        2. Copy content of a_path & commit
        3. Remove all copied files from a_path from git repo
        4. Copy content of b_path & commit
        5. Extract diff between those 2 commits

        :param a_path: location of first file/dir
        :param b_path: location of second file/dir
        :param ctx: Diff context
        :return: None
        """
        tmp = tempfile.mkdtemp(prefix="aura_diff_")
        tmp_pth = Path(tmp)
        if ctx is None:
            ctx = {}

        ctx.update({
            "tmp": tmp_pth,
            "a_path": a_path,
            "b_path": b_path,
        })

        try:
            # Create an empty repository
            bare_repo = Repo.init(tmp)
            a_content = []
            same_files = set()
            b_content = []
            # Copy the content from first path
            if a_path.location.is_dir():
                for x in a_path.location.iterdir():
                    dest = tmp_pth / x.name
                    if x.is_dir():
                        shutil.copytree(x.absolute(), dest)
                    else:
                        shutil.copy(x.absolute(), dest)
                    a_content.append(os.fspath(dest))
            else:
                dest = tmp_pth / a_path.location.name
                shutil.copy(a_path.location.absolute(), dest)
                a_content.append(os.fspath(dest))

            bare_repo.index.add(a_content)
            a_commit = bare_repo.index.commit(message=str(a_path))

            for x in a_commit.tree.traverse():
                if isinstance(x, Blob):
                    same_files.add(x.path)

            # Cleanup repo from pth1 files
            if a_content:
                bare_repo.index.remove(items=a_content, r=True, working_tree=True)

            if b_path.location.is_dir():
                for x in b_path.location.iterdir():  # type: Path
                    dest = tmp_pth / x.name
                    if dest.exists():
                        shutil.rmtree(dest)

                    if x.is_dir():
                        shutil.copytree(x.absolute(), dest)
                    else:
                        shutil.copy2(x.absolute(), dest)
                    b_content.append(os.fspath(dest))
            else:
                dest = tmp_pth / b_path.location.name
                shutil.copy(a_path.location.absolute(), dest)
                b_content.append(os.fspath(dest))

            bare_repo.index.add(b_content)
            b_commit = bare_repo.index.commit(message=str(b_path))

            for x in b_commit.tree.traverse():
                if isinstance(x, Blob):
                    same_files.add(x.path)

            for diff in a_commit.diff(b_commit, create_patch=True, M=True, l=100, B=True, C=True):
                if diff.a_path in same_files:
                    same_files.remove(diff.a_path)

                if diff.b_path in same_files:
                    same_files.remove(diff.b_path)

                self.on_diff(diff, ctx=ctx)

            for x in same_files:
                if a_path.location.is_dir():
                    self.on_same_file(a_path.location / x)
                else:
                    self.on_same_file(x)

        finally:
            shutil.rmtree(tmp)

    def pprint(self):
        from .output import text
        out = text.TextDiffOutput()
        out.output_diff(self.diffs)


class DiffDetections:
    def __init__(self, file_diffs: List[Diff], a_location: ScanLocation, b_location: ScanLocation):
        self.file_diffs: List[Diff] = file_diffs
        self.a_loc: ScanLocation = a_location
        self.b_loc: ScanLocation = b_location
        self.orphans = []

        a_refs = {}
        b_refs = {}

        for d in file_diffs:
            if d.a_ref:
                a_refs[d.a_ref] = d
            if d.b_ref:
                b_refs[d.b_ref] = d

        self.a_hits = self.scan_location(self.a_loc)
        a_pairs, a_orphans = self.pair_hits(a_refs, self.a_hits)

        self.b_hits = self.scan_location(self.b_loc)
        b_pairs, b_orphans = self.pair_hits(b_refs, self.b_hits)

        for d in file_diffs:
            a_detections = a_pairs.get(d.a_ref, [])
            b_detections = b_pairs.get(d.b_ref, [])
            d.add_detections(a_detections, b_detections)

    def scan_location(self, location):
        sandbox = Analyzer(location=location)
        return tuple(sandbox.run())

    def pair_hits(self, diff_refs, hits):
        orphans = []
        matches = defaultdict(list)
        sorted_refs = sorted(diff_refs.keys(), key=lambda x: len(x), reverse=True)

        for hit in hits:
            if hit.detection_type == "FileStats":
                continue

            for ref in sorted_refs:
                if hit.location and hit.location.startswith(ref):
                    matches[ref].append(hit)
                    break
            else:
                orphans.append(hit)

        return matches, orphans
