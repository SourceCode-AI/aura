# -*- coding: utf-á -*-
"""
Utilities for computing diffs
"""

import os
import re
import sys
import tempfile
import shutil
import pprint
from pathlib import Path
from dataclasses import dataclass, field

import magic
from git import Repo, Diff as GitDiff, Blob
from blinker import signal

from . import utils
from . import plugins
from .uri_handlers.base import ScanLocation


DIFF_EXCLUDE = re.compile(r"^Binary files .+ differ$")


@dataclass()
class Diff:
    operation: str
    a_size: str
    b_size: str
    a_scan: ScanLocation
    b_scan: ScanLocation
    a_ref: str = None
    b_ref: str = None
    a_md5: str = None
    b_md5: str = None
    a_mime: str = None
    b_mime: str = None
    diff: str = ''
    similarity: float = 0.0

    def __post_init__(self):
        assert self.operation in ("A", "D", "M", "R")

    @property
    def a_path(self) -> Path:
        if self.a_scan.location.is_file():
            return self.a_scan.location
        else:
            return self.a_scan.location / self.a_ref

    @property
    def b_path(self) -> Path:
        if self.b_scan.location.is_file():
            return self.b_scan.location
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

        return cls(**data)


class DiffAnalyzer:
    def __init__(self):
        self.hits = []
        self.diffs = []
        self.same_files = set()
        self.diff_hit = signal("aura:diff")
        self.diff_hit.connect(self.on_diff)
        self.same_file_hit = signal("aura:same_file")
        self.same_file_hit.connect(self.on_same_file)

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

    def compare(self, a_path: ScanLocation, b_path: ScanLocation, ctx=None):
        if a_path.location.is_file() and b_path.location.is_file():
            self._diff_files(a_path, b_path, ctx)
        elif b_path.location.is_dir() and a_path.location.is_dir():
            self._diff_dirs(a_path, b_path, ctx)
        else:
            # TODO: be able to compare an archive and a directory
            raise ValueError(f"FS type mismatch: {str(a_path)}, {str(b_path)}")

    def _diff_dirs(self, a_path: ScanLocation, b_path: ScanLocation, ctx):
        self._diff_git(a_path, b_path, ctx)

    def _diff_files(self, a_path: ScanLocation, b_path: ScanLocation, ctx):

        # TODO: refactor to use the archive unpacker as analyzer
        # if a_mime in Unpacker.supported_mime_types and b_mime in Unpacker.supported_mime_types:
        #     if ctx is None:
        #         ctx = {}
        #
        #     a_archive = Unpacker(path=a_path, mime=a_mime)
        #     b_archive = Unpacker(path=b_path, mime=b_mime)
        #
        #     a_ref = ctx.get('a_ref')
        #     if (not a_ref) or (a_ref and not os.fspath(a_path).endswith(a_ref)):
        #         a_ref = utils.construct_path(a_path, parent=a_ref)
        #         ctx['a_ref'] = a_ref
        #
        #     b_ref = ctx.get('b_ref')
        #     if (not b_ref) or (a_ref and not os.fspath(a_path).endswith(a_ref)):
        #         b_ref = utils.construct_path(b_path, parent=a_ref)
        #         ctx['b_ref'] = b_ref
        #
        #     self.compare(Path(a_archive.tmp_dir), Path(b_archive.tmp_dir), ctx=ctx)
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
            #  bare_content = set(os.listdir(tmp))
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

            for diff in a_commit.diff(b_commit, create_patch=True):
                if diff.a_path in same_files:
                    same_files.remove(diff.a_path)

                if diff.b_path in same_files:
                    same_files.remove(diff.b_path)

                self.on_diff(diff, ctx=ctx)

            for x in same_files:
                if a_path.location.is_dir():
                    self.same_file_hit.send(a_path.location / x)
                else:
                    self.same_file_hit.send(x)

        finally:
            shutil.rmtree(tmp)
