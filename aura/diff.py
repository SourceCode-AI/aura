#-*- coding: utf-á -*-
"""
Utilities for computing diffs
"""

import os
import sys
import tempfile
import shutil
import pprint
from pathlib import Path

import magic
import ssdeep
from git import Repo, Diff, Blob
from blinker import signal

from . import utils
# from .package_analyzer import Unpacker


class DiffAnalyzer:
    def __init__(self):
        self.diffs = []
        self.same_files = set()
        self.diff_hit = signal('aura:diff')
        self.diff_hit.connect(self.on_diff)
        self.same_file_hit = signal('aura:same_file')
        self.same_file_hit.connect(self.on_same_file)

    def on_diff(self, sender, ctx):
        if isinstance(sender, Diff):
            self._on_diff_type_diff(sender, ctx)
        elif isinstance(sender, dict):
            self._on_diff_type_dict(sender, ctx)

    def on_same_file(self, sender):
        size = os.stat(sender).st_size
        self.same_files.add((sender, size))

    def _on_diff_type_diff(self, sender, ctx):
        if sender.a_path is None or sender.new_file:
            operation = 'A'  # Added
        elif sender.b_path is None or sender.deleted_file:
            operation = 'D'  # Deleted
        elif not sender.diff:
            operation = 'R'  # Renamed
        else:
            operation = 'M'  # Modified

        data = {
            'operation': operation,
            # Relative paths to the repository
            'a_rel_path': sender.a_path,
            'b_rel_path': sender.b_path,
        }

        if sender.a_path is not None and operation != 'A':
            if ctx['a_path'].is_file():
                a_fs_path = ctx['a_path']
            else:
                a_fs_path = ctx['a_path'] / sender.a_path

            data['a_ref'] = os.fspath(sender.a_path)
            data['a_md5'] = utils.md5(a_fs_path)
            data['a_mime'] = magic.from_file(os.fspath(a_fs_path), mime=True)
            data['a_ssdeep'] = ssdeep.hash_from_file(os.fspath(a_fs_path))
            data['a_size'] = a_fs_path.stat().st_size
        else:
            data['a_size'] = 0

        if sender.b_path is not None and operation != 'D':
            if ctx['b_path'].is_file():
                b_fs_path = ctx['b_path']
            else:
                b_fs_path = ctx['b_path'] / sender.b_path

            # FIXME: parent $  ref when unpacking data['b_ref'] = utils.construct_path(sender.b_path, parent=ctx.get('b_ref'))
            data['b_ref'] = os.fspath(b_fs_path)
            data['b_md5'] = utils.md5(b_fs_path)
            data['b_mime'] = magic.from_file(os.fspath(b_fs_path), mime=True)
            data['b_ssdeep'] = ssdeep.hash_from_file(os.fspath(b_fs_path))
            data['b_size'] = b_fs_path.stat().st_size
        else:
            data['b_size'] = 0

        if data.get('a_ssdeep') and data.get('b_ssdeep'):
            data['diff'] = sender.diff.decode()
            data['similarity'] = ssdeep.compare(data['a_ssdeep'], data['b_ssdeep'])
        else:
            data['similarity'] = 0.0

        self.diffs.append(data)

    def _on_diff_type_dict(self, sender, ctx):
        pprint.pprint(sender)

    def compare(self, a_path, b_path, ctx=None):
        if a_path.is_file() and b_path.is_file():
            self._diff_files(a_path, b_path, ctx)
        elif b_path.is_dir() and a_path.is_dir():
            self._diff_dirs(a_path, b_path, ctx)
        else:
            print(f"{repr(b_path)}, {repr(a_path)}")
            raise ValueError("FS type mismatch")

    def _diff_dirs(self, a_path, b_path, ctx):
        self._diff_git(a_path, b_path, ctx)

    def _diff_files(self, a_path, b_path, ctx):
        a_mime = magic.from_file(os.fspath(a_path), mime=True)
        b_mime = magic.from_file(os.fspath(b_path), mime=True)

        if False:
            pass
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
        else:
            self._diff_git(a_path, b_path, ctx)

    def _diff_git(self, a_path, b_path, ctx):
        """
        Diff files/dirs by using temporary git commits which works like this:

        1. Create a temporary empty git repository
        2. Copy content of pth1 & commit them
        3. Remove all copied files from pth1 from git repo
        4. Copy content of pth2 & commit them
        5. Extract diff between those 2 commits

        :param a_path: location of first file/dir
        :param b_path: location of second file/dir
        :param ctx: Diff context
        :return: None
        """
        tmp = tempfile.mkdtemp(prefix='aura_diff_')
        tmp_pth = Path(tmp)
        if ctx is None:
            ctx = {}

        ctx.update({
            'tmp': tmp_pth,
            'a_path': a_path.absolute(),
            'b_path': b_path.absolute(),
        })

        try:
            bare_repo = Repo.init(tmp)
            # bare_content = set(os.listdir(tmp))
            a_content = []
            same_files = set()
            b_content = []
            # Copy the content from first path
            if a_path.is_dir():
                for x in a_path.iterdir():
                    dest = tmp_pth / x.parts[-1]
                    if x.is_dir():
                        shutil.copytree(x.absolute(), dest)
                    else:
                        shutil.copy(x.absolute(), dest)
                    a_content.append(os.fspath(dest))
            else:
                dest = tmp_pth / a_path.parts[-1]
                shutil.copy(a_path.absolute(), dest)
                a_content.append(os.fspath(dest))

            bare_repo.index.add(a_content)
            a_commit = bare_repo.index.commit(message=os.fspath(a_path))

            for x in a_commit.tree.traverse():
                if isinstance(x, Blob):
                    same_files.add(x.path)

            # Cleanup repo from pth1 files
            bare_repo.index.remove(items=a_content, r=True, working_tree=True)

            if b_path.is_dir():
                for x in b_path.iterdir():
                    dest = tmp_pth / x.parts[-1]
                    if x.is_dir():
                        shutil.copytree(x.absolute(), dest)
                    else:
                        shutil.copy2(x.absolute(), dest)
                    b_content.append(os.fspath(dest))
            else:
                dest = tmp_pth / b_path.parts[-1]
                shutil.copy(a_path.absolute(), dest)
                b_content.append(os.fspath(dest))

            bare_repo.index.add(b_content)
            b_commit = bare_repo.index.commit(message=os.fspath(b_path))

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
                if a_path.is_dir():
                    self.same_file_hit.send(a_path / x)
                else:
                    self.same_file_hit.send(x)

        finally:
            shutil.rmtree(tmp)

    def pprint(self, full=True):
        diff_ratio = []
        for x in self.same_files:
            diff_ratio.append(100.0)

        for x in self.diffs:
            similarity = x.get('similarity', 0.0)
            diff_ratio.append(similarity)

            if x['operation'] == 'M':
                utils.print_tty(f"Modified file '{x['a_ref']}' -> '{x['b_ref']}' . Similarity: {similarity}%", fg='red')
                if full:
                    utils.print_tty('---[ START OF DIFF ]---', fg='blue')
                    utils.print_tty(x['diff'])
                    utils.print_tty('---[ END OF DIFF ]---', fg='blue')
            elif x['operation'] == 'R':
                utils.print_tty(f"File renamed '{x['a_ref']}' -> '{x['b_ref']}'", fg='green')
            elif x['operation'] == 'A':
                utils.print_tty(f"File added '{x['b_ref']}'", fg='yellow')
            elif x['operation'] == 'D':
                utils.print_tty(f"File removed '{x['a_ref']}'", fg='green')


        diff_total = sum(diff_ratio) / len(diff_ratio)

        utils.print_tty(f"Total diff ratio: {diff_total:.4}%")



if __name__ == '__main__':
    pth1 = Path(sys.argv[1])
    pth2 = Path(sys.argv[2])
    da = DiffAnalyzer()

    da.compare(pth1, pth2)
    da.pprint()

