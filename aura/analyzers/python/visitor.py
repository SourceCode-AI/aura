"""
This module contains Visitor class for traversing the parsed AST tree
"""
from __future__ import annotations

import os
import copy
import time
import typing
import subprocess
from functools import partial, wraps
from collections import deque
from pathlib import Path
from warnings import warn

import pkg_resources
import simplejson as json

from .nodes import Context, ASTNode, CallGraph
from .. import python_src_inspector
from ... import python_executor
from ... import config


INSPECTOR_PATH = os.path.abspath(python_src_inspector.__file__)

DEFAULT_STAGES = ("convert", "rewrite", "taint_analysis", "readonly")

VISITORS = None

logger = config.get_logger(__name__)


def ignore_error(func):
    """
    Dummy decorator to silence the recursion errors
    """

    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except RecursionError:
            logger.exception("Recursion error")

    return wrapper


class Visitor:
    """
    Main class for traversing the parsed AST tree with support for hooks to call functions
    when nodes are visited as well as modification via the passed context
    """

    _lru_cache = {}

    def __init__(self, *, metadata, **kwargs):
        self.kwargs = kwargs
        self.tree = None
        self.traversed = False
        self.modified = False
        self.iteration = 0
        self.convergence = 1
        self.queue = deque()
        self.call_graph = CallGraph()

        self.metadata = metadata
        self.hits = []
        self.path = metadata["path"]
        self.normalized_path = metadata.get("normalized_path", self.path)
        self.max_iterations = int(config.CFG["aura"].get("max-ast-iterations", 500))
        self.max_queue_size = int(config.CFG["aura"].get("max-ast-queue-size", 10000))

    @classmethod
    def from_cache(cls, *, source, **kwargs):
        # TODO: remove, deprecated by from_visitor
        obj = cls(path=source, **kwargs)
        obj.load_tree(source)
        obj.traverse()
        return obj

    @classmethod
    def from_visitor(cls, visitor: Visitor):
        cache_id = f"{cls.__name__}#{os.fspath(visitor.path)}"

        if cache_id not in cls._lru_cache:
            obj = cls(
                metadata=visitor.metadata,
                **visitor.kwargs,
            )
            obj.tree = copy.deepcopy(visitor.tree)
            obj.traverse()
            cls._lru_cache[cache_id] = obj

        return cls._lru_cache[cache_id]

    @classmethod
    def run_stages(cls, *, metadata, stages=DEFAULT_STAGES, **kwargs):
        if not stages:
            stages = DEFAULT_STAGES

        v = None
        path = os.fspath(metadata["path"])
        previous = Visitor(metadata=metadata, **kwargs)
        previous.load_tree(path)
        previous.traverse()

        visitors = cls.get_visitors()

        for stage in stages:
            assert previous.tree is not None, stage
            if stage not in visitors:
                raise ValueError("Unknown AST stage: " + stage)
            v = visitors[stage].from_visitor(previous)
            previous = v

        return v

    @classmethod
    def get_visitors(cls):
        global VISITORS
        if VISITORS is None:
            VISITORS = {
                x.name: x.load()
                for x in pkg_resources.iter_entry_points("aura.ast_visitors")
            }

        return VISITORS

    def load_tree(self, source: Path):
        if isinstance(source, Path):
            source = os.fspath(source)

        cmd = [INSPECTOR_PATH, source]
        self.tree = python_executor.run_with_interpreters(command=cmd, metadata=self.metadata)
        if "encoding" not in self.metadata and self.tree.get("encoding"):
            self.metadata["encoding"] = self.tree["encoding"]

    def push(self, context):
        if len(self.queue) >= self.max_queue_size:
            warn("AST Queue size exceeded, dropping traversal node", stacklevel=2)
            return False
        self.queue.append(context)

    def _replace_generic(self, new_node, key, context):
        """
        This is a very simple helper that only sets dict/list value
        It's used in a combination of functools.partial to free some of it's arguments
        """
        self.modified = True
        context.modified = True
        context.node[key] = new_node

    def _replace_root(self, new_node, context):
        """
        Helper function to replace the root in a context call
        """
        self.modified = True
        context.modified = True
        self.tree = new_node

    def traverse(self, _id=id):
        """
        Traverse the AST tree from root
        Visited nodes are placed in a FIFO queue as context to be processed by hook and functions
        Context defines replacement functions allowing tree to be modified
        If the tree was modified during the traversal, another pass/traverse is made up to specified number of iterations
        In case the tree wasn't modified, extra N passes are made as defined by convergence attribute
        """
        start = time.time()
        self.iteration = 0

        while self.iteration == 0 or self.modified or self.convergence:
            self.queue.clear()
            if self.convergence is not None:
                # Convergence attribute defines how many extra passes through the tree are made
                # after it was not modified, this is a safety mechanism as some badly
                # written plugins might not have set modified attribute after modifying the tree
                # Or you know, might be a bug and the tree was not marked as modified when it should
                if (not self.modified) and self.convergence > 0:
                    self.convergence -= 1
                else:
                    #  Reset convergence if the tree was modified
                    self.convergence = 1

            self.modified = False

            # logger.debug(f"Tree '{self.__class__.__name__}' iteration {self.iteration}")

            new_ctx = Context(
                node=self.tree, parent=None, replace=self._replace_root, visitor=self
            )
            self.queue.append(new_ctx)
            self._init_visit(new_ctx)

            processed_nodes = set()

            while self.queue:
                ctx = self.queue.popleft()  # type: Context

                # Keep track of processed object ID's
                # This is to prevent infinite loops where processed object will add themselves back to queue
                # This works on python internal ID as we are only concerned about the same objects
                if _id(ctx.node) in processed_nodes:
                    continue

                # logger.debug(f"Processing context: {ctx.node}")
                self.__process_context(ctx)
                processed_nodes.add(id(ctx.node))

            self.iteration += 1
            if self.iteration >= self.max_iterations:  # TODO: report this as a result so we can collect this data
                break

        self._post_analysis()

        logger.debug(
            f"Tree visitor '{type(self).__name__}' converged in {self.iteration} iterations"
        )
        self.traversed = True

        end = time.time() - start
        if end >= 3:
            # Log message if the tree traversal took loner then 3s
            logger.info(
                f"[{self.__class__.__name__}] Convergence of {self.metadata.get('path')} took {end}s in {self.iteration} iterations"
            )

        if self.path:
            cache_id = f"{self.__class__.__name__}#{os.fspath(self.path)}"
            self._lru_cache[cache_id] = self

        return self.tree

    @ignore_error
    def __process_context(
            self,
            context: Context,
            _type=type,
            _isinstance=isinstance,
            _dict=dict,
            _list=list
    ):
        self._visit_node(context)

        if context.modified:
            return

        # Using map is much faster then for-loop
        if _type(context.node) == _dict:
            if context.node.get("lineno") in config.DEBUG_LINES:
                breakpoint()
            keys = _list(context.node.keys())
            _list(map(lambda k: self.__visit_dict(k, context), keys))
        elif _type(context.node) == _list:
            _list(map(lambda x: self.__visit_list(x[0], x[1], context), enumerate(context.node)))
        elif _isinstance(context.node, ASTNode):
            if context.node.line_no in config.DEBUG_LINES:
                breakpoint()
            context.node._visit_node(context)

    def __visit_dict(self, key, context):
        context.visit_child(
            node=context.node[key],
            replace=partial(self._replace_generic, key=key, context=context),
        )

    def __visit_list(self, idx, item, context):
        context.visit_child(
            node=item,
            replace=partial(self._replace_generic, key=idx, context=context),
        )

    def _init_visit(self, context: Context):
        pass

    def _post_analysis(self):
        pass

    def _visit_node(self, context: Context):
        pass
