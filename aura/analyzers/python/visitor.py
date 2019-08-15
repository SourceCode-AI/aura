"""
This module contains Visitor class for traversing the parsed AST tree
"""
import os
import time
import typing
import subprocess
from functools import partial, wraps
from collections import deque
from pathlib import Path

import simplejson as json

from . nodes import Context, ASTNode, CallGraph
from .. import python_src_inspector
from ... import config


INSPECTOR_PATH = os.path.abspath(python_src_inspector.__file__)
logger = config.get_logger(__name__)


def ignore_error(func):
    """
    Dummy decorator to silence the errors
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except RecursionError:
            logger.exception("Recursion error")

    return wrapper


def get_ast_tree(path:str, stdin=None) -> typing.Dict:
    """
    Enumerate configured interpreters to find the one that is able to parse the given source code
    Source code is parsed into AST tree, serialized to JSON and passed back to framework via stdout
    """
    interpreters = list(config.CFG['interpreters'].items())
    for name, interpreter in interpreters:
        proc = subprocess.run(
            [interpreter,  INSPECTOR_PATH, path],
            stdout=subprocess.PIPE,
            #stderr=subprocess.PIPE,
            shell=False,
            input=stdin
        )
        if proc.returncode == 0:
            payload = None
            try:
                payload = proc.stdout
                return json.loads(payload)
            except Exception:
                logger.exception(f"Error decoding JSON AST: {repr(payload)}")


class Visitor:
    """
    Main class for traversing the parsed AST tree with support for hooks to call functions
    when nodes are visited as well as modification via the passed context
    """

    _lru_cache = []

    def __init__(self, *, metadata, max_iterations=250, **kwargs):
        self.kwargs = kwargs
        self.tree = None
        self.traversed = False
        self.modified = False
        self.max_iterations = max_iterations
        self.iteration = 0
        self.convergence = 1
        self.queue = deque()
        self.call_graph = CallGraph()

        self.metadata = metadata
        self.hits = []
        self.path = metadata['path']

    @classmethod
    def from_cache(cls, *, source, **kwargs):
        cache_id = f"{cls.__name__}#{os.fspath(source)}"

        for x, t in cls._lru_cache:
            if x == cache_id:
                logger.info(f"Loading AST tree from cache: {cache_id}")
                return t

        obj = cls(path=source, **kwargs)
        obj.load_tree(source)
        obj.traverse()
        return obj

    def load_tree(self, source: Path):
        if isinstance(source, Path):
            source = os.fspath(source)

        self.tree = get_ast_tree(source)

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

    def traverse(self):
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
                if (not self.modified) and self.convergence > 0:
                    self.convergence -= 1
                else:
                    # Reset convergence if the tree was modified
                    self.convergence = 1

            self.modified = False

            #logger.debug(f"Tree '{self.__class__.__name__}' iteration {self.iteration}")

            new_ctx = Context(
                node=self.tree,
                parent=None,
                replace=self._replace_root,
                visitor=self
            )
            self.queue.append(new_ctx)
            self._init_visit(new_ctx)

            processed_nodes = set()

            while (self.queue):
                ctx = self.queue.popleft()  # type: Context

                # Keep track of processed object ID's
                # This is to prevent infinite loops where processed object will add themselves back to queue
                # This works on python internal ID as we are only concerned about the same objects
                if id(ctx.node) in processed_nodes:
                    continue

                # logger.debug(f"Processing context: {ctx.node}")
                self.__process_context(ctx)
                processed_nodes.add(id(ctx.node))

            self.iteration += 1
            if self.iteration >= self.max_iterations:
                break

        logger.debug(f"Tree visitor '{type(self).__name__}' converged in {self.iteration} iterations")
        self.traversed = True

        end = time.time() - start
        if end >= 3:
            # Log message if the tree traversal took loner then 3s
            logger.info(f"[{self.__class__.__name__}] Convergence of {self.metadata.get('path')} took {end}s in {self.iteration} iterations")

        if self.metadata.get('path'):
            cache_id = f"{self.__class__.__name__}#{os.fspath(self.kwargs['path'])}"
            self._lru_cache.append((cache_id, self))
            if len(self._lru_cache) > 15:
                self._lru_cache = self._lru_cache[-15:]

        return self.tree

    @ignore_error
    def __process_context(self, context: Context):
        if isinstance(context.node, dict) and context.node.get('lineno')  in config.DEBUG_LINES:
            breakpoint()
        elif isinstance(context.node, ASTNode) and context.node.line_no in config.DEBUG_LINES:
            breakpoint()

        # if isinstance(context.node, ASTNode):
        #     print(context.stack.frame.variables)
        #     context.node.pprint()

        self._visit_node(context)

        if context.modified:
            return

        if type(context.node) == dict:
            keys = list(context.node.keys())
            for key in keys:
                context.visit_child(
                    node = context.node[key],
                    replace = partial(self._replace_generic, key=key, context=context)
                )
        elif type(context.node) == list:
            for idx, node_item in enumerate(context.node):
                context.visit_child(
                    node = node_item,
                    replace = partial(self._replace_generic, key=idx, context=context)
                )
        elif isinstance(context.node, ASTNode):
            context.node._visit_node(context)

    def _init_visit(self, context:Context):
        pass

    def _visit_node(self, context:Context):
        pass
