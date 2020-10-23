"""
This module contains Visitor class for traversing the parsed AST tree
"""
from __future__ import annotations

import os
import time
from functools import partial, wraps
from collections import deque, OrderedDict
from warnings import warn
from typing import Optional, Tuple, Union, Dict

import pkg_resources

from .nodes import Context, ASTNode
from ..detections import Detection
from ...stack import CallGraph
from .. import python_src_inspector
from ...uri_handlers.base import ScanLocation
from ...exceptions import ASTParseError
from ... import python_executor
from ... import config


INSPECTOR_PATH = os.path.abspath(python_src_inspector.__file__)
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


def get_ast_tree(location: Union[ScanLocation, bytes], metadata=None) -> dict:
    if type(location) == bytes:
        kwargs = {
            "command": [INSPECTOR_PATH, "-"],
            "stdin": location
        }
    else:
        kwargs = {
            "command": [INSPECTOR_PATH, location.str_location]
        }

    if metadata is None:
        if isinstance(location, ScanLocation):
            metadata = location.metadata
        else:
            metadata = {}

    tree = python_executor.run_with_interpreters(
        metadata=metadata,
        native_callback=python_executor.get_native_source_code,
        **kwargs
    )

    if tree is None:
        raise ASTParseError("Unable to parse the source code")

    if "encoding" not in metadata and tree and tree.get("encoding"):
        metadata["encoding"] = tree["encoding"]

    return tree



class Visitor:
    """
    Main class for traversing the parsed AST tree with support for hooks to call functions
    when nodes are visited as well as modification via the passed context
    """

    stage_name = None

    def __init__(self, *, location: ScanLocation):
        self.location: ScanLocation = location
        self.tree = None
        self.traversed = False
        self.modified = False
        self.iteration = 0
        self.convergence = 1
        self.queue = deque()
        self.call_graph = CallGraph()

        self.hits = []
        self.path = location.location
        self.normalized_path: str = str(location)
        self.max_iterations = int(config.get_settings("aura.max-ast-iterations", 500))
        self.max_queue_size = int(config.get_settings("aura.max-ast-queue-size", 10000))

    @classmethod
    def from_visitor(cls, visitor: Visitor) -> Visitor:
        obj = cls(location=visitor.location)
        obj.tree = visitor.tree
        obj.hits = visitor.hits
        obj.traverse()

        return obj

    @classmethod
    def run_stages(cls, *, location: ScanLocation, stages: Optional[Tuple[str, ...]]=None, ast_tree=None) -> Visitor:
        if not stages:
            stages = config.get_ast_stages()

        v = previous = Visitor(location=location)
        if ast_tree is None:
            previous.load_tree()
        else:
            previous.tree = ast_tree
        previous.traverse()

        visitors = cls.get_visitors()

        for stage in stages:
            if stage == "raw":
                continue

            assert previous.tree is not None, stage
            if stage not in visitors:
                raise ValueError("Unknown AST stage: " + stage)
            v = visitors[stage].from_visitor(previous)
            previous = v

        return v

    @classmethod
    def get_visitors(cls) -> Dict[str, Visitor]:
        global VISITORS
        if VISITORS is None:
            VISITORS = {
                x.name: x.load()
                for x in pkg_resources.iter_entry_points("aura.ast_visitors")
            }

        return VISITORS

    def load_tree(self):
        self.tree = get_ast_tree(self.location)

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

    def _replace_root(self, new_node):
        """
        Helper function to replace the root in a context call
        """
        self.modified = True
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
                    # Reset convergence if the tree was modified
                    self.convergence = 1

            self.modified = False

            root = self.tree
            if type(root) == dict and "ast_tree" in root:
                root = root["ast_tree"]

            new_ctx = Context(
                node=root, parent=None, replace=self._replace_root, visitor=self
            )
            self.queue.append(new_ctx)
            self._init_visit(new_ctx)
            processed_nodes = set()

            while self.queue:
                ctx: Context = self.queue.popleft()

                # Keep track of processed object ID's
                # This is to prevent infinite loops where processed object will add themselves back to queue
                # This works on python internal ID as we are only concerned about the same objects
                if _id(ctx.node) in processed_nodes:
                    continue

                self.__process_context(ctx)
                processed_nodes.add(_id(ctx.node))

            self._post_iteration()
            self.iteration += 1
            if self.iteration >= self.max_iterations:
                self.hits.append(Detection(
                    detection_type="ASTAnalysisError",
                    message="Maximum AST tree iterations reached",
                    extra={"iterations": self.iteration},
                    signature=f"ast_analysis_error#max_iterations#{str(self.location)}"
                ))  # TODO: add tests for this
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
                f"[{self.__class__.__name__}] Convergence of {str(self.location)} took {end}s in {self.iteration} iterations"
            )

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
        if _type(context.node) in (_dict, OrderedDict):
            if context.node.get("lineno") in config.DEBUG_LINES:
                breakpoint()
            keys = _list(k for k, v in context.node.items() if type(v) not in (str, int))
            _list(map(lambda k: self.__visit_dict(k, context), keys))
        elif _type(context.node) == _list:
            _list(map(lambda x: self.__visit_list(x[0], x[1], context), enumerate(context.node)))
        elif _isinstance(context.node, ASTNode):
            if context.node.line_no in config.DEBUG_LINES:
                breakpoint()

            if not context.node.converged:
                context.node._visit_node(context)

    def __visit_dict(self, key: str, context: Context):
        value = context.node[key]

        if type(value) == dict and len(value) == 1 and value.get("_type") == "Load":
            return
        elif type(value) in (tuple, list) and len(value) == 0:
            return

        context.visit_child(
            node=context.node[key],
            replace=partial(self._replace_generic, key=key, context=context),
        )

    def __visit_list(self, idx: int, item, context: Context):
        context.visit_child(
            node=item,
            replace=partial(self._replace_generic, key=idx, context=context),
        )

    def _init_visit(self, context: Context):
        pass

    def _post_iteration(self):
        ...

    def _post_analysis(self):
        for node in ASTNode.get_instances():
            node.converged = False

    def _visit_node(self, context: Context):
        pass
