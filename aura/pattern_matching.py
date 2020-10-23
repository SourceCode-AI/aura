from __future__ import annotations

import re
import inspect
import fnmatch
import string
import logging
from abc import ABCMeta, abstractmethod
from typing import List, Mapping
from functools import lru_cache
from textwrap import dedent

from .analyzers.python_src_inspector import collect
from .analyzers.python import nodes, visitor
from .analyzers.detections import Detection
from .type_definitions import ScanLocation


PATTERN_CACHE = None
logger = logging.getLogger(__name__)


class PatternMatcher(metaclass=ABCMeta):
    """
    Basic abstract class used for string matching patterns
    """

    # string identifying the type of the pattern used for signature parsing
    pattern_type: str = ""

    def __init__(self, signature):
        self._signature = signature
        assert signature["pattern"]

    @abstractmethod
    def match(self, value: str) -> bool:
        """
        match the ast node against the signature
        """
        ...

    @abstractmethod
    def match_node(self, context: nodes.Context) -> bool:
        ...

    @property
    def message(self) -> str:
        """
        return a message identifying the match
        """
        return f"{self.pattern_type} match: {self._signature['message']}"

    @property
    def score(self) -> int:
        return self._signature.get("score", 0)

    @property
    def tags(self) -> set:
        return set(self._signature.get("tags", []))

    @classmethod
    def get_patterns(cls, initialize=False) -> Mapping[str, PatternMatcher]:
        global PATTERN_CACHE

        if PATTERN_CACHE is None:
            PATTERN_CACHE = {}
            initialize = True

        if initialize:
            for x in cls.__subclasses__():  # type: PatternMatcher
                if inspect.isabstract(x):
                    x.get_patterns(initialize=initialize)
                else:
                    PATTERN_CACHE[x.pattern_type] = x

        return PATTERN_CACHE

    @classmethod
    def compile_patterns(cls, signatures: List[dict]) -> List[PatternMatcher]:
        """
        Compile all defined string pattern matchers into a dictionary indexed by type
        :signatures: a list of defined signatures (loaded from json file)
        """
        types = PatternMatcher.get_patterns()

        compiled = []
        for s in signatures:
            if type(s) == str:
                s = {"type": "exact", "pattern": s, "message": "n/a"}

            if s["type"] not in types:
                raise ValueError("Unknown signature type: " + s["type"])

            compiled.append(types[s["type"]](s))

        return compiled

    @classmethod
    def find_matches(cls, value, signatures: list):
        """
        iterate over the list of compiled pattern matchers and
        attempt to match the pattern
        """
        if not isinstance(value, (str, nodes.String)):
            return
        value = str(value)

        for s in signatures:  # type: PatternMatcher
            if s.match(value):
                yield s


class StringPatternMatcher(PatternMatcher, metaclass=ABCMeta):
    def match(self, value) -> bool:
        if type(value) != str:
            return False

        return self.match_string(value)

    def match_node(self, node: nodes.NodeType) -> bool:
        return False

    @abstractmethod
    def match_string(self, value: str) -> bool:
        ...


class FilePatternMatcher():
    def __init__(self, signature):
        self._signature = signature
        self.__compiled = PatternMatcher.compile_patterns([signature])[0]

    def __repr__(self):
        return f"<FilePatternMatcher({repr(self._signature)})>"

    def match(self, value: ScanLocation) -> bool:
        if self._signature.get("target", "full") == "full":
            targets = (str(value.location),)
        elif self._signature["target"] == "part":
            targets = value.location.parts
        elif self._signature["target"] == "filename":
            targets = (value.location.name,)
        else:
            raise ValueError(f"Unknown pattern target: '{self._signature['target']}'")

        return any(self.__compiled.match(x) for x in targets)


class RegexPattern(StringPatternMatcher):
    """
    String matcher that supports regex expressions
    """

    pattern_type = "regex"

    def __init__(self, signature: dict):
        super().__init__(signature)

        flags = 0
        for f in signature.get("flags", ""):
            if f == "I":
                flags |= re.I

        self._regex = re.compile(signature["pattern"], flags=flags)

    @lru_cache()
    def match_string(self, value: str) -> bool:
        """
        match the ast node against the signature
        """
        return bool(self._regex.match(value))


class GlobPattern(StringPatternMatcher):
    """
    String matcher that supports shell like/glob expressions
    """

    pattern_type = "glob"

    @lru_cache()
    def match_string(self, value: str) -> bool:
        return fnmatch.fnmatch(value, self._signature["pattern"])


class ExactPattern(StringPatternMatcher):
    """
    String pattern matcher to match exact, e.g. equal strings
    """

    pattern_type = "exact"

    def match_string(self, value: str) -> bool:
        return value == self._signature["pattern"]


class ContainsPattern(StringPatternMatcher):

    pattern_type = "contains"

    def match_string(self, value: str) -> bool:
        return self._signature["pattern"] in value


class ASTPattern:
    """
    Match AST tree against a defined source code pattern (compiled into AST tree pattern)
    """
    # Nested class defined here on purpose to have a namespace as this `Context` is related to ASTPattern matching
    # making it easier to distinguish from other classes also named `Context`, especially the one from ASTVisitor/ASTNodes
    class Context:
        def __init__(self, pattern: ASTPattern):
            self.pattern = pattern

        def match(
                self,
                node: nodes.NodeType,  # original AST node from the source code
                other: nodes.NodeType  # AST node pattern to match against
        ) -> bool:
            if type(other) == ASTPattern.AnyOf:
                return self._match_any_of(node, other)
            elif node is None:
                return other is None
            elif type(node) == bool:
                if type(other) != bool:
                    return False
                return node is other
            elif type(node) == str:
                if type(other) not in (str, nodes.String):
                    return False
                return node == str(other)
            elif type(node) == dict:
                return self._match_dict(node, other)
            elif type(node) in (list, tuple):
                return self._match_list(node, other)
            elif type(node) == int:
                if type(other) not in (int, nodes.Number):
                    return False
                return node == int(other)
            elif type(node) == float:
                if type(other) != float:
                    return False
                return node == other

            try:
                return node.match(other, self)
            except AttributeError:
                return False

        # Dispatch method for basic python types
        def _match_dict(self, node: dict, other) -> bool:
            if type(other) != dict:
                return False
            if set(other.keys()) - set(node.keys()):
                return False

            for k, v in node.items():
                if not self.match(v, other[k]):
                    return False
            return True

        def _match_list(self, node: list, other) -> bool:
            return False  # TODO

        def _match_any_of(self, node, other: ASTPattern.AnyOf) -> bool:
            for sub_pattern in other:
                if self.match(node, sub_pattern):
                    return True
            return False


    class AnyOf(list):
        pass


    def __init__(self, signature: dict):
        self._id = None
        self._signature = signature

        if type(self._signature["pattern"]) == str:
            self._compiled = self._compile_src(self._signature["pattern"])
        else:
            self._compiled = ASTPattern.AnyOf(self._compile_src(x) for x in self._signature["pattern"])

        self.ctx: ASTPattern.Context = ASTPattern.Context(self)

    @classmethod
    def _compile_src(cls, src: str) -> nodes.NodeType:
        ast_tree = collect(dedent(src), minimal=True)
        loc = ScanLocation(location="<unknown>")
        v = visitor.Visitor.run_stages(location=loc, stages=("convert", "rewrite"), ast_tree=ast_tree)
        return v.tree[-1]  # TODO: assumption right now is it's a module with one body block

    @property
    def id(self) -> str:
        if self._id is None:
            if "id" in self._signature:
                return self._signature["id"]

            chars = string.ascii_letters + string.digits + "._-"
            self._id = "".join(x for x in self._signature["pattern"] if x in chars)

        return self._id

    def match(self, node: nodes.ASTNode) -> bool:
        return self.ctx.match(node, self._compiled)

    def apply(self, context: nodes.Context):
        logger.debug(f"Applying AST pattern {self.id} at {context.node.line_no}")

        if "tags" in self._signature:
            context.node.tags |= set(self._signature["tags"])

        if "taint" in self._signature:
            t = self._signature["taint"]

            if type(t) == str:
                t = {"level": t}

            msg = t.get("log_message")
            level = t.get("level")

            if level == "sink":
                context.node.mark_as_sink(context=context)
            elif level:
                level = nodes.Taints.from_string(level)

                if level == nodes.Taints.TAINTED and not msg:
                    msg = "AST node marked as source using semantic rules"
                elif level == nodes.Taints.SAFE and not msg:
                    msg = "AST node has been cleaned of taint using semantic rules"

                log = nodes.TaintLog(
                    path = context.visitor.path,
                    line_no = context.node.line_no,
                    taint_level = level,
                    message = msg
                )
                context.node.add_taint(level, context, taint_log=log, lock=t.get("lock", True))
            elif msg:
                log = nodes.TaintLog(
                    path=context.visitor.path,
                    line_no=context.node.line_no,
                    message=msg
                )
                context.node._taint_log.append(log)

            if type(context.node) == nodes.Call and "args" in t:
                for arg_name, arg_level in t["args"].items():
                    for arg in context.node.args:
                        if type(arg) == nodes.Arguments and arg_name in arg.args:
                            arg.taints[arg_name] = nodes.Taints.from_string(arg_level)

        if "detection" in self._signature:
            d = self._signature["detection"]

            hit = Detection(
                detection_type=d.get("type", "ASTPattern"),
                score=d.get("score", 0),
                message=d["message"],
                node=context.node,
                tags=context.node.tags,
                signature=f"ast_pattern#{self.id}/{context.node.line_no}#{context.visitor.normalized_path}"
            )
            if "informational" in d:
                hit.informational = d["informational"]
            else:
                hit.informational = (hit.score == 0)

            if isinstance(context.node, nodes.Call):
                if "type" not in d:  # Replace the default detection type name
                    hit.detection_type = "FunctionCall"
                # Enrich extra with the captured function name
                hit.extra["function"] = context.node.cached_full_name

            context.visitor.hits.append(hit)
            return hit
