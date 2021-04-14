"""
This module contains wrappers for parsed AST nodes
"""
from __future__ import annotations

import os
import typing
import inspect
import logging
from abc import ABCMeta, abstractmethod
from enum import Enum
from pathlib import Path
from warnings import warn
from collections import defaultdict
from collections.abc import Hashable
from dataclasses import dataclass, InitVar, field
from functools import partial, total_ordering, wraps

import chardet

from ...stack import Stack
from ...utils import KeepRefs, slotted_dataclass
from ... import exceptions


BASIC_ELEMENTS = (
    str,
    int,
)
logger = logging.getLogger(__name__)


@total_ordering
class Taints(Enum):
    """
    Enumeration class (`enum.Enum`) defining the different taint levels:

    - `SAFE` = 1
    - `UNKNOWN` = 2
    - `TAINTED` = 3

    Taint levels are comparable and can be "added" (e.g. taint1 + taint2)
    which will return the taint level of whichever is the highest
    """

    SAFE = 1
    UNKNOWN = 2
    TAINTED = 3

    def __lt__(self, other):
        if type(other) != Taints:
            return NotImplemented

        if self == Taints.SAFE and other != Taints.SAFE:
            return True
        elif self == Taints.UNKNOWN and other == Taints.TAINTED:
            return True
        else:
            return False

    def __add__(self, other):
        if type(other) != Taints:
            return NotImplemented

        return max(self, other)

    @classmethod
    def from_string(cls, name: str) -> Taints:
        if name.lower() == "safe":
            return Taints.SAFE
        elif name.lower() == "tainted":
            return Taints.TAINTED
        else:
            return Taints.UNKNOWN


@slotted_dataclass(
    taint_level = None,
    line_no = None,
    message = None,
    extra = field(default_factory=dict),
    node = None
)
class TaintLog:
    """
    Log entry to track the propagation of taints in the AST
    """
    __slots__ = ("path", "taint_level", "line_no", "message", "extra", "node")
    path: Path  # Path to the affected source code
    taint_level: typing.Optional[Taints]
    line_no: typing.Optional[int]
    message: typing.Optional[str]
    extra: dict
    node: typing.Optional[NodeType]

    def __post_init__(self):
        self.path = Path(self.path).absolute()

    def json(self) -> dict:
        d = {
            'line_no': self.line_no,
            'message': self.message
        }

        if self.path:
            # TODO: normalize the path
            d['path'] = os.fspath(self.path)

        if self.taint_level:
            d['taint_level'] = self.taint_level.name

        if self.extra:
            d['extra'] = self.extra

        return d

    @classmethod
    def extract_log(cls, node: ASTNode):
        """
        Extract a sequential log from the provided node
        This will follow the path of chained nodes and their logs concatenated together
        """
        log = [x.json() for x in node._taint_log]

        # Find the first node in chain that affected the propagation of a taint into the current node
        for n in node._taint_log:
            if isinstance(n.node, ASTNode) and n.node._taint_log and n.node._taint_class == node._taint_class:
                log = cls.extract_log(n.node) + log
                break

        return log



class ASTNode(KeepRefs, metaclass=ABCMeta):
    def __post_init__(self, *args, previous_node=None, **kwargs):
        self._full_name = None
        self._original = None
        self._docs = None
        self._converged: bool = False
        self.line_no = None
        self.col = None
        self.end_line_no = None
        self.end_col = None

        if previous_node is not None:
            self.enrich_from_previous(previous_node)

        self.tags = set()
        self._hash = None
        self._taint_class: Taints = Taints.UNKNOWN
        self._taint_locked: bool = False
        self._taint_log: typing.List[TaintLog] = []

    def enrich_from_previous(self, node: typing.Union[dict, ASTNode]):
        """
        Enrich the current node using the information from the previous node
        This is used when AST tree is rewritten/replace with a new node so we copy all the information from the previous one

        :param node: previous node that was replaced that we want to copy information from
        :type node: typing.Union[dict, ASTNode]
        """
        if type(node) == dict:
            if not self.line_no and "lineno" in node:
                self.line_no = node["lineno"]
            if not self.col and "col_offset" in node:
                self.col = node["col_offset"]
            if not self.end_line_no and "end_lineno" in node:
                self.end_line_no = node["end_lineno"]
            if not self.end_col and "end_col_offset" in node:
                self.end_col = node["end_col_offset"]
            if not self._docs:
                self._docs = node.get("_doc_string")
        elif isinstance(node, ASTNode):
            if not self.line_no:
                self.line_no = node.line_no
            if not self.end_line_no:
                self.end_line_no = node.end_line_no
            if not self.col:
                self.col = node.col
            if not self.end_col:
                self.end_col = node.end_col

    @property
    def full_name(self):
        return self._full_name

    @property
    def cached_full_name(self) -> str:
        """
        Permanently cache the full_name attribute
        Use this only if all the remaining stages are read-only as otherwise it would not register changes to the attributes
        """
        if self._full_name is None:
            self._full_name = self.full_name

        return self._full_name

    @property
    def json(self) -> typing.Dict[str, typing.Any]:
        data = {
            "AST_Type": self.__class__.__name__,
        }
        if self.full_name is not None:
            data["full_name"] = self.full_name
        if self.tags:
            data["tags"] = list(self.tags)
        if self.line_no is not None:
            data["line_no"] = self.line_no
        if self.col is not None:
            data["col"] = self.col

        if self._taint_class != Taints.UNKNOWN:
            data["taint"] = self._taint_class.name

        if self._taint_log:
            data['taint_log'] = [x.json() for x in self._taint_log]

        return data

    @property
    def converged(self) -> bool:
        return self._converged

    @converged.setter
    def converged(self, value: bool):
        self._converged = value

    @abstractmethod
    def _visit_node(self, context: Context):
        return NotImplemented

    def pprint(self):
        from prettyprinter import pprint as pp
        pp(self)

    def add_taint(self, taint: Taints, context: Context, lock=False, taint_log: typing.Optional[TaintLog]=None) -> bool:
        """
        Assign a taint to the node
        Operation is ignored if the current taint is already higher or equal
        return True if the taint was modified (increased)
        """
        if taint_log:
            logger.debug(f"{taint_log.message} at {taint_log.path}:{taint_log.line_no}")

        if lock:
            self._taint_locked = True
            if taint != self._taint_class:
                self._taint_class = taint
                if taint_log:
                    self._taint_log.append(taint_log)
                else:
                    warn("Taint is modified but the log entry is not set", stacklevel=2)
                return True
            return False
        elif self._taint_locked:
            return False
        if taint <= self._taint_class:
            return False

        self._taint_class = taint
        context.visitor.modified = True
        if taint_log:
            self._taint_log.append(taint_log)
        else:
            warn("Taint is modified but the log entry is not set", stacklevel=2)
        return True

    def set_safe(self, context: Context) -> bool:
        if self._taint_class != Taints.SAFE:
            self._taint_class = Taints.SAFE
            context.visitor.modified = True
            return True
        else:
            return False

    def mark_as_sink(self, context: Context):
        log = TaintLog(
            path=context.visitor.path,
            line_no=context.node.line_no,
            message="AST node marked as sink using semantic rules"
        )
        self.tags.add("taint_sink")
        self._taint_log.append(log)

    def match(self, other, ctx) -> bool:
        return False


NodeType = typing.NewType(
    "NodeType", typing.Union[ASTNode, typing.Dict, typing.List, int, str]
)


@dataclass
class Module(ASTNode):
    body: typing.List[NodeType, ...]

    def _visit_node(self, context: Context):
        for idx, x in enumerate(self.body):
            context.visit_child(
                node = x,
                replace = partial(self.__replace_body, idx=idx, visitor=context.visitor),
                closure = self
            )

    def __replace_body(self, value: NodeType, idx: int, visitor):
        self.body[idx] = value
        visitor.modified = True

    def __getitem__(self, item) -> NodeType:
        return self.body[item]

    @property
    def json(self):
        d = super().json
        d["body"] = self.body
        return d


@dataclass
class Constant(ASTNode):
    value: NodeType

    def _visit_node(self, context: Context):
        context.visit_child(
            node = self.value,
            replace = partial(self.__replace_value, visitor=context.visitor)
        )

    def __replace_value(self, value, visitor):
        self.value = value
        visitor.modified = True

    def __post_init__(self):
        super().__post_init__()
        self._taint_class = Taints.SAFE

    def __str__(self):
        if type(self.value) in (str, String, bool, Dictionary, dict):
            return str(self.value)
        elif self.value == ...:
            return "..."
        else:
            raise ValueError(f"Incompatible value type: {repr(type(self.value))}")

    def __int__(self):
        if type(self.value) in (int, Number):
            return int(self.value)
        else:
            raise ValueError(f"Incompatible value type: {repr(type(self.value))}")

    def match(self, other, ctx) -> bool:
        if type(other) != Constant:
            return False
        if other.value != self.value:
            return False
        return True


@dataclass
class Dictionary(ASTNode):  # TODO: implement methods from ASTNode
    keys: list
    values: list

    def _visit_node(self, context):
        for idx, key in enumerate(self.keys):
            context.visit_child(
                node=key,
                replace=partial(self.__replace_key, idx=idx, visitor=context.visitor),
            )

        for idx, value in enumerate(self.values):
            if isinstance(value, str) and value in context.stack:
                value = context.stack[value]
                self.values[idx] = value

            context.visit_child(
                node=value,
                replace=partial(self.__replace_value, idx=idx, visitor=context.visitor),
            )

    def __replace_key(self, value, idx, visitor):
        visitor.modified = True
        self.keys[idx] = value

    def __replace_value(self, value, idx, visitor):
        visitor.modified = True
        self.values[idx] = value

    @property
    def json(self):
        d = super().json
        d["items"] = list(zip(self.keys, self.values))
        return d

    def to_dict(self):
        return dict(zip(self.keys, self.values))

    def __str__(self):
        return str(self.to_dict())


@dataclass
class Number(ASTNode):
    value: int

    def __int__(self):
        return self.value

    def _visit_node(self, context: Context):
        if type(self.value) == dict:
            context.visit_child(
                node = self.value,
                replace=partial(self.__replace_value, visitor=context.visitor)
            )

    def __replace_value(self, value, visitor):
        self.value = value
        visitor.modified = True

    def __post_init__(self):
        super().__post_init__()
        self._taint_class = Taints.SAFE


@dataclass
class String(ASTNode):
    value: str

    def __post_init__(self):
        super().__post_init__()
        self._taint_class = Taints.SAFE

    def __add__(self, other):
        if isinstance(other, String):
            new_str = self.value + other.value
            return String(value=new_str)
        else:
            raise exceptions.ASTNodeRewrite(f"Can't add String and `{type(other)}`")

    def __mul__(self, other):
        if isinstance(other, int):
            return String(value=self.value * other)
        else:
            raise exceptions.ASTNodeRewrite(
                f"Can't multiply String and `{type(other)}`"
            )

    def __str__(self):
        return str(self.value)

    def __bytes__(self):
        return self.value.encode("utf-8")

    def __len__(self):
        return len(str(self))

    def __hash__(self):
        return hash(self.value)

    def _visit_node(self, context: Context):
        pass

    @property
    def json(self):
        d = super().json
        d["value"] = self.value
        return d

    def match(self, other, ctx) -> bool:
        if type(other) not in (str, String):
            return False

        return str(self) == str(other)


@dataclass
class Bytes(ASTNode):
    value: bytes

    def __post_init__(self):
        super().__post_init__()

        if type(self.value) == str:
            self.value = self.value.encode()

    def _visit_node(self, context: Context):
        pass

    def __str__(self):

        try:
            return self.value.decode()
        except UnicodeDecodeError:
            encoding = chardet.detect(self.value)["encoding"]
            return self.value.decode(encoding)

    def __bytes__(self):
        return self.value

    @property
    def json(self):
        d = super().json
        d["value"] = self.value
        return d


@dataclass
class List(ASTNode):
    elts: typing.List[ASTNode]
    ctx: ASTNode

    def _visit_node(self, context):
        for idx, e in enumerate(self.elts):
            context.visit_child(
                node=e,
                replace=partial(self.__replace_elt, idx=idx, visitor=context.visitor),
            )

    def __replace_elt(self, value, idx, visitor):
        self.elts[idx] = value
        visitor.modified = True

    @property
    def json(self):
        d = super().json
        d["elts"] = self.elts
        d["ctx"] = self.ctx
        return d


@dataclass
class Var(ASTNode):
    var_name: str
    value: typing.Union[NodeType, None] = None
    var_type: str = "assign"
    typing = None

    def __repr__(self):
        if self.value:
            return f"Var({repr(self.var_name)} = {repr(self.value)})"

        return f"Var({repr(self.var_name), repr(self.value), repr(self.var_type)})"  # FIXME other cases

    def __hash__(self):
        return hash(self.var_name)

    def name(self):
        return self.var_name

    @property
    def full_name(self):
        if self._full_name:
            return self._full_name
        elif hasattr(self.value, "full_name"):
            return self.value.full_name
        else:
            return self.value

    @property
    def json(self):
        d = super().json
        d["var_name"] = self.var_name
        d["value"] = self.value
        d["var_type"] = self.var_type
        return d

    def _visit_node(self, context):
        if isinstance(self.value, ASTNode) and self.value._taint_class != Taints.UNKNOWN:
            self._taint_class = self.value._taint_class

        if type(self.value) == list and self.value == []:
            self.typing = "list"

        context.visit_child(
            node=self.var_name,
            replace=partial(self.__replace_name, visitor=context.visitor),
        )

        context.visit_child(
            node=self.value,
            replace=partial(self.__replace_value, visitor=context.visitor),
            stack=context.stack.copy(),
        )

        if self.var_type == "assign" and type(self.var_name) == str:
            context.stack[self.var_name] = self

    def __replace_value(self, value, visitor):
        visitor.modified = True
        self.value = value

    def __replace_name(self, value, visitor):
        visitor.modified = True
        self.var_name = value


@dataclass
class Attribute(ASTNode):
    source: NodeType
    attr: str
    action: str

    def __post_init__(self):
        super(Attribute, self).__post_init__()
        self.__original_source = None

    def __repr__(self):
        return f"Attribute({repr(self.source)} . {repr(self.attr)})"

    @property
    def full_name(self):
        if self._full_name is not None:
            return self._full_name
        elif isinstance(self.source, (Attribute, Call, Container, Var)):
            return f"{self.source.full_name}.{self.attr}"
        elif type(self.source) == str:
            return f"{self.source}.{self.attr}"
        return f"{repr(self.source)}.{self.attr}"

    @property
    def json(self):
        d = super().json
        d["source"] = self.source
        d["attr"] = self.attr
        d["action"] = self.action
        return d

    def _visit_node(self, context):
        if type(self.source) != str:
            context.visit_child(
                node=self.source,
                replace=partial(self.__replace_source, visitor=context.visitor),
            )

    def __replace_source(self, value, visitor):
        visitor.modified = True
        self._original = self.source
        self.source = value

    def match(self, other, ctx) -> bool:
        if type(other) != Attribute:
            return False

        return self.cached_full_name == other.cached_full_name


@dataclass
class Compare(ASTNode):
    left: ASTNode
    ops: typing.List[ASTNode]
    comparators: typing.List[ASTNode]
    body: typing.List[ASTNode] = field(default_factory=list)
    orelse: typing.List[ASTNode] = field(default_factory=list)

    def _visit_node(self, context: Context):
        context.visit_child(
            node=self.left,
            replace=partial(self.__replace_left, visitor=context.visitor)
        )

        for idx, b in enumerate(self.body):
            context.visit_child(
                node=b,
                replace=partial(self.__replace_body, idx=idx, visitor=context.visitor)
            )

        for idx, x in enumerate(self.orelse):
            context.visit_child(
                node=x,
                replace=partial(self.__replace_orelse, idx=idx, visitor=context.visitor)
            )

        # TODO: add ops, comparators to children traversal

    @property
    def json(self):
        d = super().json
        d["left"] = self.left
        d["ops"] = self.ops
        d["comparators"] = self.comparators
        return d

    def __replace_left(self, value, visitor):
        visitor.modified = True
        self.left = value

    def __replace_body(self, value, idx, visitor):
        visitor.modified = True
        self.body[idx] = value

    def __replace_orelse(self, value, idx, visitor):
        visitor.modified = True
        self.orelse[idx] = value


@dataclass
class FunctionDef(ASTNode):
    name: str
    args: typing.Any
    body: typing.List[ASTNode]
    decorator_list: typing.List[ASTNode]
    returns: ASTNode

    def __post_init__(self):
        super().__post_init__()
        self.return_nodes = {}

    @property
    def json(self):
        d = super().json
        d["function_name"] = self.name
        d["args"] = self.args
        d["body"] = self.body
        d["decorator_list"] = self.decorator_list
        return d

    @property
    def full_name(self):
        return self.name

    def set_taint(self, *args, **kwargs):
        return self.args.set_taint(*args, **kwargs)

    def get_signature(self):
        return self.args.get_signature()

    def get_flask_routes(self):
        for d in self.decorator_list:  # type: Call
            if not isinstance(d, ASTNode):
                continue
            elif d.full_name != "flask.Flask.route":
                continue

            yield str(d.args[0])

    def _visit_node(self, context):
        context.stack[self.name] = self
        context.call_graph.definitions[self.name] = self
        context.stack.push()

        context.visit_child(
            node=self.args,
            replace=partial(self.__replace_args, visitor=context.visitor),
            closure=self
        )

        for idx, dec, in enumerate(self.decorator_list):
            context.visit_child(
                node=dec,
                replace=partial(
                    self.__replace_decorator, idx=idx, visitor=context.visitor
                ),
            )

        for idx, b in enumerate(self.body):
            context.visit_child(
                node=b,
                replace=partial(self.__replace_body, idx=idx, visitor=context.visitor),
                closure=self
            )

        context.stack.pop()

    def __replace_args(self, value, visitor):
        visitor.modified = True
        self.args = value

    def __replace_body(self, value, idx, visitor):
        visitor.modified = True
        self.body[idx] = value

    def __replace_decorator(self, value, idx, visitor):
        visitor.modified = True
        self.decorator_list[idx] = value


@dataclass
class ClassDef(ASTNode):
    name: str
    body: list
    bases: list = field(default_factory=list)

    def _visit_node(self, context):
        context.stack.push()

        for idx, b in enumerate(self.body):
            context.visit_child(
                node=b,
                replace=partial(self.__replace_body, idx=idx, visitor=context.visitor),
                closure=self
            )

        context.stack.pop()

    def __replace_body(self, value, idx, visitor):
        visitor.modified = True
        self.body[idx] = value

    @property
    def json(self):
        d = super().json
        d["name"] = self.name
        d["body"] = self.body
        d["bases"] = self.bases
        return d

    @property
    def full_name(self):
        return self.name


@dataclass
class Call(ASTNode):
    func: NodeType
    args: list
    kwargs: dict
    taints: dict = field(default_factory=dict)

    def __post_init__(self):
        super().__post_init__()
        self._orig_args = [None] * len(self.args)

    def __repr__(self):
        if len(self.args) == 0 and len(self.kwargs) == 0:
            f_args = ""
        elif self.args and not self.kwargs:
            f_args = f"*{repr(self.args)}"
        elif self.kwargs and not self.args:
            f_args = f"**{repr(self.kwargs)}"
        else:
            f_args = f"*{repr(self.args)}, **{repr(self.kwargs)}"

        return f"Call({repr(self.func)})({f_args})"

    def __hash__(self):
        h = hash((self.full_name, self.line_no,))
        return h

    def _visit_node(self, context: Context):
        if type(self.full_name) == str:
            context.call_graph[self.full_name] = self

        for idx in range(len(self.args)):
            try:
                arg = self.args[idx]
                if type(arg) == str:
                    arg = context.stack[arg]
                    if arg.line_no is None or arg.line_no != self.line_no:
                        self._orig_args[idx] = self.args[idx]
                        self.args[idx] = arg
                        context.visitor.modified = True
            except (TypeError, KeyError):
                pass

            context.visit_child(
                node=self.args[idx],
                replace=partial(self.__replace_arg, idx=idx, visitor=context.visitor),
            )

        for key, value in list(self.kwargs.items()):
            try:
                if type(value) == str:
                    target = context.stack[value]
                    self.kwargs[key] = target
                    context.visitor.modified = True
            except (TypeError, KeyError):
                pass

            context.visit_child(
                node=self.kwargs[key],
                replace=partial(
                    self.__replace_kwargs, key=key, visitor=context.visitor
                ),
            )

        context.visit_child(
            node=self.func,
            replace=partial(self.__replace_func, visitor=context.visitor),
        )

    @property
    def json(self):
        d = super().json
        d["function"] = self.func
        d["args"] = self.args
        d["kwargs"] = self.kwargs
        return d

    @property
    def full_name(self):
        if self._full_name is not None:
            return self._full_name

        if type(self.func) == Container:
            return self.func.full_name

        if type(self._original) == str and type(self.func) == Import:
            self._full_name = self.func.names[self._original]
            return self._full_name

        f_name = getattr(self.func, "full_name", None)

        if f_name is not None:
            return f_name
        else:
            return self.func

    def __replace_arg(self, value, idx, visitor):
        visitor.modified = True
        if isinstance(self.args[idx], str):
            self._orig_args[idx] = self.args[idx]
        self.args[idx] = value

    def __replace_kwargs(self, value, key, visitor):
        visitor.modified = True
        self.kwargs[key] = value

    def __replace_func(self, value, visitor):
        visitor.modified = True
        self._original = self.func
        self.func = value

    def get_signature(
        self, *sig_args, aura_capture_args=None, aura_capture_kwargs=None, **sig_kwargs
    ):
        params = []
        for x in sig_args:
            params.append(
                inspect.Parameter(name=x, kind=inspect.Parameter.POSITIONAL_ONLY)
            )

        for k, v in sig_kwargs.items():
            params.append(
                inspect.Parameter(
                    name=k, default=v, kind=inspect.Parameter.POSITIONAL_OR_KEYWORD
                )
            )

        if aura_capture_args:
            params.append(
                inspect.Parameter(
                    name=aura_capture_args, kind=inspect.Parameter.VAR_POSITIONAL
                )
            )

        if aura_capture_kwargs:
            params.append(
                inspect.Parameter(
                    name=aura_capture_kwargs, kind=inspect.Parameter.VAR_KEYWORD
                )
            )

        return inspect.Signature(parameters=params)

    def apply_signature(
        self, *args, aura_capture_args=None, aura_capture_kwargs=None, **kwargs
    ):
        sig = self.get_signature(
            *args,
            aura_capture_args=aura_capture_args,
            aura_capture_kwargs=aura_capture_kwargs,
            **kwargs,
        )
        return self.bind(sig)

    def bind(self, signature) -> inspect.BoundArguments:
        if isinstance(self.kwargs, Dictionary):
            kw = self.kwargs.to_dict()
        else:
            kw = self.kwargs

        return signature.bind(*self.args, **kw)

    def match(self, other: Call, ctx) -> bool:
        if type(other) != Call:
            return False
        if self.cached_full_name != other.cached_full_name:
            return False

        for x in other.args:
            if (type(x) == Constant and type(x.value) == type(...)) or type(x) == type(...):
                is_wildcard = True
                break
        else:
            is_wildcard = False

        if (not is_wildcard) and len(self.args) != len(other.args):
            return False
        else:
            for idx, arg in enumerate(other.args):
                if len(self.args) < idx:
                    if not ctx.match(arg, self.args[idx]):
                        return False

        for other_kwarg in other.kwargs.keys():
            if other_kwarg not in self.kwargs:
                return False

        for name, val in self.kwargs.items():
            if name not in other.kwargs:
                if is_wildcard:
                    continue
                else:
                    return False

            if not ctx.match(val, other.kwargs[name]):
                return False

        return True


@dataclass
class Arguments(ASTNode):  # TODO: not used yet
    args: typing.List[str]
    vararg: NodeType
    kwonlyargs: typing.List[NodeType]
    kwarg: NodeType
    defaults: typing.List[NodeType]
    kw_defaults: typing.List[NodeType]
    taints: typing.Dict[str, Taints] = field(default_factory=dict)
    taint_logs: typing.Dict[str, list] = field(default_factory=lambda: defaultdict(list))

    def _visit_node(self, context):
        if self.args:
            for x in self.args:
                if type(x) == str:
                    context.stack[x] = Container(name=x, pointer=self)

        # TODO: add to stack other arguments

    @property
    def json(self):
        d = super().json
        d["args"] = self.args
        d["vararg"] = self.vararg
        d["kwonlyargs"] = self.kwonlyargs
        d["kwarg"] = self.kwarg
        d["defaults"] = self.defaults
        d["kw_defaults"] = self.kw_defaults
        d["taints"] = self.taints
        return d

    def get_signature(self):
        params = []  # TODO add defaults
        default_diff = len(self.args) - len(self.defaults)
        for idx, x in enumerate(self.args):
            if type(x) == str:
                if idx >= default_diff:
                    default = self.defaults[idx - default_diff]
                else:
                    default = inspect.Parameter.empty

                params.append(
                    inspect.Parameter(
                        name=x,
                        default=default,
                        kind=inspect.Parameter.POSITIONAL_OR_KEYWORD,
                    )
                )

        if self.vararg:
            params.append(
                inspect.Parameter(
                    name=self.vararg, kind=inspect.Parameter.VAR_POSITIONAL
                )
            )

        default_diff = len(self.kwonlyargs) - len(self.kw_defaults)
        for idx, x in enumerate(self.kwonlyargs):
            if idx >= default_diff:
                default = self.kw_defaults[idx - default_diff]
            else:
                default = inspect.Parameter.empty

            params.append(
                inspect.Parameter(
                    name=x, default=default, kind=inspect.Parameter.KEYWORD_ONLY
                )
            )

        if self.kwarg:
            params.append(
                inspect.Parameter(name=self.kwarg, kind=inspect.Parameter.VAR_KEYWORD)
            )

        return inspect.Signature(parameters=params)

    def set_taint(self, name, taint_level, context, taint_log=None):
        if type(name) == int and name < len(self.args):
            name = self.args[name]

        if not isinstance(name, Hashable):
            return

        if taint_log is None:
            warn("Attempting to modify argument taint but log is not set", stacklevel=2)

        if name in self.taints:
            t = self.taints[name]
            if taint_level > t:
                self.taints[name] = taint_level
                if taint_log:
                    self.taint_logs[name].append(taint_log)
                context.visitor.modified = True
            return
        else:
            self.taints[name] = taint_level
            if taint_log:
                self.taint_logs[name].append(taint_log)
            context.visitor.modified = True

    def to_parameters(self):
        params = []
        offset = len(self.args) - len(self.defaults)
        for idx, arg in enumerate(self.args):
            default = inspect.Parameter.empty

            if idx >= offset:
                default = self.defaults[idx - offset]

            params.append(
                inspect.Parameter(
                    name=arg,
                    kind=inspect.Parameter.POSITIONAL_OR_KEYWORD,
                    default=default,
                )
            )

        if self.vararg is not None:
            params.append(
                inspect.Parameter(
                    name=self.vararg, kind=inspect.Parameter.VAR_POSITIONAL
                )
            )

        offset = len(self.kwonlyargs) - len(self.kw_defaults)
        for idx, kwarg in enumerate(self.kwonlyargs):
            default = inspect.Parameter.empty

            if idx >= offset:
                default = self.kw_defaults[idx - offset]

            params.append(
                inspect.Parameter(
                    name=kwarg, kind=inspect.Parameter.KEYWORD_ONLY, default=default
                )
            )

        if self.kwarg is not None:
            params.append(
                inspect.Parameter(name=self.kwarg, kind=inspect.Parameter.VAR_KEYWORD)
            )

        return params

    def to_signature(self):
        return inspect.Signature(parameters=self.to_parameters())


@dataclass
class Import(ASTNode):
    names: dict = field(default_factory=dict)
    level = None

    def _visit_node(self, context: Context):
        for name, target in self.names.items():
            if name == "*":
                imp_name = target.rstrip(".*")
                context.shared_state.setdefault("wildcard_imports", set()).add(imp_name)

            context.stack[name] = Container(name=name, pointer=self)

    def get_modules(self) -> typing.Iterable[str]:
        m = set(self.names.values())
        return m

    def get_files(self, base: Path) -> typing.Dict[str, Path]:
        imp_files = {}

        for name, target in self.names.items():
            while target.startswith('.'):
                base = base.parent
                target = target[1:]

            mod_name = base / (target + '.py')
            init = base / target / '__init__.py'
            if mod_name.exists():
                imp_files[name] = mod_name
                continue
            elif init.exists():
                imp_files[name] = init
                continue

        return imp_files

    @property
    def full_name(self):
        return None

    @property
    def json(self) -> typing.Dict[str, typing.Any]:
        d: typing.Dict[str, typing.Any] = super().json
        d["names"] = self.names
        if self.level is not None:
            d["level"] = self.level
        return d

    def match(self, other, ctx) -> bool:
        if type(other) == Import:
            self_mods = self.get_modules()

            for m in other.get_modules():
                if m in self_mods:
                    return True
                elif any(x.startswith(m+".") for x in self_mods):
                    return True

        return False


@dataclass
class BinOp(ASTNode):
    op: str
    left: NodeType
    right: NodeType

    def __post_init__(self):
        super().__post_init__()
        self._orig_left = None
        self._orig_right = None

    def _visit_node(self, context):
        context.visit_child(
            node=self.left,
            replace=partial(self.__replace_left, visitor=context.visitor),
        )
        context.visit_child(
            node=self.right,
            replace=partial(self.__replace_right, visitor=context.visitor),
        )

    def __replace_left(self, value, visitor):
        self._orig_left = self.left
        self.left = value
        visitor.modified = True

    def __replace_right(self, value, visitor):
        self._orig_right = self.right
        self.right = value
        visitor.modified = True

    @property
    def json(self):
        d = super().json
        d["op"] = self.op
        d["left"] = self.left
        d["right"] = self.right
        return d


@dataclass
class Print(ASTNode):
    values: typing.List[NodeType]
    dest: typing.Any

    def _visit_node(self, context: Context):
        for idx, x in enumerate(self.values):
            context.visit_child(
                node=x,
                replace=partial(self.__replace_value, idx=idx, visitor=context.visitor)
            )

    def __replace_value(self, value, idx, visitor):
        self.values[idx] = value
        visitor.modified = True

    @property
    def json(self):
        d = super().json
        d["values"] = self.values
        d["dest"] = self.dest
        return d


@dataclass
class ReturnStmt(ASTNode):
    value: NodeType

    def _visit_node(self, context: Context):
        if type(context.scope_closure) == FunctionDef:
            context.scope_closure.return_nodes[self.line_no] = self

        context.visit_child(
            node=self.value,
            replace=partial(self.__replace_value, visitor=context.visitor),
        )

    @property
    def full_name(self):
        return getattr(self.value, "full_name", None)

    @property
    def json(self):
        d = super().json
        d["value"] = self.value
        return d

    def __replace_value(self, value, visitor):
        self.value = value
        visitor.modified = True


@dataclass
class Yield(ReturnStmt):
    pass


@dataclass
class YieldFrom(Yield):
    pass


@dataclass
class Subscript(ASTNode):
    value: ASTNode
    slice: ASTNode
    ctx: str

    def _visit_node(self, context):
        context.visit_child(
            node=self.value,
            replace=partial(self.__replace_value, visitor=context.visitor),
        )
        context.visit_child(
            node=self.slice,
            replace=partial(self.__replace_slice, visitor=context.visitor)
        )

    @property
    def json(self):
        d = super().json
        d["value"] = self.value
        d["slice"] = self.slice
        d["ctx"] = self.ctx
        return d

    def __replace_value(self, value, visitor):
        self.value = value
        visitor.modified = True

    def __replace_slice(self, value, visitor):
        self.slice = value
        visitor.modified = True


@dataclass
class Continue(ASTNode):
    def __post_init__(self):
        super(Continue, self).__post_init__()
        self._taint_class = Taints.SAFE
        self._taint_locked = True

    def _visit_node(self, context: Context):
        pass


@dataclass
class Pass(ASTNode):
    def __post_init__(self):
        super(Pass, self).__post_init__()
        self._taint_class = Taints.SAFE
        self._taint_locked = True

    def _visit_node(self, context: Context):
        pass


@dataclass
class ExceptHandler(ASTNode):
    body: list
    type: List
    name: typing.Union[str, None] = None

    def _visit_node(self, context):
        for idx, expr in enumerate(self.body):
            context.visit_child(
                node=expr,
                replace=partial(self.__replace_body, idx=idx, visitor=context.visitor),
            )

    @property
    def json(self):
        d = super().json
        d["name"] = self.name
        d["body"] = self.body
        d["type"] = self.type
        return d

    def __replace_body(self, value, idx, visitor):
        self.body[idx] = value
        visitor.modified = True


@dataclass
class Container(ASTNode):
    name: str
    pointer: ASTNode

    def _visit_node(self, context):
        self.pointer._visit_node(context)

    @property
    def _taint_class(self) -> Taints:
        if type(self.pointer) == Arguments:
            return self.pointer.taints.get(self.name, Taints.UNKNOWN)
        else:
            return self.pointer._taint_class

    @_taint_class.setter
    def _taint_class(self, value):
        pass

    @property
    def json(self):
        d = super().json
        d["name"] = self.name
        d["pointer"] = self.pointer
        return d

    @property
    def full_name(self):
        if type(self.pointer) == Import:
            return self.pointer.names[self.name]
        else:
            return self.name



@slotted_dataclass(
    replace=field(default=lambda x: None),
    visitor=field(default=None),
    stack=field(default_factory=Stack),
    depth=field(default=0),
    modified=field(default=False),
    shared_state=field(default_factory=dict),
    scope_closure=field(default=None)
)
class Context:
    __slots__ = (
        "node", "parent", "replace",
        "visitor", "stack", "depth",
        "modified", "shared_state", "scope_closure"
    )

    node: NodeType
    parent: typing.Union[Context, None]
    # can_replace: bool = True
    replace: typing.Callable[[NodeType], None]
    visitor: typing.Any # FIXME typing
    stack: Stack
    depth: int
    modified: bool
    shared_state: dict
    scope_closure: typing.Optional[ASTNode]

    @property
    def call_graph(self):
        return self.visitor.call_graph

    @property
    def signature(self) -> str:
        return f"{self.visitor.normalized_path}:{self.node.line_no}"

    def as_child(self, node: NodeType, replace=lambda x: None) -> Context:
        return Context(
            parent=self,
            node=node,
            depth=self.depth + 1,
            visitor=self.visitor,
            replace=replace,
            stack=self.stack,
            shared_state=self.shared_state,
            scope_closure=self.scope_closure
        )

    def visit_child(self, node, stack=None, replace=lambda x: None, closure=None):
        if type(node) in (str, int, type(...)) or node is None or node == ...:
            return

        new_context = self.as_child(node, replace=replace)
        if stack is not None:
            new_context.stack = stack
        if closure is not None:
            new_context.scope_closure = closure
        new_context.visitor.push(new_context)


def to_json(element):
    if not isinstance(element, ASTNode):
        return element

    output = element.json
    if type(output) == dict:
        return {k: to_json(v) for k, v in output.items()}
    elif type(output) in (list, tuple):
        return [to_json(x) for x in output]
    else:
        return output
