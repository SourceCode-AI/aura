"""
This module contains wrappers for parsed AST nodes
"""
from __future__ import annotations

import os
import typing
import inspect
import weakref
from abc import ABCMeta, abstractmethod
from enum import Enum
from pathlib import Path
from warnings import warn
from collections import defaultdict
from collections.abc import Hashable
from dataclasses import dataclass, InitVar, field
from functools import partial, total_ordering, wraps

from ...stack import Stack, CallGraph
from ... import exceptions


BASIC_ELEMENTS = (
    str,
    int,
)

@total_ordering
class Taints(Enum):
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
        if self == Taints.TAINTED or other == Taints.TAINTED:
            return Taints.TAINTED

        if self == Taints.UNKNOWN or other == Taints.UNKNOWN:
            return Taints.UNKNOWN

        return self


@dataclass
class TaintLog:
    """
    Log entry to track the propagation of taints in the AST
    """
    path: Path  # Path to the affected source code
    taint_level: Taints = None
    line_no: int = None
    message: str = None
    extra: dict = field(default_factory=dict)
    node: NodeType = None

    def __post_init__(self):
        self.path = Path(self.path).absolute()

    def json(self):
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


class KeepRefs:
    """
    A class that would keep references to all created instances
    https://stackoverflow.com/questions/328851/printing-all-instances-of-a-class
    """
    __refs__ = defaultdict(list)

    def __init__(self):
        super(KeepRefs, self).__init__()
        self.__refs__[self.__class__].append(weakref.ref(self))

    @classmethod
    def get_instances(cls):
        for inst_ref in cls.__refs__[cls]:
            inst = inst_ref()
            if inst is not None:
                yield inst


class ASTNode(KeepRefs, metaclass=ABCMeta):
    def __post_init__(self, *args, **kwargs):
        self._full_name = None
        self._original = None
        self._docs = None
        self.line_no = None
        self.col = None
        self.tags = set()
        self._hash = None
        self._taint_class: Taints = Taints.UNKNOWN
        self._taint_locked: bool = False
        self._taint_log: typing.List[TaintLog] = []

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
    def json(self):
        data = {
            "AST_Type": self.__class__.__name__,
        }
        if self.full_name is not None:
            data["full_name"] = self.full_name
        if self.tags:
            data["tags"] = list(self.tags)
        if self.line_no is not None:
            data["line_no"] = self.line_no

        if self._taint_class != Taints.UNKNOWN:
            data["taint"] = self._taint_class.name

        if self._taint_log:
            data['taint_log'] = [x.json() for x in self._taint_log]

        return data

    @abstractmethod
    def _visit_node(self, context: Context):
        return NotImplemented

    def pprint(self):
        from pprint import pprint as pp

        pp(to_json(self))

    def add_taint(self, taint: Taints, context: Context, lock=False, taint_log=None) -> bool:
        """
        Assign a taint to the node
        Operation is ignored if the current taint is already higher or equal
        return True if the taint was modified (increased)
        """
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


NodeType = typing.NewType(
    "NodeType", typing.Union[ASTNode, typing.Dict, typing.List, int, str]
)


@dataclass
class Dictionary(ASTNode):  #  TODO: implement methods from ASTNode
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


@dataclass
class Number(ASTNode):
    value: int

    def _visit_node(self, context: Context):
        pass

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

    def _visit_node(self, context: Context):
        pass

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
        if isinstance(self.value, list) and self.value == []:
            self.typing = "list"
        elif isinstance(self.value, str):
            try:
                target = context.stack[self.value]
                self._original = self.value
                self.value = target
                context.visitor.modified = True
            except (TypeError, KeyError):
                pass
        elif isinstance(self.value, Arguments) and self._original in self.value.taints:
            new_taint = self.value.taints[self._original]
            log = TaintLog(
                path=context.visitor.normalized_path,
                taint_level=new_taint,
                message="Taint propagated via the variable that is pointing to an argument",
                node=self.value,
                line_no=self.line_no
            )
            self.add_taint(new_taint, context=context, taint_log=log)

        context.visit_child(
            node=self.var_name,
            replace=partial(self.__replace_name, visitor=context.visitor),
        )

        context.visit_child(
            node=self.value,
            replace=partial(self.__replace_value, visitor=context.visitor),
            stack=context.stack.copy(),
        )

        if self.var_type == "assign" and isinstance(self.var_name, str):
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

    def __repr__(self):
        return f"Attribute({repr(self.source)} . {repr(self.attr)})"

    @property
    def full_name(self):
        if self._full_name is not None:
            return self._full_name

        if isinstance(self.source, Import):
            self._full_name = f"{self.source.names[self._original]}.{self.attr}"
            return self._full_name
        elif isinstance(self.source, (Attribute, Call)):
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
        if isinstance(self.source, str):
            try:
                target = context.stack[self.source]
                self._original = self.source
                if (
                    isinstance(target, Var)
                    and target.var_type == "assign"
                    and target.line_no != self.line_no
                ):
                    self.source = target.value
                else:
                    self.source = target
                context.visitor.modified = True
            except (KeyError, TypeError):
                # context.node.pprint()
                # print(context.stack.frame.variables)
                pass

        context.visit_child(
            node=self.source,
            replace=partial(self.__replace_source, visitor=context.visitor),
        )

    def __replace_source(self, value, visitor):
        visitor.modified = True
        self._original = self.source
        self.source = value


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
        # context.stack = context.stack.copy()

        context.visit_child(
            node=self.args,
            replace=partial(self.__replace_args, visitor=context.visitor),
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
                    if arg.line_no != self.line_no:
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

        if aura_capture_args:
            params.append(
                inspect.Parameter(
                    name=aura_capture_args, kind=inspect.Parameter.VAR_POSITIONAL
                )
            )

        for k, v in sig_kwargs.items():
            params.append(
                inspect.Parameter(
                    name=k, default=v, kind=inspect.Parameter.POSITIONAL_OR_KEYWORD
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
                if isinstance(x, str):
                    context.stack[x] = self

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
            if isinstance(x, str):
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

    def _visit_node(self, context):
        for name, target in self.names.items():
            context.stack[name] = self

    def get_modules(self) -> typing.List[str]:
        m = list(self.names.values())
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
    def json(self):
        d = super().json
        d["names"] = self.names
        if self.level is not None:
            d["level"] = self.level
        return d


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
        try:
            if isinstance(self.left, str) and self.left in context.stack:
                self._orig_left = self.left
                self.left = context.stack[self.left]
                context.visitor.modified = True
        except (TypeError, KeyError):
            pass

        try:
            if isinstance(self.right, str) and self.right in context.stack:
                self._orig_right = self.right
                self.right = context.stack[self.right]
                context.visitor.modified = True
        except (TypeError, KeyError):
            pass

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
        pass  # TODO

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
        parent = context.parent
        while parent:
            if isinstance(parent.node, FunctionDef):
                parent.node.return_nodes[self.line_no] = self
                break
            parent = parent.parent

        try:
            if isinstance(self.value, str):
                target = context.stack[self.value]
                self.value = target
                context.visitor.modified = True
        except (TypeError, KeyError):
            pass

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
class Context:
    node: NodeType
    parent: typing.Union[Context, None]
    # can_replace: bool = True
    replace: typing.Callable[[NodeType], None] = lambda x: None
    visitor: typing.Any = None  # FIXME typing
    stack: Stack = field(default_factory=Stack)
    depth: int = 0
    modified: bool = False

    @property
    def call_graph(self):
        return self.visitor.call_graph

    def as_child(self, node: NodeType, replace=lambda x: None) -> Context:
        return self.__class__(
            parent=self,
            node=node,
            depth=self.depth + 1,
            visitor=self.visitor,
            replace=replace,
            stack=self.stack,
        )

    def visit_child(self, stack=None, *args, **kwargs):
        new_context = self.as_child(*args, **kwargs)
        if stack is not None:
            new_context.stack = stack
        new_context.visitor.push(new_context)


def to_json(element):
    if not isinstance(element, ASTNode):
        return element

    output = element.json
    if isinstance(output, dict):
        return {k: to_json(v) for k, v in output.items()}
    elif isinstance(output, (list, tuple)):
        return [to_json(x) for x in output]
    else:
        return output
