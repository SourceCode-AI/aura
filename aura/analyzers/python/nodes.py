"""
This module contains wrappers for parsed AST nodes
"""
from __future__ import annotations

import typing
import inspect
from enum import Enum
from dataclasses import dataclass, InitVar, field
from functools import partial, total_ordering

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
        if not isinstance(other, Taints):
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



class ASTNode(object):
    def __post_init__(self, *args, **kwargs):
        self._full_name = None
        self._original = None
        self._docs = None
        self.line_no = None
        self.col = None
        self.tags = set()
        self._hash = None
        self._taint_class = Taints.UNKNOWN

    @property
    def full_name(self):
        return self._full_name

    @property
    def json(self):
        data = {
            'AST_Type': self.__class__.__name__,
        }
        if self.full_name is not None:
            data['full_name'] = self.full_name
        if self.tags:
            data['tags'] = list(self.tags)
        if self.line_no is not None:
            data['line_no'] = self.line_no

        if self._taint_class != Taints.UNKNOWN:
            data['taint'] = self._taint_class.name

        return data

    def _visit_node(self, context):
        pass

    def pprint(self):
        from pprint import pprint as pp
        pp(to_json(self))


NodeType = typing.NewType(
    "NodeType",
    typing.Union[ASTNode, typing.Dict, typing.List, int, str]
)


@dataclass
class Dictionary(ASTNode):  # TODO: implement methods from ASTNode
    keys: list
    values: list

    def _visit_node(self, context):
        for idx, key in enumerate(self.keys):
            context.visit_child(
                node = key,
                replace = partial(self.__replace_key, idx=idx, visitor=context.visitor)
            )

        for idx, value in enumerate(self.values):
            if isinstance(value, str) and value in context.stack:
                value = context.stack[value]
                self.values[idx] = value

            context.visit_child(
                node = value,
                replace = partial(self.__replace_value, idx=idx, visitor=context.visitor)
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
        d['items'] = list(zip(self.keys, self.values))
        return d

    def to_dict(self):
        return dict(zip(self.keys, self.values))


@dataclass
class Number(ASTNode):
    value: int

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
            return String(value=self.value*other)
        else:
            raise exceptions.ASTNodeRewrite(f"Can't multiply String and `{type(other)}`")

    def __str__(self):
        return str(self.value)

    @property
    def json(self):
        d = super().json
        d['value'] = self.value
        return d


@dataclass
class Var(ASTNode):
    var_name: str
    value: NodeType = None
    var_type: str = "assign"

    def __repr__(self):
        if self.value:
            return f"Var({repr(self.var_name)} = {repr(self.value)})"

        return f"Var({repr(self.var_name), repr(self.value), repr(self.var_type)})" # FIXME other cases

    def __hash__(self):
        return hash(self.var_name)

    def name(self):
        return self.var_name

    @property
    def full_name(self):
        if self._full_name:
            return self._full_name
        elif hasattr(self.value, 'full_name'):
            return self.value.full_name
        else:
            return self.value

    @property
    def json(self):
        d = super().json
        d['var_name'] = self.var_name
        d['value'] = self.value
        d['var_type'] = self.var_type
        return d

    def _visit_node(self, context):
        context.visit_child(
            node = self.var_name,
            replace = partial(self.__replace_name, visitor=context.visitor)
        )

        context.visit_child(
            node = self.value,
            replace = partial(self.__replace_value, visitor=context.visitor),
            stack = context.stack.copy()
        )

        if self.var_type == 'assign' and isinstance(self.var_name, str):
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
        if isinstance(self.source, Import):
            return f"{self.source.names[self._original]}.{self.attr}"
        elif isinstance(self.source, (Attribute, Call)):
                return f"{self.source.full_name}.{self.attr}"
        elif isinstance(self.source, str):
            return f"{self.source}.{self.attr}"
        return f"{repr(self.source)}.{self.attr}"

    @property
    def json(self):
        d = super().json
        d['source'] = self.source
        d['attr'] = self.attr
        d['action'] = self.action
        return d

    def _visit_node(self, context):
        if isinstance(self.source, str):
            try:
                target = context.stack[self.source]
                self._original = self.source
                if isinstance(target, Var) and target.var_type == 'assign' and target.line_no != self.line_no:
                    self.source = target.value
                else:
                    self.source = target
                context.visitor.modified = True
            except (KeyError, TypeError):
                #context.node.pprint()
                #print(context.stack.frame.variables)
                pass

        context.visit_child(
            node = self.source,
            replace = partial(self.__replace_source, visitor=context.visitor)
        )

    def __replace_source(self, value, visitor):
        visitor.modified = True
        self._original = self.source
        self.source = value


@dataclass
class Compare(ASTNode):
    left: str
    ops: typing.List[ASTNode]
    comparators: typing.List[ASTNode]

    @property
    def json(self):
        d = super().json
        d['left'] = self.left
        d['ops'] = self.ops
        d['comparators'] = self.comparators
        return d


@dataclass
class FunctionDef(ASTNode):
    name: str
    args: typing.Any
    body: typing.List[ASTNode]
    decorator_list: typing.List[ASTNode]
    returns: ASTNode

    @property
    def json(self):
        d = super().json
        d['function_name'] = self.name
        d['args'] = self.args
        d['body'] = self.body
        d['decorator_list'] = self.decorator_list
        return d

    @property
    def full_name(self):
        return self.name

    def set_taint(self, *args, **kwargs):
        return self.args.set_taint(*args, **kwargs)

    def _visit_node(self, context):
        context.stack[self.name] = self
        context.call_graph.definitions[self.name] = self
        context.stack.push()
        #context.stack = context.stack.copy()

        context.visit_child(
            node = self.args,
            replace = partial(self.__replace_args, visitor=context.visitor)
        )

        for idx, dec, in enumerate(self.decorator_list):
            context.visit_child(
                node=dec,
                replace = partial(self.__replace_decorator, idx=idx, visitor=context.visitor)
            )

        for idx, b in enumerate(self.body):
            context.visit_child(
                node = b,
                replace = partial(self.__replace_body, idx=idx, visitor=context.visitor)
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
    bases:list = field(default_factory=list)

    def _visit_node(self, context):
        context.stack.push()

        for idx, b in enumerate(self.body):
            context.visit_child(
                node = b,
                replace = partial(self.__replace_body, idx=idx, visitor=context.visitor)
            )

        context.stack.pop()

    def __replace_body(self, value, idx, visitor):
        visitor.modified = True
        self.body[idx] = value

    @property
    def json(self):
        d = super().json
        d['name'] = self.name
        d['body'] = self.body
        d['bases'] = self.bases
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
        h = hash((
            self.full_name,
            self.line_no,
        ))
        return h

    def _visit_node(self, context: Context):
        if isinstance(self.full_name, str):
            context.call_graph[self.full_name] = self

        for idx in range(len(self.args)):
            try:
                arg = self.args[idx]
                if isinstance(arg, str):
                    arg = context.stack[arg]
                    if arg.line_no != self.line_no:
                        self.args[idx] = arg
                        context.visitor.modified = True
            except (TypeError, KeyError):
                pass

            context.visit_child(
                node = self.args[idx],
                replace = partial(self.__replace_arg, idx=idx, visitor=context.visitor)
            )

        for key in list(self.kwargs.keys()):
            context.visit_child(
                node = self.kwargs[key],
                replace = partial(self.__replace_kwargs, key=key, visitor=context.visitor)
            )

        # Replace call to functions by their targets from defined variables, e.g.
        # x = open
        # x("test.txt") will be replaced to open("test.txt")
        try:
            if isinstance(self.func, Var):
                source = self._full_name
            else:
                source = self.func

            target = context.stack[source]
            if isinstance(target, Import):
                name = target.names[source]
            else:
                name = target.full_name
            if isinstance(name, str) and self._full_name != name and target.line_no != self.line_no:
                self._full_name = name
                context.visitor.modified = True
        except (TypeError, KeyError, AttributeError):
            pass

        context.visit_child(
            node = self.func,
            replace = partial(self.__replace_func, visitor=context.visitor),
        )

    @property
    def json(self):
        d = super().json
        d['function'] = self.func
        d['args'] = self.args
        d['kwargs'] = self.kwargs
        return d

    @property
    def full_name(self):
        if self._full_name is not None:
            return self._full_name

        f_name = getattr(self.func, 'full_name', None)
        if isinstance(self._original, str) and isinstance(self.func, Import):
            return self.func.names[self._original]
        elif f_name is not None:
            return f_name
        else:
            return self.func

    def __replace_arg(self, value, idx, visitor):
        visitor.modified = True
        self.args[idx] = value

    def __replace_kwargs(self, value, key, visitor):
        visitor.modified = True
        self.kwargs[key] = value

    def __replace_func(self, value, visitor):
        visitor.modified = True
        self._original = self.func
        self.func = value

    def get_signature(
            self,
            *sig_args,
            aura_capture_args=None,
            aura_capture_kwargs=None,
            **sig_kwargs
    ):
        params = []
        for x in sig_args:
            params.append(
                inspect.Parameter(name=x, kind=inspect.Parameter.POSITIONAL_ONLY)
            )

        for k, v in sig_kwargs.items():
            params.append(
                inspect.Parameter(name=k, default=v, kind=inspect.Parameter.POSITIONAL_OR_KEYWORD)
            )

        if aura_capture_kwargs:
            params.append(
                inspect.Parameter(name=aura_capture_kwargs, kind=inspect.Parameter.VAR_KEYWORD)
            )

        return inspect.Signature(parameters=params)

    def apply_signature(
            self,
            *args,
            aura_capture_args = None,
            aura_capture_kwargs=None,
            **kwargs
    ):
        sig = self.get_signature(
            *args,
            aura_capture_args = aura_capture_args,
            aura_capture_kwargs = aura_capture_kwargs,
            **kwargs
        )
        return self.bind(sig)

    def bind(self, signature):
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

    def _visit_node(self, context):
        if self.args:
            for x in self.args:
                context.stack[x] = self

        # TODO: add to stack other arguments

    @property
    def json(self):
        d = super().json
        d['args'] = self.args
        d['vararg'] = self.vararg
        d['kwonlyargs'] = self.kwonlyargs
        d['kwarg'] = self.kwarg
        d['defaults'] = self.defaults
        d['kw_defaults'] = self.kw_defaults
        d['taints'] = self.taints
        return d

    def set_taint(self, name, taint_level, context):
        if name in self.taints:
            t = self.taints[name]
            if taint_level > t:
                self.taints[name] = taint_level
                context.visitor.modified = True
            return
        else:
            self.taints[name] = taint_level
            context.visitor.modified = True

    def to_parameters(self):
        params = []
        offset = len(self.args) - len(self.defaults)
        for idx, arg in enumerate(self.args):
            default = inspect.Parameter.empty

            if idx >= offset:
                default = self.defaults[idx-offset]

            params.append(inspect.Parameter(
                name = arg,
                kind = inspect.Parameter.POSITIONAL_OR_KEYWORD,
                default = default
            ))

        if self.vararg is not None:
            params.append(inspect.Parameter(
                name = self.vararg,
                kind = inspect.Parameter.VAR_POSITIONAL
            ))

        offset = len(self.kwonlyargs) - len(self.kw_defaults)
        for idx, kwarg in enumerate(self.kwonlyargs):
            default = inspect.Parameter.empty

            if idx >= offset:
                default = self.kw_defaults[idx - offset]

            params.append(inspect.Parameter(
                name = kwarg,
                kind = inspect.Parameter.KEYWORD_ONLY,
                default = default
            ))

        if self.kwarg is not None:
            params.append(inspect.Parameter(
                name = self.kwarg,
                kind = inspect.Parameter.VAR_KEYWORD
            ))

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

    @property
    def full_name(self):
        return None
    @property
    def json(self):
        d = super().json
        d['names'] = self.names
        if self.level is not None:
            d['level'] = self.level
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
            node = self.left,
            replace = partial(self.__replace_left, visitor=context.visitor)
        )
        context.visit_child(
            node = self.right,
            replace = partial(self.__replace_right, visitor=context.visitor)
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
        d['op'] = self.op
        d['left'] = self.left
        d['right'] = self.right
        return d

@dataclass
class Print(ASTNode):
    values: typing.List[NodeType]
    dest: typing.Any

    @property
    def json(self):
        d = super().json
        d['values'] = self.values
        d['dest'] = self.dest
        return d


@dataclass
class ReturnStmt(ASTNode):
    value: NodeType

    def _visit_node(self, context):
        try:
            if isinstance(self.value, str):
                target = context.stack[self.value]
                self.value = target
                context.visitor.modified = True
        except (TypeError, KeyError):
            pass

        context.visit_child(
            node = self.value,
            replace = partial(self.__replace_value, visitor=context.visitor)
        )

    @property
    def json(self):
        d = super().json
        d['value'] = self.value
        return d

    def __replace_value(self, value, visitor):
        self.value = value
        visitor.modified = True


@dataclass
class Subscript(ASTNode):
    value: ASTNode
    slice: ASTNode
    ctx: str

    def _visit_node(self, context):
        context.visit_child(
            node = self.value,
            replace = partial(self.__replace_value, visitor=context.visitor)
        )

    @property
    def json(self):
        d = super().json
        d['value'] = self.value
        d['slice'] = self.slice
        d['ctx'] = self.ctx
        return d

    def __replace_value(self, value, visitor):
        self.value = value
        visitor.modified = True


@dataclass
class Context:
    node: NodeType
    parent: Context
    # can_replace: bool = True
    replace: typing.Callable[[NodeType], None] = lambda x: None
    visitor: typing.Any = None  # FIXME typing
    stack: Stack = field(default_factory=Stack)
    depth: int = 0
    modified: bool = False
    call_graph: dict = field(default_factory=CallGraph)


    def as_child(self, node:NodeType, replace=lambda x: None) -> Context:
        return self.__class__(
            parent = self,
            node = node,
            depth = self.depth + 1,
            visitor = self.visitor,
            replace = replace,
            stack = self.stack,
            call_graph=self.call_graph,
        )

    def visit_child(self, stack=None, *args, **kwargs):
        new_context = self.as_child(*args, **kwargs)
        if stack is not None:
            new_context.stack = stack
        new_context.visitor.queue.append(new_context)


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
