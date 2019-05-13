"""
This module contains wrappers for parsed AST nodes
"""
from __future__ import annotations

import typing
from dataclasses import dataclass, InitVar
from functools import partial

from ... import exceptions


BASIC_ELEMENTS = (
    str,
    int,
)


class ASTNode(object):
    def __post_init__(self, *args, **kwargs):
        self._full_name = None
        self._original = None
        self._docs = None
        self.line_no = None
        self.tags = set()
        self._hash = None

    @property
    def full_name(self):
        return self._full_name

    @property
    def is_static(self):
        """
        Return true if the AST node is a purely static structure
        Examples: numbers, strings, None
        E.g. it is not/does not contain a variable or some function calls that depends on variable input
        :return:
        """
        return False

    def _visit_node(self, context):
        pass


NodeType = typing.NewType(
    "NodeType",
    typing.Union[ASTNode, typing.Dict, typing.List, int, str]
)


@dataclass
class Dictionary(ASTNode):  # TODO: implement methods from ASTNode
    keys: list
    values: list

    @property
    def is_static(self):
        for x in self.keys:
            if isinstance(x, BASIC_ELEMENTS):
                continue
            elif not x.is_static:
                return False
        for x in self.values:
            if isinstance(x, BASIC_ELEMENTS):
                continue
            elif not x.is_static:
                return False
        return True


@dataclass
class Number(ASTNode):
    value: int

    @property
    def is_static(self):
        return True


@dataclass
class String(ASTNode):
    value: str

    @property
    def is_static(self):
        return True

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

@dataclass
class Var(ASTNode):
    var_name: str
    value: NodeType = None
    var_type: str = "assign"

    allow_lookup: InitVar[bool] = True

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
        elif hasattr(self.value, 'fullname'):
            return self.value.fullname
        else:
            return self.value

    def _visit_node(self, context):
        context.visit_child(
            node = self.var_name,
            replace = partial(self.__replace_name, visitor=context.visitor)
        )

        context.visit_child(
            node = self.value,
            replace = partial(self.__replace_value, visitor=context.visitor)
        )

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

    def _visit_node(self, context):
        context.visit_child(
            node = self.source,
            replace = partial(self.__replace_source, visitor=context.visitor)
        )

    def __replace_source(self, value, visitor):
        visitor.modified = True
        self.source = value


@dataclass
class Call(ASTNode):
    func: NodeType
    args: list
    kwargs: dict

    signature: InitVar = None

    def __repr__(self):
        if len(self.args) == 0 and len(self.kwargs) == 0:
            f_args = ""
        elif self.args and not self.kwargs:
            f_args = f"*{repr(self.args)}"
        elif self.kwargs and not self.args:
            f_args = f"**{repr(self.kwargs)}"
        else:
            f_args = f"*{repr(self.args)}, **{repr(self.kwargs)}"

        return f"Call({repr(self.full_name)})({f_args})"

    def _visit_node(self, context: Context):
        for idx in range(len(self.args)):
            context.visit_child(
                node = self.args[idx],
                replace = partial(self.__replace_arg, idx=idx, visitor=context.visitor)
            )

        for key in list(self.kwargs.keys()):
            context.visit_child(
                node = self.kwargs[key],
                replace = partial(self.__replace_kwargs, key=key, visitor=context.visitor)
            )

        context.visit_child(
            node = self.func,
            replace = partial(self.__replace_func, visitor=context.visitor),
        )

    @property
    def full_name(self):
        if self._full_name is not None:
            return self._full_name

        f_name = getattr(self.func, 'full_name', None)
        if f_name is not None:
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
        self.func = value

    def get_arg(self, index, default=None):
        pass


@dataclass
class Import(ASTNode):
    module: str
    alias: str
    import_type: str = 'import' # Or could be 'from'

    allow_lookup: InitVar[bool] = True

    def name(self):
        return self.alias

    @property
    def full_name(self):
        return self.module


@dataclass
class BinOp(ASTNode):
    op: str
    left: NodeType
    right: NodeType

    @property
    def is_static(self):
        return self.left.is_static and self.right.is_static


@dataclass
class Print(ASTNode):
    values: typing.List[NodeType]
    dest: typing.Any


@dataclass
class Context:
    node: NodeType
    parent: NodeType
    # can_replace: bool = True
    replace: typing.Callable[[NodeType], None] = lambda x: None
    visitor: typing.Any = None  # FIXME typing
    depth: int = 0
    modified: bool = False

    def as_child(self, node:NodeType, replace=lambda x: None) -> Context:
        return self.__class__(
            parent = self,
            node = node,
            depth = self.depth + 1,
            visitor = self.visitor,
            replace = replace
        )

    def visit_child(self, *args, **kwargs):
        new_context = self.as_child(*args, **kwargs)
        new_context.visitor.queue.append(new_context)
