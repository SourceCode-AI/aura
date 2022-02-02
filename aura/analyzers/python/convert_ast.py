from typing import Optional, Union
from collections import OrderedDict

from .visitor import Visitor
from .nodes import *
from ... import tracing


def visit_List(context) -> List:
    new_node = List(elts=context.node.get("elts", []), ctx=context.node.get("ctx"))
    new_node.enrich_from_previous(context.node)
    context.replace(new_node)
    return new_node


def visit_Str(context) -> String:
    node = String(context.node["s"])
    node.enrich_from_previous(context.node)
    context.replace(node)
    return node


def visit_Bytes(context) -> Bytes:
    node = Bytes(context.node["s"])
    node.enrich_from_previous(context.node)
    context.replace(node)
    return node


def visit_Num(context):
    node = Number(context.node["n"])
    node.enrich_from_previous(context.node)
    context.replace(node)
    return node


def visit_Complex(context):
    node = complex(context.node["real"], context.node["imag"])
    context.replace(node)


def visit_Constant(context):
    node: Union[String, Number, Constant]

    if context.node.get("kind") is None and type(context.node["value"]) == str:
        node = String(context.node["value"])
    elif context.node.get("kind") is None and type(context.node["value"]) == int:
        node = Number(context.node["value"])
    else:
        node = Constant(context.node["value"])

    node.enrich_from_previous(context.node)
    context.replace(node)
    return node


def visit_Dict(context):
    new_node = Dictionary(context.node["keys"], context.node["values"])
    new_node.enrich_from_previous(context.node)
    context.replace(new_node)
    return new_node


def visit_Expr(context):
    new_node = context.node["value"]
    context.replace(new_node)


def visit_Call(context):
    keyword = {}
    for x in context.node["keywords"]:
        keyword[x["arg"]] = x["value"]

    new_node = Call(context.node["func"], context.node["args"], keyword)
    new_node.enrich_from_previous(context.node)
    context.replace(new_node)
    return new_node


def visit_Assign(context):
    # TODO: fixme when len(targets) > 1
    target = context.node["targets"][0]

    if type(target) == Var and target.var_type == "name":
        target = target.name()

    new_node = Var(target, context.node["value"])
    new_node.enrich_from_previous(context.node)
    context.replace(new_node)
    return new_node


def visit_BinOp(context):
    left = context.node["right"]
    right = context.node["left"]
    new_node = BinOp(left=left, right=right, op=context.node["op"]["_type"].lower())
    new_node.enrich_from_previous(context.node)
    context.replace(new_node)
    return new_node


def visit_Name(context):
    # TODO: check if we need to store node['ctx']['_type']
    # context.replace(Var(context.node['id'], var_type="name"))
    context.replace(context.node["id"])


def visit_Attribute(context):
    target = context.node["value"]
    if isinstance(target, Var) and target.var_type == "name":
        target = target.name()

    new_node = Attribute(target, context.node["attr"], context.node["ctx"]["_type"])
    new_node.enrich_from_previous(context.node)
    new_node._original = context.node

    context.replace(new_node)
    return new_node


def visit_ImportFrom(context):
    new_node = Import()
    new_node.level = context.node.get("level")

    for x in context.node["names"]:
        alias = x["asname"] if x["asname"] else x["name"]
        mname = context.node['module'] or ''
        new_node.names[alias] = f"{mname}.{x['name']}"

    new_node.enrich_from_previous(context.node)
    context.replace(new_node)
    return new_node


def visit_Import(context):
    new_node = Import()
    new_node._original = context.node
    new_node.line_no = context.node["lineno"]
    new_node.col = context.node["col_offset"]

    for x in context.node["names"]:
        alias = x["asname"] if x.get("asname") else x["name"]
        new_node.names[alias] = x["name"]

    context.replace(new_node)
    return new_node


def visit_Print(context):
    new_node = Print(context.node["values"], context.node["dest"])
    new_node.enrich_from_previous(context.node)
    context.replace(new_node)
    return new_node


def visit_Compare(context):
    new_node = Compare(
        left=context.node["left"],
        ops=context.node["ops"],
        comparators=context.node["comparators"]
    )

    if context.node.get('body'):
        new_node.body = context.node['body']

    if context.node.get('orelse'):
        new_node.orelse = context.node['orelse']

    new_node.enrich_from_previous(context.node)
    context.replace(new_node)
    return new_node


def visit_FunctionDef(context):
    new_node = FunctionDef(
        name=context.node["name"],
        args=context.node["args"],
        body=context.node["body"],
        decorator_list=context.node["decorator_list"],
        returns=context.node.get("returns"),
    )
    new_node.enrich_from_previous(context.node)
    context.replace(new_node)
    return new_node


def visit_arguments(context):
    args = []
    if context.node.get("args"):
        for x in context.node["args"]:
            match x:
                case str():
                    args.append(Arg(arg=x))
                case {"_type": "arg", **rest}:
                    args.append(Arg.from_raw_ast(x))
                case _:
                    raise RuntimeError(f"Unknown AST type for arg: {x}")

            #if isinstance(x, dict) and "arg" in x:
            #    args.append(x["arg"])
            #else:
            #    args.append(x)

    match ast_kwarg := context.node.get("kwarg"):
        case {"_type": "arg", **rest}:
            node_kwarg = Arg.from_raw_ast(ast_kwarg)
        case str():
            node_kwarg = Arg(arg=ast_kwarg)
        case None:
            node_kwarg = None
        case _:
            raise RuntimeError(f"Unknown AST type for kwarg: {ast_kwarg}")

    match ast_vararg := context.node.get("vararg"):
        case {"_type": "arg", **rest}:
            node_vararg = Arg.from_raw_ast(ast_vararg)
        case str():
            node_vararg = Arg(arg=ast_vararg)
        case None:
            node_vararg = None
        case _:
            raise RuntimeError(f"Unknown AST type for vararg: {ast_vararg}")

    new_node = Arguments(
        args=args,
        vararg=node_vararg,
        posonlyargs=context.node.get("posonlyargs", []),
        kwonlyargs=context.node.get("kwonlyarg", []),
        kwarg=node_kwarg,
        defaults=context.node.get("defaults", []),
        kw_defaults=context.node.get("kw_defaults", []),
    )

    new_node.enrich_from_previous(context.node)
    context.replace(new_node)
    return new_node


def visit_ClassDef(context) -> ClassDef:
    new_node = ClassDef(
        name=context.node.get("name"),
        body=context.node.get("body"),
        bases=context.node.get("bases"),
    )
    new_node.enrich_from_previous(context.node)
    context.replace(new_node)
    return new_node


def visit_Return(context) -> ReturnStmt:
    new_node = ReturnStmt(value=context.node["value"])
    new_node.enrich_from_previous(context.node)
    context.replace(new_node)
    return new_node


def visit_Yield(context) -> Yield:
    new_node = Yield(value=context.node["value"])
    new_node.enrich_from_previous(context.node)
    context.replace(new_node)
    return new_node


def visit_YieldFrom(context):
    new_node = YieldFrom(value=context.node["value"])
    new_node.enrich_from_previous(context.node)
    context.replace(new_node)
    return new_node


def visit_Subscript(context):
    new_node = Subscript(
        value=context.node.get("value"),
        slice=context.node.get("slice"),
        ctx=context.node["ctx"]["_type"],
    )
    new_node.enrich_from_previous(context.node)
    context.replace(new_node)
    return new_node


def visit_Continue(context):
    new_node = Continue()
    new_node.enrich_from_previous(context.node)
    context.replace(new_node)
    return new_node


def visit_Pass(context):
    new_node = Pass()
    new_node.enrich_from_previous(context.node)
    context.replace(new_node)
    return new_node


def visit_ExceptHandler(context):
    new_node = ExceptHandler(
        body=context.node.get("body", []),
        type=context.node.get("type"),
        name=context.node.get("name"),
    )
    new_node.enrich_from_previous(context.node)
    context.replace(new_node)
    return new_node

def visit_Ellipsis(context):
    context.replace(...)

def visit_Module(context):
    new_node = Module(body=context.node.get("body", []))
    new_node.enrich_from_previous(context.node)
    context.replace(new_node)
    return new_node


VISITORS = {
    "List": visit_List,
    "Tuple": visit_List,
    "Set": visit_List,
    "Str": visit_Str,
    "Bytes": visit_Bytes,
    "Num": visit_Num,
    "Constant": visit_Constant,
    "NameConstant": visit_Constant,
    "Dict": visit_Dict,
    "Expr": visit_Expr,
    "Call": visit_Call,
    "Assign": visit_Assign,
    "BinOp": visit_BinOp,
    "Name": visit_Name,
    "Attribute": visit_Attribute,
    "ImportFrom": visit_ImportFrom,
    "Import": visit_Import,
    "Print": visit_Print,
    "Compare": visit_Compare,
    "FunctionDef": visit_FunctionDef,
    "ClassDef": visit_ClassDef,
    "Return": visit_Return,
    "Yield": visit_Yield,
    "YieldFrom": visit_YieldFrom,
    "Subscript": visit_Subscript,
    "arguments": visit_arguments,
    "Continue": visit_Continue,
    "Pass": visit_Pass,
    "ExceptHandler": visit_ExceptHandler,
    "complex": visit_Complex,
    "Ellipsis": visit_Ellipsis,
    "Module": visit_Module,
}


class ASTVisitor(Visitor):
    """
    This class converts JSON serialized AST tree to appropriate dataclasses if possible
    """

    __slots__ = Visitor.__slots__

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.convergence = None

    def _visit_node(self, context):
        if type(context.node) not in (dict, OrderedDict):
            return

        otype = context.node.get("_type")

        if otype in VISITORS:
            new_node: Optional[ASTNode] = VISITORS[otype](context)

            # if new_node is not None and context.parent:
            #     context.visitor.queue.clear()
            #     context.visitor.push(context.parent)
            #     new_node._visit_node(context)

    def _post_analysis(self):
        super()._post_analysis()
