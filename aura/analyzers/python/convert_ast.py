from .visitor import Visitor
from .nodes import *


def visit_List(context):
    context.replace([x for x in context.node['elts']])


def visit_Str(context):
    node = String(context.node['s'])
    node.line_no = context.node.get('lineno')
    context.replace(node)


def visit_Num(context):
    node = Number(context.node['n'])
    node.line_no = context.node.get('lineno')
    context.replace(node)


def visit_Dict(context):
    context.replace(Dictionary(context.node['keys'], context.node['values']))


def visit_Call(context):
    keyword = {}
    for x in context.node['keywords']:
        keyword[x['arg']] = x['value']

    new_node = Call(context.node['func'], context.node['args'], keyword)
    new_node.line_no = context.node['lineno']
    new_node._docs = context.node.get('_doc_string')
    context.replace(new_node)


def visit_Assign(context):
    # TODO: fixme when len(targets) > 1
    target = context.node['targets'][0]

    if isinstance(target, Var) and target.var_type == "name":
        target = target.name()

    new_node = Var(target, context.node['value'])
    new_node.line_no = context.node['lineno']
    context.replace(new_node)


def visit_BinOp(context):
        left = context.node['right']
        right = context.node['left']
        new_node = BinOp(left=left, right=right, op=context.node['op']['_type'].lower())
        new_node.line_no = context.node['lineno']
        context.replace(new_node)


def visit_Name(context):
    # TODO: check if we need to store node['ctx']['_type']
    # context.replace(Var(context.node['id'], var_type="name"))
    context.replace(context.node['id'])


def visit_Attribute(context):
    target = context.node['value']
    if isinstance(target, Var) and target.var_type == "name":
        target = target.name()

    context.replace(Attribute(target, context.node['attr'], context.node['ctx']['_type']))


def visit_ImportFrom(context):
    # FIXME when array len > 1
    for x in context.node['names']:
        alias = x['asname'] if x.get('asname') else x['name']
        full_name = f"{context.node['module']}.{x['name']}"
        new_node = Import(full_name, alias, import_type='from')
        new_node._original = context.node
        new_node.line_no = context.node.get('lineno')
        context.replace(new_node)
        return


def visit_Import(context):
    # FIXME when array len > 1
    for x in context.node['names']:
        alias = x['asname'] if x.get('asname') else x['name']
        new_node = Import(x['name'], alias)
        new_node._original = context.node
        new_node.line_no = context.node.get('lineno')

        context.replace(new_node)
        return


def visit_Print(context):
    new_node = Print(context.node['values'], context.node['dest'])
    new_node._original = context.node
    context.replace(new_node)


def visit_Compare(context):
    new_node = Compare(
        left = context.node['left'],
        ops = context.node['ops'],
        comparators = context.node['comparators']
    )
    new_node._original = context.node
    context.replace(new_node)


def visit_FunctionDef(context):
    new_node = FunctionDef(
        name = context.node['name'],
        args = context.node['args'],
        body = context.node['body'],
        decorator_list = context.node['decorator_list'],
        returns = context.node.get('returns')
    )
    new_node._original = context.node
    new_node.line_no = context.node['lineno']
    context.replace(new_node)


VISITORS = {
    'List': visit_List,
    'Tuple': visit_List,
    'Set': visit_List,
    'Str': visit_Str,
    'Num': visit_Num,
    'Dict': visit_Dict,
    'Call': visit_Call,
    'Assign': visit_Assign,
    'BinOp': visit_BinOp,
    'Name': visit_Name,
    'Attribute': visit_Attribute,
    'ImportFrom': visit_ImportFrom,
    'Import': visit_Import,
    'Print': visit_Print,
    'Compare': visit_Compare,
    'FunctionDef': visit_FunctionDef,
}


class ASTVisitor(Visitor):
    """
    This class converts JSON serialized AST tree to appropriate dataclasses if possible
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def _visit_node(self, context):
        if type(context.node) != dict:
            return

        otype = context.node.get('_type')

        if otype in VISITORS:
            VISITORS[otype](context)
