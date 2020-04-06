import os
import pprint
from dataclasses import dataclass, field
from pathlib import Path
from typing import Union, List, Any, Tuple

from aura.utils import Analyzer
from aura import python_executor
from aura.analyzers import python_src_inspector

INSPECTOR_PATH = os.path.abspath(python_src_inspector.__file__)


@dataclass
class ASTNodeIdentifier:
    label: Union[str, None] = None
    node_type: Union[str, None] = ''
    children: List[Any] = field(default_factory=list)

    def __iadd__(self, other):
        if other:
            self.children.append(other)
        return self

    def to_tuple(self):
        return (self.label, self.node_type, tuple(x.to_tuple() for x in self.children))


@Analyzer.ID("ast_ngrams")
def extract(pth: Path, mime: str, **kwargs):
    if pth.suffix == '.py':
        pass
    elif mime != 'text/x-python':
        return

    spth = os.fspath(pth.absolute())

    ast_tree, iname, icmd = python_executor.run_with_interpreters(command=[INSPECTOR_PATH, spth])

    pprint.pprint(ast_tree['ast_tree'])

    identifier_tree = extract_identifier(ast_tree['ast_tree'])
    tuple_identifiers = identifier_tree.to_tuple()

    pprint.pprint(tuple_identifiers)
    print('---')
    for x in filter_pq_gram_duplicates(tuple_identifiers, 2, 3):
        print(x)

    yield from []


def pq_gram_index(node: tuple, p: int, q: int, stem=None):
    """
    Implementation of the pq Gram Index
    Iterates over node identifier tuples producing n-grams of size p+q
    p is the stem size (left fill)
    q is the base size (right fill)
    for the algorithm explanation, refer to the research paper below:
    https://files.ifi.uzh.ch/boehlen/Papers/ABG10.pdf
    """
    if stem is None:
        stem = ((None, '*'),) * p

    base = ((None, '*'),) * q
    stem = stem[1:] + ((node[0], node[1]),)

    if len(node[2]) == 0: # Leaf node
        yield stem + base
    else:
        for child in node[2]:
            base = base[1:] + ((child[0], child[1]),)
            yield stem + base
            yield from pq_gram_index(node=child, p=p, q=q, stem=stem)

        for i in range(1, q):
            base = base[1:] + ((None, '*'),)
            yield stem + base


def filter_pq_gram_duplicates(*args, **kwargs):
    grams = []

    # TODO: not very effective but would do it's job for now
    for gram in pq_gram_index(*args, **kwargs):
        if gram not in grams:
            grams.append(gram)

    return grams


def extract_identifier(node):
    """
    Recursively traverse the RAW AST JSON tree and convert them into ASTNodeIdentifier tree

    :param node:
    :return:
    """
    # We want to only process raw ast node which must be dict types and have a `_type` key
    if isinstance(node, dict):
        t = node.get('_type')
        if t in AST_NODE_TYPES: # Process the AST node via a specific node converter
            return AST_NODE_TYPES[t](node)
        elif t is not None:  # Unknown/unsupported node, output it as misc without further recursion
            return ASTNodeIdentifier(label=t, node_type='misc')


#---[ Functions to convert raw ast dict nodes into ASTNodeIdentifier based on their type ]---


def node_function_def(node: dict) -> ASTNodeIdentifier:
    stmt = ASTNodeIdentifier(label=node['name'], node_type='func_def')
    body = ASTNodeIdentifier(label='body', node_type='func_def_body')

    for b in node['body']:
        body += extract_identifier(b)

    stmt += body
    return stmt


def node_call(node: dict) -> ASTNodeIdentifier:
    stmt = ASTNodeIdentifier(label=None, node_type='call')

    func = ASTNodeIdentifier(node_type='call_func')
    func += extract_identifier(node['func'])
    stmt += func

    args = ASTNodeIdentifier(node_type='call_args')
    for arg in node['args']:
        args += extract_identifier(arg)

    stmt += args
    return stmt


def node_module(node: dict) -> ASTNodeIdentifier:
    stmt = ASTNodeIdentifier(label=None, node_type='module')
    body = ASTNodeIdentifier(label=None, node_type='module_body')

    for b in node['body']:
        body += extract_identifier(b)

    stmt += body
    return stmt


def node_expr(node: dict) -> ASTNodeIdentifier:
    stmt = ASTNodeIdentifier(label=None, node_type='expr')
    stmt += extract_identifier(node['value'])
    return stmt


def node_class_def(node: dict) -> ASTNodeIdentifier:
    stmt = ASTNodeIdentifier(label=node['name'], node_type='class_def')
    body = ASTNodeIdentifier(node_type='class_def_body')
    for b in node['body']:
        body += extract_identifier(b)

    stmt += body
    return stmt


def node_attribute(node: dict) -> ASTNodeIdentifier:
    stmt = ASTNodeIdentifier(label=node['attr'], node_type='attribute')
    # TODO: ctx

    value = ASTNodeIdentifier(node_type='attribute_value')
    value += extract_identifier(node['value'])
    stmt += value
    return stmt


def node_name(node: dict) -> ASTNodeIdentifier:
    stmt = ASTNodeIdentifier(label=node['id'], node_type='name')
    # TODO: add ctx
    return stmt


def node_str(node: dict) -> ASTNodeIdentifier:
    stmt = ASTNodeIdentifier(label=node['s'], node_type='str')
    return stmt


def node_assign(node: dict) -> ASTNodeIdentifier:
    stmt = ASTNodeIdentifier(node_type='assign')
    targets = ASTNodeIdentifier(node_type='assign_targets')

    for t in node['targets']:
        targets += extract_identifier(t)
    stmt += targets

    value = ASTNodeIdentifier(node_type='assign_value')
    value += extract_identifier(node['value'])
    stmt += value

    return stmt


def node_import(node: dict) -> ASTNodeIdentifier:
    stmt = ASTNodeIdentifier(node_type='import')
    names = ASTNodeIdentifier(node_type='import_names')

    for n in node['names']:
        name = ASTNodeIdentifier(label=n['name'], node_type='import_name')
        if n['asname']:
            asname = ASTNodeIdentifier(label=n['asname'], node_type='import_name_asname')
            name += asname
        names += name

    stmt += names
    return stmt


def node_import_from(node: dict) -> ASTNodeIdentifier:
    stmt = ASTNodeIdentifier(label=node['module'], node_type='import_from')
    names = ASTNodeIdentifier(node_type='import_from_names')

    for n in node['names']:
        name = ASTNodeIdentifier(label=n['name'], node_type='import_from_name')
        if n['asname']:
            asname = ASTNodeIdentifier(label=n['asname'], node_type='import_from_name_asname')
            name += asname
        names += name
    stmt += names

    level = ASTNodeIdentifier(label=str(node['level']), node_type='import_from_level')
    stmt += level
    return stmt


def node_print(node: dict) -> ASTNodeIdentifier:
    stmt = ASTNodeIdentifier(node_type='print')

    dest = ASTNodeIdentifier(node_type='print_dest')
    dest += extract_identifier(node['dest'])
    stmt += dest

    values = ASTNodeIdentifier(node_type='print_values')
    for v in node['values']:
        value = ASTNodeIdentifier(node_type='print_value')
        value += extract_identifier(v)
        values += value

    stmt += values
    return stmt


def node_if(node: dict) -> ASTNodeIdentifier:
    stmt = ASTNodeIdentifier(node_type='if')
    body = ASTNodeIdentifier(node_type='if_body')

    for b in node['body']:
        body += extract_identifier(b)
    stmt += body

    orelse = ASTNodeIdentifier(node_type='if_orelse')
    for o in node['orelse']:
        orelse += extract_identifier(o)
    stmt += orelse

    test = ASTNodeIdentifier(node_type='if_test')
    test += extract_identifier(node['test'])
    stmt += test

    return stmt


def node_compare(node: dict) -> ASTNodeIdentifier:
    stmt = ASTNodeIdentifier(node_type='compare')

    left = ASTNodeIdentifier(node_type='compare_left')
    left += extract_identifier(node['left'])
    stmt += left

    comparators = ASTNodeIdentifier(node_type='compare_comparators')
    stmt += comparators
    for c in node['comparators']:
        comparators += extract_identifier(c)

    ops = ASTNodeIdentifier(node_type='compare_ops')
    stmt += ops
    for op in node['ops']:
        ops += extract_identifier(op)

    return stmt


AST_NODE_TYPES = {
    'FunctionDef': node_function_def,
    'Call': node_call,
    'Module': node_module,
    'Expr': node_expr,
    'ClassDef': node_class_def,
    'Attribute': node_attribute,
    'Name': node_name,
    'Str': node_str,
    'Assign': node_assign,
    'Import': node_import,
    'ImportFrom': node_import_from,
    'Print': node_print,
    'If': node_if,
    'Compare': node_compare
}
