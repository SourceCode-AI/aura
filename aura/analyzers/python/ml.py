"""
Aura plugin for generating data suitable for ML applications and data mining on top of the source code

Implementation of the pq Gram Index
    Iterates over node identifier tuples producing n-grams of size p+q
    p is the stem size (left fill)
    q is the base size (right fill)
    for the algorithm explanation, refer to the research paper below

                   ┌────────────┐
        stem       │  PQ grams  │
         ╔═╗       ├────────────┤
         ║*║       │*a **a      │
         ║a║       │   aa **e   │
         ╚═╝       │      ae ***│
base    ╱ │ ╲      │   aa *eb   │
 ╔═════╗  b  c     │      ab ***│
 ║* * a║           │   aa eb*   │
 ╚═════╝   ┌─────┐ │   aa b**   │
     ╱ ╲   │p = 2│ │*a *ab      │
    e   b  │q = 3│ │   ab ***   │
           └─────┘ │*a abc      │
                   │   ac ***   │
                   │*a bc*      │
                   │*a c**      │
                   └────────────┘

Image source https://files.ifi.uzh.ch/boehlen/Papers/ABG10.pdf p.24
"""
import re
from dataclasses import dataclass, field
from collections import deque
from itertools import combinations
from typing import Union, List, Any, Tuple, Optional

from .visitor import Visitor
from ..detections import Detection


TOKEN_REGEX = re.compile(r"([A-Z]{2,}|[A-Z][a-z]{1,}|[a-z]+|\d+)")
TERMINALS = {
    "str", "constant_value", "import_name_asname", "import_name", "name", "attribute_name"
}


class IDGen:
    """
    Generates incremental IDS for nodes in a tree
    """
    current = 0

    @classmethod
    def id(cls) -> int:
        prev = cls.current
        cls.current += 1
        return prev


@dataclass
class ASTNodeIdentifier:
    label: Union[str, None] = None
    node_type: Union[str, None] = ''
    children: List[Any] = field(default_factory=list)
    id: int = field(default_factory=IDGen.id)

    @property
    def is_terminal(self) -> bool:
        if self.node_type in TERMINALS:
            return True
        else:
            return False

    def __iadd__(self, other):
        if other:
            self.children.append(other)
        return self

    def to_tuple(self) -> Tuple[int, Optional[str], str, Tuple]:
        return (self.id, self.label, self.node_type, tuple(x.to_tuple() for x in self.children))


class MLVisitor(Visitor):
    stage_name = "ml"

    def traverse(self, _id=id):
        root = self.tree
        if type(root) == dict and "ast_tree" in root:
            root = root["ast_tree"]

        # Extract the pq-grams from the tree
        identifier_tree = extract_identifier(root)
        #self.extract_code_paths(identifier_tree)
        #tuple_identifiers = identifier_tree.to_tuple()



        #ngrams = tuple(pq_gram_index(tuple_identifiers, 2, 3))

        # self.hits.append(
        #     Detection(
        #         detection_type="PQGrams",
        #         score=0,
        #         extra={
        #             "pqgrams": ngrams
        #         },
        #         message="Extracted PQ grams from the source code",
        #         signature=f"pq_grams#{self.normalized_path}",
        #         tags={"pq_grams"},
        #         informational=True,
        #     )
        # )

        return self.tree

    def extract_code_paths(self, tree: ASTNodeIdentifier):
        code_paths = []

        terminals = list(get_terminals(tree))

        for lnode, rnode in combinations(terminals, r=2):
            node_path = extract_node_path(lnode[0], rnode[0])
            if node_path is not None:
                print(lnode[1].label, [(x.id, (x.label or x.node_type)) for x in node_path], rnode[1].label)


def extract_node_path(lpath, rpath):
    lsize, rsize, i = len(lpath), len(rpath), 0

    while i < min(lsize, rsize) and lpath[i].id == rpath[i].id:
        i += 1

    return lpath[i:][::-1] + (lpath[i-1],) + rpath[i:]


def pq_gram_index(node: tuple, p: int, q: int, stem=None):
    if stem is None:
        stem = ((None, None, None),) * p

    base = ((None, None, None),) * q
    stem = stem[1:] + ((node[0], node[1], node[2]),)

    if len(node[3]) == 0: # Leaf node
        yield stem + base
    else:
        for child in node[3]:
            base = base[1:] + ((child[0], child[1], child[2]),)
            yield stem + base
            yield from pq_gram_index(node=child, p=p, q=q, stem=stem)

        for i in range(1, q):
            base = base[1:] + ((None, None, None),)
            yield stem + base


def get_terminals(root: ASTNodeIdentifier):
    """
    Traverse the AST tree and yield back all terminal nodes + their path up to the root node
    This can be done recursively but we risk hitting the RecursionError for more complex code so we do it via LIFO queue instead
    """

    q = deque()
    # Queue items structure:
    # (<tuple that is a path of nodes from root to this element>, <AST node>)
    q.append(((), root))

    while len(q):
        node_pth, node = q.pop()
        child_pth = node_pth + (node,)

        if node.is_terminal:
            yield (node_pth, node)
            continue

        for idx, child in enumerate(node.children):
            q.append((child_pth, child))


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
    if type(node) == dict:
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
    stmt = ASTNodeIdentifier(node_type='attribute')
    # TODO: ctx
    value = ASTNodeIdentifier(node_type='attribute_value')
    value += extract_identifier(node['value'])
    stmt += value
    stmt += ASTNodeIdentifier(label=node["attr"], node_type="attribute_name")
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


def node_constant(node: dict) -> ASTNodeIdentifier:
    stmt = ASTNodeIdentifier(node_type="constant")
    v = node["value"]
    ctype = ASTNodeIdentifier(label=v.__class__.__name__, node_type="constant_type")
    ctype += ASTNodeIdentifier(label=str(v), node_type="constant_value")
    stmt += ctype
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
    'Compare': node_compare,
    "Constant": node_constant,
}


def split_token(token: str) -> List[str]:
    """
    Split the identifier token into separate components
    Example:
    "getMatch" -> ["get", "Match"]
    "get_match" -> ["get", "match"]
    "find666" -> ["find", "666"]
    """
    return [x.groups()[0] for x in TOKEN_REGEX.finditer(token)]
