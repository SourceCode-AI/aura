# coding=utf-8
"""
Transformer for parsed AST tree
"""
import collections

str_wrapper = collections.namedtuple("String", ['value', 'line_no'])


def visit_str(obj):
    return str_wrapper(obj['s'], obj['lineno'])


def visit_list(obj):
    return [walk(x) for x in obj['elts']]


def walk(obj):
    if isinstance(obj, dict):
        if obj.get('_type') == 'Str':
            return visit_str(obj)
        elif obj.get('_type') == 'List':
            return visit_list(obj)
        else:
            return {k: walk(v) for (k, v) in obj.items()}
    elif isinstance(obj, list) or isinstance(obj, tuple):
        return [walk(x) for x in obj]

    return obj


def transform(obj):
    return walk(obj)
