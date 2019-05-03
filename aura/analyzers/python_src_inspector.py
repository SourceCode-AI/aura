#-*- coding: utf-8 -*-
"""

This file need to be pure-python only (e.g. no external module imports)
and also both py2k & py3k compatible

"""
from __future__ import print_function
from __future__ import unicode_literals

import ast
import sys
import inspect
import codecs
import platform

try:
    import simplejson as json
except ImportError:
    import json


BUILTIN_PURE = [int, float, bool]
BUILTIN_BYTES = (bytearray, bytes)
BUILTIN_STR = (str,)


def hex_decode(value):
    hex = codecs.encode(value, 'hex_codec')
    return hex.decode('utf-8')


def decode_bytes(value):
    try:
        return value.encode('utf-8', errors='replace')
    except:
        return hex_decode(value)


if sys.version_info.major == 3:
    def decode_str(value):
        return value
else:  # Python2 specific handlers
    BUILTIN_PURE.append(long)
    BUILTIN_STR = (str, basestring)

    def decode_str(value):
        return decode_bytes(value)


def ast2json(node):
    """
    Inspired by:
    https://github.com/YoloSwagTeam/ast2json/blob/master/ast2json/ast2json.py
    """
    assert isinstance(node, ast.AST)
    data = dict()
    data['_type'] = node.__class__.__name__

    #try:
    #    data['_doc_string'] = ast.get_docstring(node)
    #except TypeError:
    #    pass

    for attr, target in node.__dict__.items():
        if attr.startswith('_'):
            continue
        data[attr] = get_value(target)
    return data


def get_value(attr):
    t = type(attr)

    if attr is None:
        return attr
    elif isinstance(attr, tuple(BUILTIN_PURE)):  # We could also use isinstance but that is slow compared to array lookup
        return attr
    elif isinstance(attr, BUILTIN_BYTES):
        return decode_bytes(attr)
    elif  isinstance(attr, BUILTIN_STR):
        return decode_str(attr)
    elif t == list:
        return  list(map(get_value, attr)) # map is faster then list comprehension
    elif isinstance(attr, ast.AST):
        return ast2json(attr)
    elif t == complex:
        return {'_type': 'complex', 'real': attr.real, 'imag': attr.imag}
    else:
        raise ValueError("Could not serialize given value {}".format(repr(attr)))


def get_builtins():
    scope = {}
    for k, v in __builtins__.__dict__.items():
        if inspect.isclass(v):
            t = {
                'type': 'class',
                'cls': v.__name__
            }
        elif inspect.isfunction(v):
            t = {
                'type': 'function',
                'cls': v.__name__
            }
        else:
            t = {
                'type': 'other',
                'repr': repr(v)
            }
            if hasattr(v, '__name__'):
                t['name'] = v.__name__
        scope[k] = t

    return scope


def main(pth=None):
    if pth is None:
        pth = sys.argv[1]

    if pth != '-':
        with open(pth, 'r') as fd:
            source_code = fd.read()
    else:
        source_code = sys.stdin.read()

    try:
        src = ast.parse(source_code)
    except SyntaxError:
        sys.exit(1)
    except Exception:
        print("Error parsing source code for file: " + pth, file=sys.stderr)
        raise

    src_dump = {
        'ast_tree': ast2json(src),
        'version': list(platform.python_version_tuple()),
        'implementation': platform.python_implementation(),
        'compiler': platform.python_compiler(),
        'build': platform.python_build(),
        'builtins': get_builtins(),
    }

    try:
        print(json.dumps(src_dump))
    except Exception:
        print("Error parsing source code for file: " + pth, file=sys.stderr)
        raise

if __name__ == '__main__':
    main()
