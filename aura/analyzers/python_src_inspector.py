#-*- coding: utf-8 -*-
"""

This file need to be pure-python only (e.g. no external module imports)
and also both py2k & py3k compatible

"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import ast
import sys
import os
import json
import codecs
import subprocess
import traceback

from distutils.spawn import find_executable


PY_2K = find_executable('python2')
PY_3K = find_executable('python3')
INSPECTOR_PATH = os.path.abspath(__file__)
BUILTIN_PURE = [int, float, bool]
BUILTIN_BYTES = (bytearray, bytes)
BUILTIN_STR = [str]
HEX_DECODE = lambda value: codecs.getencoder('hex_codec')(value)[0].decode('utf-8')

def decode_bytes(value):
    try:
        return value.decode('utf-8')
    except:
        return HEX_DECODE(value)


if sys.version_info.major == 3:
    def decode_str(value):
        return value
else:  # Python2 specific handlers
    BUILTIN_PURE.append(long)
    BUILTIN_STR.append(basestring)

    def decode_str(value):
        try:
            return value.decode('utf-8')
        except:
            return HEX_DECODE(value)


class CodeVisitor(ast.NodeVisitor):
    def __init__(self, *args, **kwargs):
        self.__imports = {}
        self.__func_calls = []

        super(CodeVisitor, self).__init__(*args, **kwargs)

    def visit_Import(self, node):
        for x in node.names:
            glob_name = (x.asname or x.name)
            self.__imports[glob_name] = {
                'type': 'import',
                'module': x.name,
                'alias': x.asname,
                'line_no': node.lineno
            }

    def visit_ImportFrom(self, node):
        if node.module is None:
            return

        for x in node.names:
            glob_name = (x.asname or x.name)
            full_name = '{}.{}'.format(node.module, x.name)
            self.__imports[glob_name] = {
                'type': 'from_import',
                'module': node.module,
                'name': x.name,
                'alias': x.asname,
                'full_name': full_name,
                'line_no': node.lineno
            }

    def __recurse_attr(self, node):
        path = []

        if isinstance(node, ast.Attribute):
            path = self.__recurse_attr(node.value)
            if getattr(node, 'attr'):
                path.append(node.attr)
        elif isinstance(node, ast.Str):
            path = [node.s]
        elif isinstance(node, ast.Call):
            path = self.__recurse_attr(node.func)
        elif isinstance(node, ast.Name):
            try:
                path = [node.id]
            except AttributeError:
                print(ast.dump(node))
                raise

        return path

    def __resolve_function(self, func_data):
        if len(func_data) == 0:
            return

        global_name = func_data['call_parts'][0]
        func_part = func_data['call_parts'][:]  # Copy the list
        if global_name in self.__imports:
            imp_data = self.__imports[global_name]
            if imp_data['type'] == 'import' and imp_data['alias']:
                func_part[0] = imp_data['module']
            elif imp_data['type'] == 'from_import':
                func_part = imp_data['module'].split('.') + imp_data['name'].split('.') + func_part[1:]


        func_data['function_parts'] = func_part
        func_data['function'] = '.'.join(func_part)

        self.__func_calls.append(func_data)

    def visit_Call(self, node):
        func_name = self.__recurse_attr(node)
        args = [ast.dump(x) for x in node.args]
        kwargs = [ast.dump(x) for x in node.keywords]

        if not func_name:
            return

        data = {
            'call': '.'.join(func_name),
            'call_parts': func_name,
            'args': args,
            'kwargs': kwargs,
            'line_no': node.lineno
        }
        self.__resolve_function(data)

    def pprint(self):
        for x in self.__imports.values():
            print("Imported: '{}'".format(x.get('full_name') or x['module']))

        for x in self.__func_calls:
            print("Function called: '{}'".format(x['function']))

    def as_dict(self):
        data = {
            'modules': self.__imports,
            'calls': self.__func_calls
        }
        return data


def ast2json(node):
    """
    Inspired by:
    https://github.com/YoloSwagTeam/ast2json/blob/master/ast2json/ast2json.py

    :param node:
    :return:
    """
    assert isinstance(node, ast.AST)
    data = dict()
    data['_type'] = node.__class__.__name__
    for attr in dir(node):
        if attr.startswith('_'):
            continue
        data[attr] = get_value(getattr(node, attr))
    return data


def get_value(attr):
    if attr is None:
        return attr
    elif isinstance(attr, tuple(BUILTIN_PURE)):
        return attr
    elif isinstance(attr, BUILTIN_BYTES):
        return decode_bytes(attr)
    elif isinstance(attr, tuple(BUILTIN_STR)):
        return decode_str(attr)
    elif isinstance(attr, list):
        return [get_value(x) for x in attr]
    elif isinstance(attr, ast.AST):
        return ast2json(attr)
    else:
        raise ValueError("Could not serialize given value {}".format(repr(attr)))


def load_signatures(fname='signatures.json'):
    location = os.path.join(os.getcwd(), fname)
    location = os.environ.get('AURA_CFG', location)
    with open(location, 'r') as fd:
        data = json.loads(fd.read())
    return data


def exec_on_py2k():
    if PY_2K:
        os.execv(PY_2K, [INSPECTOR_PATH] + sys.argv)


def main():
    with open(sys.argv[1], 'r') as fd:
        try:
            src = ast.parse(fd.read())
        except (Exception, SyntaxError):
            if sys.version_info.major == 3:
                exec_on_py2k()
            print(sys.version_info)
            raise

    inspector = CodeVisitor()
    inspector.visit(src)

    src_dump = inspector.as_dict()
    src_dump['ast_tree'] = ast2json(src)

    print(json.dumps(src_dump))


def analyze(path):
    proc = subprocess.run(
        [PY_3K, INSPECTOR_PATH, path],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if proc.returncode == 0:
        script_data = json.loads(proc.stdout)
        return script_data


if __name__ == '__main__':
    main()
