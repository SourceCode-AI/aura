# -*- coding: utf-8 -*-
"""

This file need to be pure-python only (e.g. no external module imports)
and also both py2k & py3k compatible

"""
from __future__ import print_function
from __future__ import unicode_literals

import ast
import sys
import io
import re
import inspect
import codecs
import tokenize
import platform
import traceback

try:
    import rapidjson as json
except ImportError:
    import json


BUILTIN_PURE = [int, float, bool]
BUILTIN_BYTES = (bytearray, bytes)
BUILTIN_STR = (str,)
ENCODING_REGEX = re.compile(r"^[ \t\f]*#.*?coding[:=][ \t]*(?P<encoding>[-_.a-zA-Z0-9]+)")


if sys.version_info.major >= 3 and sys.version_info.minor >= 6:
    OrderedDict = dict
else:
    from collections import OrderedDict



def hex_decode(value):
    hex = codecs.encode(value, "hex_codec")
    return hex.decode("utf-8")


def decode_bytes(value):
    try:
        return value.encode("utf-8", errors="replace")
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
    data = OrderedDict()
    data["_type"] = node.__class__.__name__

    # try:
    #    data['_doc_string'] = ast.get_docstring(node)
    # except TypeError:
    #    pass

    for attr, target in node.__dict__.items():
        if attr.startswith("_"):
            continue
        data[attr] = get_value(target)
    return data


def get_value(attr):
    t = type(attr)

    if attr is None:
        return attr
    elif t in BUILTIN_PURE:  # We could also use isinstance but that is slow compared to array lookup
        return attr
    elif isinstance(attr, BUILTIN_BYTES):
        return decode_bytes(attr)
    elif isinstance(attr, BUILTIN_STR):
        return decode_str(attr)
    elif t == list:
        return list(map(get_value, attr))  # map is faster then list comprehension
    elif isinstance(attr, ast.AST):
        return ast2json(attr)
    elif type(attr) == type(Ellipsis):
        return {"_type": "Ellipsis"}
    elif t == complex:
        return {"_type": "complex", "real": attr.real, "imag": attr.imag}
    else:
        raise ValueError("Could not serialize given value {}".format(repr(attr)))


def get_builtins():
    scope = {}
    if hasattr(__builtins__, "__dict__"):
        b = __builtins__.__dict__
    else:
        b = __builtins__

    for k, v in b.items():
        if inspect.isclass(v):
            t = {"type": "class"}
        elif inspect.isfunction(v):
            t = {"type": "function"}
        else:
            t = {"type": "other", "repr": repr(v)}

        if hasattr(v, "__name__"):
            name = v.__name__
            if name != k:
                t["name"] = name
        scope[k] = t

    return scope


def get_comments(source_code):
    if type(source_code) == str:
        source_code = source_code.encode()

    wrap = io.StringIO(source_code)
    for line in tokenize.generate_tokens(wrap.readline):
        if line.type == tokenize.COMMENT:
            yield {"line": line.start, "string": line.string}


def find_encoding_py2(fd_readline):
    m = ENCODING_REGEX.match(fd_readline())
    if not m:
        m = ENCODING_REGEX.match(fd_readline())
    if not m:
        return "utf-8"
    else:
        return m.groupdict()["encoding"]


def get_encoding(path):
    try:
        with open(path, "rb") as fd:
            if sys.version_info.major == 2:
                return find_encoding_py2(fd.readline)
            return tokenize.detect_encoding(fd.readline)[0]
    except SyntaxError:
        return "utf-8"


def get_environment():
    return {
        "version": list(platform.python_version_tuple()),
        "implementation": platform.python_implementation(),
        "compiler": platform.python_compiler(),
        "build": platform.python_build(),
        "builtins": get_builtins(),
        # TODO: 'comments': list(get_comments(source_code=source_code))
    }


def collect(source_code, encoding="utf-8", minimal=False):
    src = ast.parse(source_code)
    src_dump = {
        "ast_tree": ast2json(src),
        "encoding": encoding,
    }

    if not minimal:
        src_dump.update(get_environment())

    return src_dump


def main(pth=None, out=sys.stdout):
    if "--environment-only" in sys.argv:
        print(json.dumps(get_environment()), file=out)
        return sys.exit(0)

    if pth is None:
        pth = sys.argv[1]

    if pth != "-":
        encoding = get_encoding(pth)

        with open(pth, "rb") as fd:
            source_code = fd.read()
    else:
        encoding = sys.getdefaultencoding()
        source_code = sys.stdin.read()

    try:
        src_dump = collect(source_code=source_code, encoding=encoding)
        print(json.dumps(src_dump), file=out)
    except SyntaxError:
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)
    except Exception:
        print("Error parsing source code for file: " + pth, file=sys.stderr)
        raise


if __name__ == "__main__":
    main()
