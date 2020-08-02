"""
This file is injected into the interpreter by find_imports
The reason is to be python 2 and 3 compatible regardless of Aura framework
"""

import sys
import dis
import json
import modulefinder


LOAD_CONST = dis.opmap["LOAD_CONST"]
IMPORT_NAME = dis.opmap["IMPORT_NAME"]
STORE_NAME = dis.opmap["STORE_NAME"]
STORE_GLOBAL = dis.opmap["STORE_GLOBAL"]
STORE_OPS = STORE_NAME, STORE_GLOBAL
EXTENDED_ARG = dis.EXTENDED_ARG

if hasattr(dis, "_unpack_opargs"):
    _unpack_opargs = dis._unpack_opargs
else:  # Python 2.7 fallback
    _unpack_opargs = modulefinder._unpack_opargs


def find_imports(co):
    code = co.co_code
    names = co.co_names
    consts = co.co_consts
    opargs = [
        (op, arg) for _, op, arg in _unpack_opargs(code)
        if op != EXTENDED_ARG
    ]

    for i, (op, oparg) in enumerate(opargs):
        if (
            op == IMPORT_NAME
            and i >= 2
            and opargs[i - 1][0] == opargs[i - 2][0] == LOAD_CONST
        ):
            level = consts[opargs[i - 2][1]]
            fromlist = consts[opargs[i - 1][1]]
            if fromlist:
                fromlist = list(fromlist)
            name = names[oparg]
            yield [level, fromlist, name]


def main(file_path):
    with open(file_path, "r") as fd:
        co = compile(fd.read() + "\n", file_path, "exec")

    imports = []

    for x in find_imports(co):
        imports.append(x)

    print(json.dumps(imports))


if __name__ == "__main__":
    pth = sys.argv[1]
    main(file_path=pth)
