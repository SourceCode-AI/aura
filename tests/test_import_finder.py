import os

from aura import commands
from aura.analyzers import find_imports


AURA_CMD_IMPORTS = {
    (1, ('Analyzer',), 'package_analyzer'),
    (1, ('ScanOutputBase', 'DiffOutputBase'), 'output.base'),
    (1, ('PypiPackage',), 'package'),
    (1, ('URIHandler', 'ScanLocation'), 'uri_handlers.base')
}


def test_get_imports():
    imports = find_imports.get_imports(os.path.abspath(commands.__file__))
    converted = set()

    for imp in imports:
        if imp[0] == 0:
            continue

        if imp[1]:
            pkgs = tuple(imp[1])
        else:
            pkgs = imp[1]

        data = (imp[0], pkgs, imp[2])
        converted.add(data)

    assert len(AURA_CMD_IMPORTS - converted) == 0, (AURA_CMD_IMPORTS-converted)
