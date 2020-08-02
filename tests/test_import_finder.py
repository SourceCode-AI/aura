import pytest

from aura.analyzers import find_imports


@pytest.mark.parametrize("test_input,expected", [
    ("import_tester/mypackage/sub1/module1.py", {(2, ('module2object',), 'sub2.module2')}),
    ("import_tester/mypackage/sub2/module2.py", set()),  # TODO
    ("import_tester/mypackage/empty.py", set()),
    ("import_tester/mypackage/root.py", {(1, ("*",), "sub1")}),
    ("import_tester/mypackage/py2.py", {(1, ('*',), 'root')}),
    ("import_tester/mypackage/py3.py", {(1, ('*',), 'root')}),
    ("obfuscated.py", {(-1, ('d',), 'a.b.c'), (-1, None, 'ab.cd'), (-1, ('post',), 'requests'), (-1, ('y',), 'x'), (-1, None, 'pprint'), (2, ('relative',), '')})
])
def test_get_imports2(test_input, expected, fixtures):
    pth = fixtures.path(test_input)
    imports = find_imports.get_imports(pth)

    # Convert to representation for easier equivalency comparison (tuples in sets)
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

    assert expected == converted, converted
