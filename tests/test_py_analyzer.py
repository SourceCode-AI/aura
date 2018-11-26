import re
import pprint
import subprocess

from aura.analyzers import rules
from aura.analyzers import python_src
from aura.analyzers import python_src_inspector


def test_basic_ast(fixtures):
    pth = fixtures.path('basic_ast.py')

    data = python_src_inspector.analyze(pth)

    output = list(python_src.process_script_data(pth, data, kwargs={'filter': False}))

    imported = set()
    calls = dict()
    for x in output:
        if isinstance(x, rules.module_import):
            imported.add(x.name)
        else:
            calls[x.line_no] = x

    # Check if all imported modules were detected
    assert imported == {'requests', 'subprocess', 'urllib2', 'importlib', 'os', 'donald_trump'}

    pprint.pprint(output)

    # Check if the function calls were captured
    assert calls[11].function == 'requests.get'
    assert calls[15].function == 'importlib.import_module'
    assert calls[16].function == '__import__'
    assert calls[20].function == 'os.system'
    assert calls[21].function == 'subprocess.Popen'
    assert calls[22].function == 'subprocess.check_call'
    assert calls[23].function == 'subprocess.check_output'


def test_python_symlinks():
    py2k = subprocess.check_output([python_src_inspector.PY_2K, '-c', 'import sys; print(sys.version)'])
    py2k = py2k.decode().split()[0]
    assert re.match(r'^2\.7[\d.]*$', py2k), "Invalid python2 symlink"

    py3k = subprocess.check_output([python_src_inspector.PY_3K, '-c', 'import sys; print(sys.version)'])
    py3k = py3k.decode().split()[0]
    assert re.match(r'^3\.[67][\d.]*$', py3k), "Invalid python3 symlink"
