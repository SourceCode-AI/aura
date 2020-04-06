import io
import json

from aura.analyzers import python_src_inspector


def test_src_inspector():
    output = io.StringIO()
    python_src_inspector.main(pth=python_src_inspector.__file__, out=output)
    ast_tree = json.loads(output.getvalue())
    assert 'builtins' in ast_tree
    assert 'ast_tree' in ast_tree
    assert 'version' in ast_tree
    assert 'build' in ast_tree
    assert 'implementation' in ast_tree

