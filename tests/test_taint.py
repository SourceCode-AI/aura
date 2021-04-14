from textwrap import dedent
from unittest.mock import patch

from aura import config
from aura.uri_handlers.base import ScanLocation
from aura.pattern_matching import ASTPattern
from aura.analyzers.python.visitor import Visitor
from aura.analyzers.python.nodes import *
from aura.analyzers.python_src_inspector import collect



@patch("aura.cache.ASTPatternCache.proxy")
def process_taint(src: str, pattern: str, cache_mock, taint: str="tainted"):
    tree = collect(dedent(src), minimal=True)
    loc = ScanLocation(location="<unknown>")
    p = ASTPattern({
        "pattern": pattern,
        "taint": taint
    })

    cache_mock.return_value = [p]

    v = Visitor.run_stages(location=loc,  ast_tree=tree)
    return v.tree[-1]



def test_taint_operations():
    u = Taints.UNKNOWN
    s = Taints.SAFE
    t = Taints.TAINTED
    # Test that the combinations of taints are correct
    assert (s + s) == Taints.SAFE
    assert (u + u) == Taints.UNKNOWN
    assert (t + t) == Taints.TAINTED
    assert (t + u) == Taints.TAINTED
    assert (u + t) == Taints.TAINTED
    assert (u + s) == Taints.UNKNOWN
    assert (s + u) == Taints.UNKNOWN
    assert (s + t) == Taints.TAINTED
    assert (t + s) == Taints.TAINTED
    # Check total ordering of taint types
    assert Taints.SAFE < Taints.UNKNOWN
    assert not Taints.SAFE >= Taints.UNKNOWN
    assert Taints.UNKNOWN < Taints.TAINTED
    assert not Taints.UNKNOWN >= Taints.TAINTED
    assert Taints.SAFE < Taints.TAINTED
    assert not Taints.SAFE >= Taints.TAINTED


def test_flask_app(fixtures, fuzzy_rule_match):
    output = fixtures.scan_test_file('flask_app.py')
    assert len(output['detections']) > 0, output

    # TODO: also perhaps 24? `eval(self.code)`
    # TODO: cover the case at vuln5:72
    lines = [17, 34, 36, 45, 53, 61, 88]

    matches = [
        {
            'type': 'TaintAnomaly',
            'line_no': x,
            'message': 'Tainted input is passed to the sink'
        } for x in lines
    ]

    output_line_nos = {x['line_no'] for x in output['detections']} - set(lines)

    for x in matches:
        assert any(fuzzy_rule_match(h, x) for h in output['detections']), (output_line_nos, x)

    excluded = [105, 111]
    for hit in output['detections']:
        if hit.get('type') != 'TaintAnomaly':
            continue

        assert hit.get('line_no') not in excluded, hit


def test_taint_log_flask_app(fixtures, fuzzy_rule_match):
    match_log = [
        {
            "line_no": 44,
            "message": "AST node marked as source using semantic rules",
            "taint_level": "TAINTED"
        },
        {
            "line_no": 44,
            "message": "Taint propagated via variable subscript",
            "taint_level": "TAINTED"
        },
        {
            "line_no": 45,
            "message": "Taint propagated by return/yield statement",
            "taint_level": "TAINTED"
        }
    ]

    output = fixtures.scan_test_file('flask_app.py')

    for h in output['detections']:
        if h['line_no'] == 45:
            log = h['extra']['taint_log']
            break
    else:
        raise AssertionError("Taint log hit not found")

    assert fuzzy_rule_match(log, match_log)


def test_variable_assignment_propagation():
    src = """
    x = c()
    y = x
    """
    p = "c()"
    node = process_taint(src, p)
    assert node.var_name == "y"
    assert node._taint_class == Taints.TAINTED


def test_attribute_propagation():
    src = """
    x = c()
    x.y
    """
    p = "c()"
    node = process_taint(src, p)
    assert isinstance(node, Attribute)
    assert node.full_name == "c.y"
    assert node._taint_class == Taints.TAINTED


def test_subscript_propagation():
    src = """
    x = c()
    x[:3]
    """
    p = "c()"
    node = process_taint(src, p)
    assert node._taint_class == Taints.TAINTED


def test_return_statement_propagation():
    src = """
    def x():
        return c()
    
    x()
    """
    p = "c()"
    node = process_taint(src, p)
    assert isinstance(node, Call)
    assert node.full_name == "x"
    assert node._taint_class == Taints.TAINTED


def test_binop_propagation():
    src = """
    x = c()
    a = "test" + x
    b = a + "test"
    """
    p = "c()"
    node = process_taint(src, p)
    assert isinstance(node, Var)
    assert node.var_name == "b"
    assert node._taint_class == Taints.TAINTED


def test_function_argument_propagation():
    src = """
    def x(arg):
        copy = arg
        return copy
    
    y = c()
    result = x(y)
    """
    p = "c()"
    node = process_taint(src, p)
    assert isinstance(node, Var)
    assert node.var_name == "result"
    assert node._taint_class == Taints.TAINTED
