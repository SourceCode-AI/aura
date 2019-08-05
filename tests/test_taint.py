from aura.analyzers.python.nodes import Taints


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
    assert len(output['hits']) > 0, output

    matches = [
        {
            'type': 'TaintAnomaly',
            'line_no': 8,
            'message': 'Tainted input is passed to the sink'
        }
    ]

    for x in matches:
        assert any(fuzzy_rule_match(h, x) for h in output['hits']), x
