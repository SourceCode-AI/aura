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
            "line_no": 44,
            "message": "Taint propagated via variable assignment",
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
