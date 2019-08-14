
def test_generic_sqli(fixtures, fuzzy_rule_match):
    output = fixtures.scan_test_file('sqli.py')

    lines = [] #TODO: [15, 22, 29]

    matches = [
        {
            'type': 'TaintAnomaly',
            'message': 'Tainted input is passed to the sink',
            'line_no': x
        } for x in lines
    ]

    for x in matches:
        assert any(fuzzy_rule_match(h, x) for h in output['hits']), x
