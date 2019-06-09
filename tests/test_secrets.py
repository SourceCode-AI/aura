
def test_secret_finder(fixtures, fuzzy_rule_match):
    output = fixtures.scan_test_file('secrets.py')

    assert len(output['hits']) > 0

    matches = [
        {
            'type': 'LeakingSecret',
            'extra': {
                'name': 'user1',
                'secret': 'pass1'
            },
            'line_no': 4
        },
        {
            'type': 'LeakingSecret',
            'extra': {
                'name': 'super_password',
                'secret': 'letmein'
            },
            'line_no': 7
        },
        {
            'type': 'LeakingSecret',
            'extra': {
                'name': 'auth_token',
                'secret': 'RATATATAXXX'
            },
            'line_no': 5
        },
        {
            'type': 'LeakingSecret',
            'extra': {
                'name': 'password',
                'secret': 'cmp_toor'
            },
            # FIXME: line_no missing?
        }
    ]

    for x in matches:
        assert any(fuzzy_rule_match(h, x) for h in output['hits']), x

    no_match = [
        {
            'type': 'LeakingSecret',
            'extra': {
                'secret': 'secret_key_var'
            }
        }
    ]
    for x in no_match:
        for h in output['hits']:
            assert not fuzzy_rule_match(h, x)
