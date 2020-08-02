
def test_secret_finder(fixtures, fuzzy_rule_match):
    output = fixtures.scan_test_file('secrets.py')

    assert len(output['detections']) > 0

    matches = [
        {
            'type': 'LeakingSecret',
            'extra': {
                'name': 'user1',
                'secret': 'pass1'
            },
            'line': "requests.get('https://api.github.com/user', auth=HTTPBasicAuth('user1', 'pass1'))"
        },
        {
            'type': 'LeakingSecret',
            'extra': {
                'name': 'super_password',
                'secret': 'letmein'
            },
            "line": 'super_password = "letmein"'
        },
        {
            'type': 'LeakingSecret',
            'extra': {
                'name': 'auth_token',
                'secret': 'RATATATAXXX'
            },
            "line": "requests.get('https://api.github.com/user?auth_token=RATATATAXXX', auth=('user2', 'pass2'))"
        },
        {
            'type': 'LeakingSecret',
            'extra': {
                'name': 'password',
                'secret': 'cmp_toor'
            },
            "line": 'if password == "cmp_toor":'
        }
    ]

    for x in matches:
        assert any(fuzzy_rule_match(h, x) for h in output['detections']), x

    no_match = [
        {
            'type': 'LeakingSecret',
            'extra': {
                'secret': 'secret_key_var'
            }
        }
    ]
    for x in no_match:
        for h in output['detections']:
            assert not fuzzy_rule_match(h, x)
