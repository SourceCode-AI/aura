
def test_secret_finder(fixtures, fuzzy_rule_match):
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

    no_match = [
        {
            'type': 'LeakingSecret',
            'extra': {
                'secret': 'secret_key_var'
            }
        }
    ]

    fixtures.scan_and_match("secrets.py", matches=matches, excludes=no_match)
