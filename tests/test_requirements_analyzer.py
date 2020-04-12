def test_requirements_generic(fixtures):
    matches = [
        {
            'type': 'OutdatedRequirement',
            'extra': {
                'package': 'wheel'
            },
            'tags': ['outdated_requirement']
        },
        {
            'type': "UnpinnedRequirement",
            "extra": {
                "package": "six"
            },
            "tags": ["unpinned_requirement"]
        },
        {
            "type": "InvalidRequirement",
            "extra": {
                "line": "invalid can't parse this"
            },
            "message": "Could not parse the requirement for analysis"
        }
    ]
    fixtures.scan_and_match('requirements-test.txt', matches)
