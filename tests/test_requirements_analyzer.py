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
        }
    ]
    fixtures.scan_and_match('requirements-test.txt', matches)
