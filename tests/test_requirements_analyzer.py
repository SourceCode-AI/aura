def test_requirements_generic(fixtures):
    matches = [
        {
            'type': 'OutdatedPackage',
            'extra': {
                'package': 'wheel'
            },
            'tags': ['outdated_package']
        },
        {
            'type': "UnpinnedPackage",
            "message": "Package six is unpinned",
            "extra": {
                "package": "six"
            },
            "tags": ["unpinned_package"]
        },
        {
            "type": "InvalidRequirement",
            "extra": {
                "line": ".[test]"
            },
            "message": "Could not parse the requirement for analysis"
        }
    ]
    fixtures.scan_and_match('requirements-test.txt', matches)
