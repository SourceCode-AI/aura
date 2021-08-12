import responses


@responses.activate
def test_requirements_generic(fixtures, mock_pypi_rest_api):
    mock_pypi_rest_api(responses)

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
            "message": "Package requests is unpinned",
            "extra": {
                "package": "requests"
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
