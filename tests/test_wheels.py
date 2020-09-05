def test_wheel_analyzer(fixtures):
    matches = [
        {
            'type': 'Wheel',
            'message': "Wheel contain a file not listed in the RECORDs",
            'tags': ['wheel', 'anomaly', 'missing_record_file']
        },
        {
            'type': 'Wheel',
            'message': "Wheel anomaly detected, invalid record checksum",
            'tags': ['wheel', 'anomaly']
        },
        {
            'type': 'Wheel',
            'message': "Found setup.py in a wheel archive",
            'tags': ['wheel', 'anomaly', 'setup.py']
        }
    ]

    fixtures.scan_and_match("djamgo-0.0.1-py3-none-any.whl", matches)
