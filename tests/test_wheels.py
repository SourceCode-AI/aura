from click.testing import CliRunner

from aura import cli


def test_wheel_analyzer(fixtures, fuzzy_rule_match):
    output = fixtures.scan_test_file('djamgo-0.0.1-py3-none-any.whl')

    hits = [
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

    assert len(output['hits']) > 0

    for x in hits:
        assert any(fuzzy_rule_match(h, x) for h in output['hits'])
