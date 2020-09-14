import pytest

try:
    import defusedxml
except ImportError:
    pytest.skip("defusedxml package is not installed", allow_module_level=True)


def test_malformed_general(fixtures):
    matches = [
        {
            'score': 20,
            'type': 'MalformedXML',
            'tags': ['malformed_xml', 'test-code', 'xml_dtd'],
            'extra': {'type': 'dtd'},
        },
        {
            'score': 100,
            'type': 'MalformedXML',
            'tags': ['malformed_xml', 'test-code', 'xml_entities'],
            'extra': {'type': 'entities'},
        }
    ]

    fixtures.scan_and_match('malformed_xmls/bomb.xml', matches)
    fixtures.scan_and_match('malformed_xmls/bomb2.xml', matches)
    fixtures.scan_and_match('malformed_xmls/cyclic.xml', matches)


def test_dtd(fixtures):
    matches = [
        {
            'score': 20,
            'type': 'MalformedXML',
            'tags': ['malformed_xml', 'test-code', 'xml_dtd'],
            'extra': {'type': 'dtd'},
        }
    ]

    fixtures.scan_and_match('malformed_xmls/dtd.xml', matches)


def test_external(fixtures):
    matches = [
        {
            'score': 100,
            'type': 'MalformedXML',
            'tags': ['malformed_xml', 'test-code', 'xml_external_reference'],
            'extra': {'type': 'external_reference'},
        }
    ]

    fixtures.scan_and_match('malformed_xmls/external.xml', matches)
    fixtures.scan_and_match('malformed_xmls/external_file.xml', matches)
