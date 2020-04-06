
def test_setup(fixtures):
    matches = [
        {
            'type': 'SetupScript',
            'message': 'Code execution capabilities found in a setup.py script',
            'line_no': 12
        },
        {
            'type': 'SetupScript',
            'message': 'Imported module with network communication capabilities in a setup.py script',
            'line_no': 2
        }
    ]

    fixtures.scan_and_match('setup.py', matches)
