import os


def setup_module(module):
    os.environ["AURA_ALL_MODULE_IMPORTS"] = "true"


def teardown_module(module):
    del os.environ["AURA_ALL_MODULE_IMPORTS"]


def test_setup(fixtures):
    matches = [
        {
            'type': 'SetupScript',
            'message': 'Code execution capabilities found in a setup.py script',
            'line_no': 12
        },
        {
            'type': 'SetupScript',
            'message': 'Found code with network communication capabilities in a setup.py script',
            'line_no': 2
        }
    ]

    fixtures.scan_and_match('setup.py', matches)
