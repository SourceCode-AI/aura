# TODO: test __reduce__ detection
# TODO: test pickle.loads detection


def test_misc_signatures(fixtures):
    matches = [
        {
            "type": "FunctionCall",
            "extra": {"function": "tempfile.mktemp"},
            "line": "temp_file = m()",
            "message": "Usage of tempfile.mktemp is susceptible to race conditions!",
        },
        {
            "type": "FunctionCall",
            "extra": {"function": "os.system"},
            "tags": ["test-code", "system_execution"],
            "line": 'os.system("echo Hello world")'
        },
    ]

    fixtures.scan_and_match("misc.py", matches)


def test_redos(fixtures):
    hit_locations = {
        1: r'(a*)*',
        2: r'((a+|b)c?)+',
        3: r'(x+x+)+y',
        4: r'(.|[abc])+z'
    }

    matches = [
        {
            "type": "Rule",
            "extra": {
                "type": "redos",
                "regex": regex
            },
            "line_no": line_no
        } for (line_no, regex) in hit_locations.items()
    ]
    fixtures.scan_and_match("redos.py", matches=matches)

    # TODO: test that clean regexes don't trigger redos
