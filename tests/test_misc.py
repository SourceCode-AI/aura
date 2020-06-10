
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
        {
            "type": "FunctionCall",
            "extra": {"function": "pickle.loads"},
            "tags": ["test-code", "dangerous_pickle", "pickle_usage"],
            "line": "pickle.loads(dumped)"
        },
        {
            "type": "Rule",
            "message": "Usage of __reduce__ in an object indicates a possible pickle exploit",
            "line": "def __reduce__(self):",
            "tags": ["test-code", "__reduce__"]
        }
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


def test_different_source_code_encoding(fixtures):
    matches = [
        {
            "type": "FunctionCall",
            "extra": {
                "function": "eval"
            }
        }
    ]
    fixtures.scan_and_match("encoding_ISO_8859_2.py", matches=matches)


def test_fs_structure_detections(fixtures, fuzzy_rule_match, tmp_path):
    files = {
        "bytecode.pyc": "some_bytecode_content",
        ".pypirc": "pypirc_content",
        ".empty.txt": ""
    }

    for filename, content in files.items():
        with (tmp_path/filename).open("w") as fd:
            fd.write(content)

    matches = [
        {
            "type": "SuspiciousFile",
            "message": "A potentially suspicious file has been found",
            "tags": ["python_bytecode"],
            "extra": {
                "file_name": "bytecode.pyc",
                "file_type": "python_bytecode"
            }
        },
        {
            "type": "SuspiciousFile",
            "message": "A potentially suspicious file has been found",
            "tags": ["hidden_file"],
            "extra": {
                "file_name": ".pypirc",
                "file_type": "hidden_file"
            }
        },
        {
            "type": "SensitiveFile",
            "message": "A potentially sensitive file has been found",
            "tags": ["sensitive-file"],
            "extra": {
                "file_name": ".pypirc"
            }
        }
    ]

    output = fixtures.scan_test_file(str(tmp_path))

    for m in matches:
        assert any(fuzzy_rule_match(x, m) for x in output["detections"]), m

    exclude = {
        "extra": {
            "file_name": ".empty.txt"
        }
    }
    assert not any(fuzzy_rule_match(x, exclude) for x in output["detections"])
