import os
import pytest


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
            "type": "Detection",
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
            "type": "Detection",
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


def test_fs_structure_detections(fixtures, tmp_path):
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
            "tags": ["sensitive_file"],
            "extra": {
                "file_name": ".pypirc"
            }
        }
    ]

    excludes = [{
        "extra": {
            "file_name": ".empty.txt"
        }
    }]

    fixtures.scan_and_match(
        str(tmp_path),
        matches=matches,
        excludes=excludes
    )


def test_custom_config(tmp_path):
    cfg_pth = tmp_path / "custom_cfg.yml"
    cfg_content = """---
aura:
    <<: *aura_config
    test_key: test_val
    async: nope
"""
    cfg_pth.write_text(cfg_content)
    os.environ["AURA_CFG"] = str(cfg_pth)

    from aura import config

    parsed = config.parse_config()
    assert parsed["aura"]["test_key"] == "test_val"
    # Inherited key
    assert parsed["aura"]["text-output-width"] == "auto"
    # Overwritten key
    assert parsed["aura"]["async"] == "nope"
