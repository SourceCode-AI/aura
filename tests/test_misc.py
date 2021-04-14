import os
import codecs
import uuid
from unittest.mock import patch

import pytest

from aura import utils
from aura.uri_handlers.base import ScanLocation
from aura.analyzers import fs_struct


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
            "type": "ReDoS",
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


@pytest.mark.e2e
@patch("aura.analyzers.fs_struct.enable_suspicious_files", return_value=True)
def test_fs_structure_detections(fs_mock, fixtures, tmp_path):
    files = {
        "bytecode.pyc": "some_bytecode_content",
        # FIXME: ".pypirc": "pypirc_content",
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
    <<: *aura_config  # test comment
    test_key: test_val
    async: nope
"""
    cfg_pth.write_text(cfg_content)
    try:
        os.environ["AURA_CFG"] = str(cfg_pth)

        from aura import config

        config.CFG_PATH = config.find_configuration()
        config.load_config()
        assert config.CFG["aura"]["test_key"] == "test_val"
        # Inherited key
        assert config.CFG["aura"]["text-output-width"] == "auto"
        # Overwritten key
        assert config.CFG["aura"]["async"] == "nope"
    finally:
        del os.environ["AURA_CFG"]
        config.CFG_PATH = config.find_configuration()
        config.load_config()


def test_custom_signatures(tmp_path):
    sig_pth = tmp_path / "custom_sig.yml"
    sig_content = """---
patterns:
    - <<: *default_patterns
    - id: test_sig_pattern
      pattern: "super_sig(...)"
"""

    sig_pth.write_text(sig_content)
    try:
        os.environ["AURA_SIGNATURES"] = str(sig_pth)

        from aura import config

        config.load_config()
        sig = config.SEMANTIC_RULES["patterns"][-1]
        assert sig["id"] == "test_sig_pattern"

        first = config.SEMANTIC_RULES["patterns"][0]
        assert first["id"] == "flask_run_debug"

    finally:
        del os.environ["AURA_SIGNATURES"]
        config.load_config()


def test_base64_payload_finder(tmp_path, fixtures):
    content = ";".join([str(uuid.uuid4()) for _ in range(25)])
    b64 = codecs.encode(content.encode(), "base64").decode().replace("\n", "")
    assert type(b64) is str
    payload = f"variable = sssshhh('{b64}')"

    fname = (tmp_path/"test_file.py")
    fname.write_text(payload)

    match = {
        "type": "Base64Blob",
        "extra": {
            "base64_decoded": content
        },
        "message": "Base64 data blob found",
        "tags": ["base64"]
    }

    fixtures.scan_and_match(str(fname), matches=[match])


@pytest.mark.parametrize("size,expected", (
        ("1", 1),
        ("42", 42),
        ("1GB", 1024**3),
        ("1G", 1024**3)
))
def test_size_conversion(size: str, expected: int):
    output = utils.convert_size(size)
    assert output == expected



@pytest.mark.parametrize("metadata, expected", (
        ({}, False),
        ({"suspicious_files": True}, True),
        ({"suspicious_files": False}, False),
        ({"scheme": "pypi"}, True),
        ({"scheme": "mirror"}, True),
        ({"scheme": "local"}, False),
        ({"scheme": "local", "suspicious_files": True}, True),
        ({"scheme": "pypi", "suspicious_files": False}, False)
))
def test_suspicious_file_trigger(metadata, expected):
    loc = ScanLocation("does_not_exists", metadata=metadata)
    assert fs_struct.enable_suspicious_files(location=loc) is expected
