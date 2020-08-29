import pytest
from pathlib import Path

from aura.pattern_matching import FilePatternMatcher
from aura.uri_handlers.base import ScanLocation


CASES = (  # (<pattern_definition:dict>, <test_file_path:str>, <should_pattern_match:bool>)
    (
        {
            "type": "regex",
            "pattern": "^test(_.+|s)?$",
            "target": "part"
        },
        "/some/path/test_full.py",
        True
    ),
    (
        {
            "type": "regex",
            "pattern": "^test(_.+|s)?$",
            "target": "part"
        },
        "/some/path/tests/full.py",
        True
    ),
    (
        {
            "type": "regex",
            "pattern": "^test(_.+|s)?$",
            "target": "part"
        },
        "/some/path/full.py",
        False
    ),
    (
        {
            "type": "exact",
            "pattern": "/blah/something",
        },
        "/blah/something",
        True
    ),
    (
        {
            "type": "exact",
            "pattern": "/blah/something",
            "target": "full"  # This is the same as the default target is "full"
        },
        "/blah/something",
        True
    ),
    (
        {
            "type": "exact",
            "pattern": "/blah/something",
        },
        "prefix/blah/something",
        False
    ),
    (
        {
            "type": "exact",
            "pattern": "file.txt",
            "target": "filename"
        },
        "/som/path/file.txt",
        True
    ),
    (
        {
            "type": "exact",
            "pattern": "file.txt",
            "target": "filename"
        },
        "/som/path/file.txt/something",
        False
    )
)


@pytest.mark.parametrize("pattern,path,should_match", CASES)
def test_file_patterns(pattern: str, path: str, should_match: bool):
    p = FilePatternMatcher(pattern)
    loc = ScanLocation(location=Path(path))

    assert p.match(loc) is should_match

