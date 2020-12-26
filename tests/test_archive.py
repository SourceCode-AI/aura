import pytest

import zipfile
import tarfile
import tempfile
from unittest.mock import patch

from aura import config
from aura.analyzers.detections import Detection
from aura.analyzers import archive


@pytest.mark.parametrize(
    "file_path,is_suspicious",
    (
        ("/etc/shadow", True),
        ("test/../../../../../../etc/shadow", True),
        ("hello/../wold", True),
        ("pkg-dist/RECORDS", False),
        ("single_level", False)
    )
)
def test_is_suspicious_file(file_path, is_suspicious, fuzzy_rule_match):
    ret = archive.is_suspicious(pth=file_path, location='something')

    if is_suspicious:
        assert ret is not None
        assert isinstance(ret, Detection)
        match = {
            "type": "SuspiciousArchiveEntry",
            "location": "something",
            "extra": {
                "entry_path": file_path
            }
        }
        assert fuzzy_rule_match(ret, match)
    else:
        assert ret is None


def test_zip_extractor(fixtures):
    result = fixtures.scan_test_file('evil.zip')


def test_zip_bomb(fixtures):
    matches = [
        {
            'type': 'ArchiveAnomaly',
            'message': "Archive contain a file that exceed the configured maximum size",
            'extra': {
                'archive_path': f'book {x}.zip'
            }
        } for x in '123456789abcdef'
    ]
    with patch.object(config, "get_maximum_archive_size", return_value=10) as m:
        fixtures.scan_and_match("zip_bomb.zip", matches=matches)


def test_damaged_zipfile(fixtures):
    matches = [
        {
            "type": "ArchiveAnomaly",
            "message": "Could not open the archive for analysis",
            "extra": {
                "reason": "archive_read_error"
            }
        }
    ]

    with tempfile.TemporaryDirectory(prefix="aura_pytest_") as tmpd:
        pth = f"{tmpd}/archive.zip"

        with zipfile.ZipFile(pth, "w") as fd:
            fd.writestr("foo.txt", b"O, for a Muse of Fire!")

        with open(pth, "wb") as fd:
            fd.seek(10, 2)
            fd.write(b"0"*5)

        fixtures.scan_and_match(pth, matches=matches)


def test_damaged_tarfile(fixtures):
    matches = [
        {
            "type": "ArchiveAnomaly",
            "message": "Could not open the archive for analysis",
            "extra": {
                "reason": "archive_read_error",
                "exc_message": "file could not be opened successfully",
                "mime": "application/gzip"
            }
        }
    ]

    fixtures.scan_and_match("common-passwords.txt.gz", matches=matches)


def test_recursive_bomb(fixtures):
    matches = [
        {
            "type": "DataProcessing",
            "extra": {
                "reason": "max_depth"
            },
            "message": "Maximum processing depth reached"
        }
    ]
    fixtures.scan_and_match("recursive_bomb.tar.gz", matches=matches)
