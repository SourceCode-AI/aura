import pytest

import zipfile
import tarfile
import tempfile

from aura.analyzers.rules import Rule
from aura.analyzers import archive


def test_suspicious_files():
    ret = archive.is_suspicious(pth='/etc/shadow', location='something')
    assert ret is not None
    # TODO: add fuzzy rule match
    assert isinstance(ret, Rule)

    ret = archive.is_suspicious(pth='test/../../../../../../etc/shadow', location='something')
    assert ret is not None
    # TODO: add fuzzy rule match
    assert isinstance(ret, Rule)

    ret = archive.is_suspicious('pkg-dist/RECORDS', location='something')
    assert ret is None
    # TODO: add fuzzy rule match
    assert not isinstance(ret, Rule)


def test_zip_extractor(fixtures):
    result = fixtures.scan_test_file('evil.zip')


def test_zip_bomb(fixtures, fuzzy_rule_match):
    matches = [
        {
            'type': 'ArchiveAnomaly',
            'message': "Archive contain a file that exceed the configured maximum size",
            'extra': {
                'archive_path': f'book {x}.zip'
            }
        } for x in '123456789abcdef'
    ]

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


@pytest.mark.timeout(3)
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
