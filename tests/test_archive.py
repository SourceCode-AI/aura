import zipfile
import tarfile
import tempfile

from aura.analyzers import archive


def test_suspicious_files():
    ret = archive.is_suspicious(pth='/etc/shadow', location='something')
    assert ret is not None
    assert isinstance(ret, archive.SuspiciousArchiveEntry)

    ret = archive.is_suspicious(pth='test/../../../../../../etc/shadow', location='something')
    assert ret is not None
    assert isinstance(ret, archive.SuspiciousArchiveEntry)

    ret = archive.is_suspicious('pkg-dist/RECORDS', location='something')
    assert ret is None
    assert not isinstance(ret, archive.SuspiciousArchiveEntry)


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
