import resource

from aura import config
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
    from aura import config

    resource.setrlimit(resource.RLIMIT_FSIZE, (16384, 16384))

    fsize_limit = config.CFG["aura"]["rlimit-fsize"]
    try:
        config.CFG["aura"]["rlimit-fsize"] = "16384"
        # Fingers crossed
        output = fixtures.scan_test_file('zip_bomb.zip')
    finally:
        config.CFG["aura"]["rlimit-fsize"] = fsize_limit

    hits = [
        {
            'type': 'ArchiveAnomaly',
            'message': "Archive contain a file that exceed the configured maximum size",
            'extra': {
                'archive_path': f'book {x}.zip'
            }
        } for x in '123456789abcdef'
    ]

    for x in hits:
        assert any(fuzzy_rule_match(h, x) for h in output['hits'])
