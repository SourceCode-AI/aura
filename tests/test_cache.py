import json
import uuid
from unittest import mock

import pytest

from aura import cache
from aura import mirror
from aura import exceptions



@pytest.mark.parametrize("url,cache_id", (
        ("https://google.com/", "f82438a9862a39d642f39887b3e8e5b4"),
))
def test_url_cache_ids(url, cache_id):
    computed = cache.URLCache.cache_id(url=url)
    assert computed == cache_id


@mock.patch("aura.cache.Cache.get_location")
def test_cache_mock_location(cache_mock, tmp_path):
    cache_mock.return_value = tmp_path
    assert cache.Cache.get_location() == tmp_path


@mock.patch("aura.cache.Cache.get_location")
@pytest.mark.parametrize("filename,content,cache_id,call", (
        ("testjson_file", "json_content", "mirrorjson_testjson_file", cache.MirrorJSON.proxy),
        ("testpkg_file", "pkg_content", "mirror_testpkg_file", cache.Cache.proxy_mirror)
))
def test_proxy_mirror_json(cache_mock, tmp_path, filename, content, cache_id, call):
    f = tmp_path / filename
    cache_path = tmp_path / "cache"
    cache_path.mkdir()
    cache_file = cache_path/cache_id
    cache_mock.return_value = cache_path

    assert f.exists() is False
    out = call(src=f)
    assert out == f
    assert cache_file.exists() is False
    assert len(list(cache_path.iterdir())) == 0

    f.write_text(content)
    assert f.exists() is True
    out = call(src=f)
    assert out != f
    assert out == cache_file
    assert len(list(cache_path.iterdir())) == 1
    assert out.read_text() == content

    # Make sure the cache does not attempt to do any kind of file access if the cache entry exists
    m = mock.MagicMock(spec_set=("name",), side_effect=ValueError("Call prohibited"))
    m.name = filename
    out = call(src=m)
    assert out == cache_file

    # Original path should be returned if cache is disabled
    cache_mock.return_value = None
    out = call(src=f)
    assert out == f


@mock.patch("aura.cache.Cache.get_location")
@pytest.mark.e2e
def test_mirror_cache(cache_mock, fixtures, simulate_mirror, tmp_path):
    cache_content = list(tmp_path.iterdir())
    assert len(cache_content) == 0

    cache_mock.return_value = tmp_path
    assert cache.Cache.get_location() == tmp_path
    out = fixtures.get_cli_output(['scan', '--download-only', 'mirror://wheel', '-f', 'json'])

    parsed_output = json.loads(out.stdout)
    assert len(parsed_output["detections"]) == 0

    cache_content = list(x.name for x in tmp_path.iterdir())
    assert len(cache_content) > 0
    assert "mirror_wheel-0.34.2.tar.gz" in cache_content, cache_content
    assert "mirror_wheel-0.34.2-py2.py3-none-any.whl" in cache_content


@mock.patch("aura.cache.Cache.get_location")
@mock.patch("aura.mirror.LocalMirror.get_mirror_path")
def test_mirror_cache_no_remote_access(mirror_mock, cache_mock, fixtures, tmp_path):
    """
    Test that if the content is fully cached, the mirror uri handler does not attempt to access the mirror but rather retrieves **all** content from cache only
    This is mainly to test correctness of prefetching the data for global PyPI scan to ensure no further network calls are made
    """
    pkg = str(uuid.uuid4())
    pkg_content = {"id": pkg}
    mirror_path = tmp_path / "mirror"
    cache_path = tmp_path / "cache"
    cache_path.mkdir()
    cache_mock.return_value = cache_path
    mirror_mock.return_value = mirror_path
    m = mirror.LocalMirror()

    assert cache.Cache.get_location() == cache_path
    assert m.get_mirror_path() == mirror_path
    assert mirror_path.exists() == False

    with pytest.raises(exceptions.NoSuchPackage):
        m.get_json(pkg)

    (cache_path/f"mirrorjson_{pkg}").write_text(json.dumps(pkg_content))
    out = m.get_json(pkg)
    assert out == pkg_content
