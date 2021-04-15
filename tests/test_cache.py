import io
import json
import uuid
from unittest import mock
from pathlib import Path
from urllib.parse import urlparse
from contextlib import ExitStack

import pytest
import responses

from aura import config
from aura import cache
from aura import mirror
from aura import exceptions
from aura.uri_handlers.base import URIHandler


CACHE_ENTRIES = {
    "mirror/wheel-0.33.0-py2.py3-none-any.whl": {"type": "mirrorfile"}
}


def create_cache_entry(arg: str, metadata: dict, fixtures) -> cache.Cache:
    if metadata["type"] == "mirrorfile":
        c = cache.MirrorFile(src=Path(fixtures.path(arg)), tags=metadata.get("tags"))
        c.fetch()
        assert c.is_valid
        assert c.metadata_location.exists()
        return c


@pytest.mark.parametrize("url,cache_id", (
        ("https://google.com/", "f82438a9862a39d642f39887b3e8e5b4"),
))
def test_url_cache_ids(url, cache_id):
    computed = cache.FileDownloadCache.cache_id(url=url)
    assert computed == cache_id


@mock.patch("aura.cache.Cache.get_location")
@pytest.mark.parametrize("filename,content,cache_id,call", (
        ("testjson_file", "json_content", "mirrorjson_testjson_file", cache.MirrorJSON.proxy),
        ("testpkg_file", "pkg_content", "mirror_testpkg_file", cache.MirrorFile.proxy)
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
    assert len(list(x for x in cache_path.iterdir() if not x.name.endswith(".metadata.json"))) == 1
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


@pytest.mark.e2e
def test_mirror_cache(fixtures, simulate_mirror, mock_cache):
    out = fixtures.get_cli_output(['scan', '--download-only', 'mirror://wheel', '-f', 'json'])

    parsed_output = json.loads(out.stdout)
    assert len(parsed_output["detections"]) == 0

    cache_content = [
        x.item_path.name
        for x in cache.CacheItem.iter_items()
    ]

    assert len(cache_content) > 0
    assert "mirror_wheel-0.34.2.tar.gz" in cache_content, cache_content
    assert "mirror_wheel-0.34.2-py2.py3-none-any.whl" in cache_content


@pytest.mark.parametrize("file_path", (
    "crypto.py",
    "evil.tar.gz",
    "djamgo-0.0.1-py3-none-any.whl",
    "sarif-schema.json"
))
def test_mirror_cache_paths(file_path, fixtures, mock_cache):
    pth = Path(fixtures.path(file_path))
    exc = RuntimeError("failed")
    assert pth.exists()

    mock_pth = mock.Mock(spec=pth, wraps=pth)
    mock_pth.exists.side_effect = exc
    mock_pth.name = pth.name

    cached = cache.MirrorFile.proxy(src=pth)
    assert cached != pth
    assert cached != mock_pth

    with mock.patch.object(cache.MirrorFile, "fetch", side_effect=exc):
        cached2 = cache.MirrorFile.proxy(src=mock_pth)

    assert cached2 == cached

    cache_obj = cache.MirrorFile(src=pth)
    assert cache_obj.is_valid is True
    assert cache_obj.cache_file_location == cached
    assert cache_obj.cache_file_location.exists()
    assert cache_obj.metadata_location.exists()

    cache_obj.delete()
    assert not cache_obj.cache_file_location.exists()
    assert not cache_obj.metadata_location.exists()
    assert cache_obj.is_valid is False


def test_mirror_no_remote_access(simulate_mirror, mock_cache):
    uri = "mirror://wheel"
    exc = RuntimeError("test failed")

    assert str(mirror.LocalMirror.get_mirror_path()) == simulate_mirror
    assert cache.MirrorFile.get_location() is not None

    handler = URIHandler.from_uri(uri)
    paths = tuple(handler.get_paths())
    assert len(paths) > 0

    for path in paths:
        assert path.location.exists()
        path = str(path.location)
        assert not path.startswith(simulate_mirror)


    with ExitStack() as stack:
        # Mock any remote file access functionality to throw an exception
        shutil_mock = stack.enter_context(mock.patch("aura.cache.shutil"))
        shutil_mock.copyfile.side_effect = exc
        fetch_mock = stack.enter_context(mock.patch("aura.cache.MirrorFile.fetch", side_effect=exc))

        handler_cached = URIHandler.from_uri(uri)
        paths_cached = tuple(handler_cached.get_paths())

    assert paths == paths_cached


@mock.patch("aura.cache.get_cache_threshold")
@pytest.mark.parametrize("threshold", (0, 10))
def test_cache_purge(tmock, threshold, tmp_path, fixtures, mock_cache):
    tmock.return_value = threshold

    for k, v in CACHE_ENTRIES.items():
        create_cache_entry(k, v, fixtures=fixtures)

    items = list(cache.CacheItem.analyze())
    cache.CacheItem.cleanup(items=items)
    total = sum(x.size for x in items if not x._deleted)
    assert total <= threshold


@mock.patch("aura.cache.CacheItem.cleanup")
@pytest.mark.parametrize("mode,confirm,standard,run_cleanup", (
    ("ask", False, True, False),
    ("ask", True, True, True),
    ("ask", True, False, False),
    ("ask", False, False, False),
    ("auto", False, True, True),
    ("auto", True, False, False),
    ("always", False, True, True),
    ("always", False, False, True)
))
def test_purge_modes(cleanup_mock, mode, confirm, standard, run_cleanup, confirm_prompt):
    confirm_prompt.return_value = confirm

    with mock.patch.dict(config.CFG["cache"], values={"mode": mode}, clear=True):
        with mock.patch.object(cache.Cache, "DISABLE_CACHE", new=False):
            cache.purge(standard=standard)

    if run_cleanup:
        cleanup_mock.assert_called_once()
    else:
        cleanup_mock.assert_not_called()


@mock.patch("aura.cache.CacheItem.is_expired", new_callable=mock.PropertyMock)
def test_always_delete_expired(exp_mock, mock_cache, fixtures):
    exp_mock.return_value = True

    for k, v in CACHE_ENTRIES.items():
        create_cache_entry(k, v, fixtures=fixtures)

    items = list(cache.CacheItem.analyze())

    cache.CacheItem.cleanup(items=items)

    for x in items:
        assert x.is_expired is True
        assert x._deleted is True


@responses.activate
def test_url_caching(mock_cache):
    payload = "Hello body"
    url = "https://url_cache_test.example.com"

    responses.add(responses.GET, url, body=payload, status=200)

    response = cache.URLCache.proxy(url=url)
    assert response == payload

    cache_items = tuple(cache.CacheItem.iter_items())
    assert len(cache_items) == 1
    assert cache_items[0].metadata["url"] == url

    cache.CacheItem.cleanup()
    assert len(tuple(cache.CacheItem.iter_items())) == 0


@responses.activate
def test_filedownload_caching(mock_cache):
    payload = b"this is some file payload"
    url = "https://url_cache_test.example.com/some_file.tgz"
    fd = io.BytesIO()

    responses.add(responses.GET, url, body=payload, status=200, stream=True)

    cache.FileDownloadCache.proxy(url=url, fd=fd)
    assert fd.getvalue() == payload

    cache_items = tuple(cache.CacheItem.iter_items())
    assert len(cache_items) == 1
    assert cache_items[0].metadata["url"] == url

    cache.CacheItem.cleanup()
    assert len(tuple(cache.CacheItem.iter_items())) == 0


@mock.patch("aura.cache.PyPIPackageList._get_package_list")
def test_pypi_cache(pkg_list_mock, mock_cache):
    pkgs = ["pkg1", "pkg2", "pkg3"]
    pkg_list_mock.return_value = pkgs

    output = cache.PyPIPackageList.proxy()
    assert output == pkgs
    assert pkg_list_mock.called is True
    pkg_list_mock.reset_mock()

    output = cache.PyPIPackageList.proxy()
    assert output == pkgs
    assert pkg_list_mock.called is False

    cache_items = tuple(cache.CacheItem.iter_items())
    assert len(cache_items) == 1
    assert cache_items[0].metadata["type"] == "pypi_package_list"

    cache.CacheItem.cleanup()
    assert len(tuple(cache.CacheItem.iter_items())) == 0


@mock.patch("aura.cache.ASTPatternCache.get_patterns_hash", return_value="sig1")
@mock.patch("aura.cache.ASTPatternCache._compile_all", return_value=[])
def test_ast_cache(ast_compile_mock, patterns_hash_mock, mock_cache):
    # Reset the cache status
    cache.ASTPatternCache._AST_PATTERN_CACHE = None

    assert [] == cache.ASTPatternCache.proxy()
    assert ast_compile_mock.called is True
    ast_compile_mock.reset_mock()

    assert [] == cache.ASTPatternCache.proxy()
    assert ast_compile_mock.called is False

    cache_items = tuple(cache.CacheItem.iter_items())
    assert len(cache_items) == 1
    assert cache_items[0].metadata["type"] == "ast_patterns"

    # Test that cache is invalidated if config hash changes
    patterns_hash_mock.return_value = "sig2"
    ast_compile_mock.return_value = ["changed"]

    assert ["changed"] == cache.ASTPatternCache.proxy()

    # Now there will be two items, the old ast patterns and new ones
    assert len(tuple(cache.CacheItem.iter_items())) == 2

    cache.CacheItem.cleanup()
    assert len(tuple(cache.CacheItem.iter_items())) == 0


@responses.activate
def test_cache_tag_filtering(mock_cache, fixtures):
    def _cb(request):
        return (200, {}, "Hello world")

    responses.add_callback(method=responses.GET, url="http://example.com/tag_test", match_querystring=False, callback=_cb)

    tags = {"tag1", "tag2", "tag3"}

    for tag in tags:
        url = f"http://example.com/tag_test?tag={tag}"
        cache.URLCache.proxy(url=url, tags=[tag])


    all_items = tuple(cache.CacheItem.iter_items())
    assert len(all_items) == len(tags)

    items = tuple(cache.CacheItem.iter_items(tags=["non-existing"]))
    assert len(items) == 0

    items_by_type = tuple(cache.CacheItem.iter_items(tags=["url"]))
    assert len(items_by_type) == len(all_items)

    for tag in tags:
        items = tuple(cache.CacheItem.iter_items(tags=[tag]))
        assert len(items) == 1
        assert tag in items[0].tags
