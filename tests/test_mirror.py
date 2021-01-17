import pytest

from urllib.parse import urlparse

from aura import mirror
from aura import exceptions
from aura.analyzers import fs_struct
from aura.uri_handlers import mirror as umirror


def test_local_mirror(simulate_mirror):
    m = mirror.LocalMirror()

    packages = set(x.name for x in m.list_packages())
    assert "wheel" in packages

    version = "0.34.2"
    pkg_meta = m.get_json("wheel")
    assert isinstance(pkg_meta, dict)
    assert "info" in pkg_meta
    assert pkg_meta["info"]["name"] == "wheel"
    assert pkg_meta["info"]["version"] == version
    assert len(pkg_meta["releases"][version]) == 2

    for pkg_release in pkg_meta["releases"][version]:
        local_path = m.url2local(pkg_release["url"])
        assert local_path.is_file(), local_path
        assert local_path.name == pkg_release["filename"]


def test_mirror_uri_handler(simulate_mirror):
    handler = umirror.MirrorHandler(urlparse("mirror://wheel"))
    assert handler.package_name == "wheel"
    assert handler.opts["release"] == "latest"
    assert isinstance(handler.metadata, dict)

    paths = list(handler.get_paths())
    assert len(paths) == 2
    filenames = set(x.filename for x in paths)
    assert {"wheel-0.34.2-py2.py3-none-any.whl", "wheel-0.34.2.tar.gz"} == filenames


def test_mirror_suspicious_file_trigger(simulate_mirror):
    handler = umirror.MirrorHandler(urlparse("mirror://wheel"))

    for loc in handler.get_paths():
        assert fs_struct.enable_suspicious_files(loc) is True


def test_mirror_uri_variations(simulate_mirror):
    # Does not exists
    with pytest.raises(exceptions.NoSuchPackage):
        _ = umirror.MirrorHandler(urlparse("mirror://does_not_exists"))


def test_mirror_metadata(simulate_mirror):
    uri = urlparse("mirror://wheel")
    handler = umirror.MirrorHandler(uri)

    paths = tuple(handler.get_paths())
    urls = {
        'https://files.pythonhosted.org/packages/75/28/521c6dc7fef23a68368efefdcd682f5b3d1d58c2b90b06dc1d0b805b51ae/wheel-0.34.2.tar.gz',
        'https://files.pythonhosted.org/packages/8c/23/848298cccf8e40f5bbb59009b32848a4c38f4e7f3364297ab3c3e2e2cd14/wheel-0.34.2-py2.py3-none-any.whl'
    }

    for p in paths:
        url = p.metadata["package"]["info"]["url"]
        assert url in urls
        urls.remove(url)

    assert len(urls) == 0
    assert handler.package.source == "local_mirror"
