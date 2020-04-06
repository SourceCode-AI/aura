import pytest

from urllib.parse import urlparse

from aura import mirror
from aura import exceptions
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

    # Test explicit mirror path, should be the same
    m2 = mirror.LocalMirror(simulate_mirror)
    assert packages == set(x.name for x in m2.list_packages())


def test_mirror_uri_handler(simulate_mirror):
    handler = umirror.MirrorHandler(urlparse("mirror://wheel"))
    assert handler.package_name == "wheel"
    assert handler.opts["release"] == "latest"
    assert isinstance(handler.metadata, dict)

    paths = list(handler.get_paths())
    assert len(paths) == 2
    filenames = set(x.filename for x in paths)
    assert {"wheel-0.34.2-py2.py3-none-any.whl", "wheel-0.34.2.tar.gz"} == filenames


def test_mirror_uri_variations(simulate_mirror):
    # Does not exists
    with pytest.raises(exceptions.NoSuchPackage):
        _ = umirror.MirrorHandler(urlparse("mirror://does_not_exists"))
