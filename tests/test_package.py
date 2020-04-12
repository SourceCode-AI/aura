import pytest
import uuid

from aura import package
from aura import exceptions


def test_non_existing_package():
    with pytest.raises(exceptions.NoSuchPackage):
        package.PypiPackage.from_pypi(f"does_not_exists_{str(uuid.uuid4())}")

# TODO
def disabled_test_version_constrains(simulate_mirror):
    pkg = package.PypiPackage.from_local_mirror("wheel")

    latest = "0.34.2"
    assert pkg.get_latest_release() == latest
    assert pkg.find_release(find_highest=True) == latest
    assert pkg.find_release(constrains=((">", "0.34.0"),("<", "0.35")), find_highest=True) == latest
    assert pkg.find_release(constrains=(("==", "0.34.2"),)) == latest

    v1 = pkg.find_release(constrains=(("==", "0.34.2"),), find_highest=False)
    assert len(v1) == 1

    assert pkg.find_release(constrains=((">", "0.10"), ("<", "0.29"))) == "0.19.0"


def test_package_listing():
    existing = {
        "requests",
        "django",
    }

    on_pypi = set(x.lower() for x in package.PypiPackage.list_packages())

    assert len(existing.difference(on_pypi)) == 0


def disabled_test_package_retrieval():
    pkg = package.PypiPackage.from_pypi("wheel")
    url = "https://files.pythonhosted.org/packages/8c/23/848298cccf8e40f5bbb59009b32848a4c38f4e7f3364297ab3c3e2e2cd14/wheel-0.34.2-py2.py3-none-any.whl"

    with pkg.url2local(url) as location:
        assert location.is_file()
        file_name = url.split("/")[-1]
        assert location.name == file_name
