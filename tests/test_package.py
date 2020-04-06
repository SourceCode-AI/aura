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
