import uuid
import os
import datetime
import tempfile
from unittest.mock import Mock
from xmlrpc import client as xml_client

import responses
import pytz
import pytest

from aura import package
from aura import exceptions


def test_non_existing_package():
    with pytest.raises(exceptions.NoSuchPackage):
        package.PypiPackage.from_pypi(f"does_not_exists_{str(uuid.uuid4())}")


def test_version_constrains(simulate_mirror):
    pkg = package.PypiPackage.from_pypi("wheel")

    latest = "0.34.2"
    assert pkg.get_latest_release() == latest
    assert pkg.find_release(find_highest=True) == latest
    assert pkg.find_release(constrains=((">", "0.34.0"),("<", "0.35")), find_highest=True) == latest
    assert pkg.find_release(constrains=(("==", "0.34.2"),)) == latest

    v1 = pkg.find_release(constrains=(("==", "0.34.2"),), find_highest=False)
    assert len(v1) == 1

    assert pkg.find_release(constrains=((">", "0.10"), ("<", "0.29"))) == "0.28.0"


def test_package_listing():
    existing = {
        "requests",
        "django",
    }

    xml_client.ServerProxy = Mock()
    instance = xml_client.ServerProxy.return_value
    instance.list_packages.return_value = existing

    on_pypi = set(x.lower() for x in package.PypiPackage.list_packages())

    assert len(existing.difference(on_pypi)) == 0


@responses.activate
def test_package_retrieval(mock_pypi_rest_api):
    mock_pypi_rest_api(responses)
    pkg = package.PypiPackage.from_pypi("wheel")
    url = "https://files.pythonhosted.org/packages/8c/23/848298cccf8e40f5bbb59009b32848a4c38f4e7f3364297ab3c3e2e2cd14/wheel-0.34.2-py2.py3-none-any.whl"

    with pkg.url2local(url) as location:
        assert location.is_file()
        file_name = url.split("/")[-1]
        assert location.name.endswith(file_name), (location, file_name)

    with tempfile.TemporaryDirectory(prefix="aura_pytest_") as tmp:
        downloaded = pkg.download_release(tmp)
        content = os.listdir(tmp)

    assert "wheel-0.34.2.tar.gz" in downloaded
    assert "wheel-0.34.2.tar.gz" in content
    assert "wheel-0.34.2-py2.py3-none-any.whl" in downloaded
    assert "wheel-0.34.2-py2.py3-none-any.whl" in content


@responses.activate
def test_package_score(mock_github, mock_pypi_rest_api):
    mock_github(responses)
    mock_pypi_rest_api(responses)

    pkg = package.PackageScore("requests")
    pkg.now = pytz.UTC.localize(datetime.datetime.fromisoformat("2020-04-18T14:21:43.572676"))

    assert pkg.package_name == "requests"
    assert pkg.pkg.info["info"]["name"] == "requests"
    assert pkg.github is not None
    assert pkg.github.owner == "psf"
    assert pkg.github.name == "requests"

    matrix = pkg.get_score_matrix()
    assert matrix["contributors"] == 2
    assert matrix["forks"] == 4
    assert matrix["github_stars"] == 5
    assert matrix["has_documentation"] == 1
    assert matrix["has_homepage"] == 1
    assert matrix["has_sdist_source"] == 1
    assert matrix["has_source_repository"] == 1
    assert matrix["has_wheel"] == 1
    assert matrix["is_new"] == 1
    assert matrix["last_commit"] == 1
    assert matrix["multiple_releases"] == 1
    assert matrix["total"] == 19

    # Make the package seem outdated
    pkg.now = pytz.UTC.localize(
        datetime.datetime.utcnow() + datetime.timedelta(365)
    )
    matrix = pkg.get_score_matrix()
    assert matrix["last_commit"] == 0


@responses.activate
def test_bad_package_score(mock_github, mock_pypi_rest_api):
    mock_pypi_rest_api(responses)
    mock_github(responses)

    pkg = package.PackageScore("badboy")

    matrix = pkg.get_score_matrix()
    assert matrix["total"] == 0
