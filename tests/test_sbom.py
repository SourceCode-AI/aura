import pytest
import responses

from aura import sbom
from aura import package


@pytest.mark.parametrize("data,expected", (
    ("License :: OSI Approved :: MIT License", "MIT"),
    ("MIT", "MIT"),
    ("does not exists", None),
    ("", None),
))
def test_get_license_identifier(data, expected):
    output = sbom.get_license_identifier(data)
    assert output == expected


@responses.activate
@pytest.mark.parametrize("package_name,license_", (
    ("requests", {"Apache-2.0"}),
    ("requests2", {"Apache-2.0"}),
    ("wheel", {"MIT"}),
    ("badboy", set())
))
def test_get_package_licenses(package_name, license_, mock_pypi_rest_api):
    mock_pypi_rest_api(responses)

    pkg = package.PypiPackage.from_cached(package_name)
    output = sbom.get_package_licenses(pkg)
    assert license_ == output


@responses.activate
@pytest.mark.parametrize("package_name,purl", (
    ("requests", "pkg:pypi/requests@2.24.0"),
    ("requests2", "pkg:pypi/requests2@2.16.0"),
    ("wheel", "pkg:pypi/wheel@0.34.2"),
    ("badboy", "pkg:pypi/badboy@666")
))
def test_get_package_purl(package_name, purl, mock_pypi_rest_api):
    mock_pypi_rest_api(responses)

    pkg = package.PypiPackage.from_cached(package_name)
    output = sbom.get_package_purl(pkg)
    assert output == purl


@responses.activate
def test_get_component(mock_pypi_rest_api, fuzzy_rule_match):
    mock_pypi_rest_api(responses)
    expected = {
        "name": "wheel",
        "type": "library",
        "purl": "pkg:pypi/wheel@0.34.2",
        "version": "0.34.2",
        "licenses": [{"license": {"id": "MIT"}}],
        "hashes": [
            {"alg": "MD5", "content": "8a2e3b6aca9665a0c6abecc4f4ea7090"},
            {"alg": "SHA-256", "content": "df277cb51e61359aba502208d680f90c0493adec6f0e848af94948778aed386e"},
            {"alg": "MD5", "content": "ce2a27f99c130a927237b5da1ff5ceaf"},
            {"alg": "SHA-256", "content": "8788e9155fe14f54164c1b9eb0a319d98ef02c160725587ad60f14ddc57b6f96"}
        ]
    }

    pkg = package.PypiPackage.from_cached("wheel")
    component = sbom.get_component(pkg)
    assert fuzzy_rule_match(component, expected), component

