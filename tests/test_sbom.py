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
    ("badboy", "pkg:pypi/badboy")
))
def test_get_package_purl(package_name, purl, mock_pypi_rest_api):
    mock_pypi_rest_api(responses)

    pkg = package.PypiPackage.from_cached(package_name)
    output = sbom.get_package_purl(pkg)
    assert output == purl


@responses.activate
def test_get_component(mock_pypi_rest_api):
    mock_pypi_rest_api(responses)
    expected = {
        "name": "wheel",
        "type": "library",
        "purl": "pkg:pypi/wheel@0.2",
        "version": "0.2",
        "licenses": [{"license": {"id": "MIT"}}],
        "hashes": [
            {"alg": "MD5", "content": "96d458e73e65f87c1354c78e2145ce30"},
            {"alg": "SHA-256", "content": "82026a421ca379affefa9a0cb85807047e7184574a92f406670b2dcc3384da36"}
        ]
    }

    pkg = package.PypiPackage.from_cached("wheel")
    pkg.opts["version"] = "0.2"
    component = sbom.get_component(pkg)
    assert component == expected
