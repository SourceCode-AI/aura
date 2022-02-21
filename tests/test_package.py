import uuid
import datetime
from unittest.mock import patch

import responses
import pytz
import pytest

from aura import package
from aura.uri_handlers.base import URIHandler
from aura import exceptions


REQUESTS_DEPS = [str(uuid.uuid4()) for _ in range(2896)]  # Mock `requests` reverse dependencies for pacakge score matrix


@responses.activate
def test_non_existing_package(mock_pypi_rest_api):
    mock_pypi_rest_api(responses)
    with pytest.raises(exceptions.NoSuchPackage):
        package.PypiPackage.from_cached(f"does_not_exists_{str(uuid.uuid4())}")


@responses.activate
def test_package_info(mock_pypi_rest_api):
    mock_pypi_rest_api(responses)
    pkg = package.PypiPackage.from_cached("wheel")

    repo_url = "https://github.com/pypa/wheel"

    assert pkg.homepage_url == repo_url
    assert pkg.source_url == repo_url
    assert pkg.documentation_url == "https://wheel.readthedocs.io/"

    deps = list(pkg.get_dependencies())
    dep_names = [x.name for x in deps]
    assert "pytest" in dep_names
    assert "pytest-cov" in dep_names


@responses.activate
@patch("aura.package.get_reverse_dependencies", return_value=REQUESTS_DEPS)
def test_package_score(mock1, mock_github, mock_pypi_rest_api, mock_pypi_stats):
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

    scores = {x["slug"]: x["normalized"] for x in matrix["entries"]}

    assert scores["github_contributors"] == 2
    assert scores["github_forks"] == 4
    assert scores["github_stars"] == 5
    assert scores["has_documentation"] == 1
    assert scores["has_homepage"] == 1
    assert scores["has_sdist"] == 1
    assert scores["has_source_repository"] == 1
    assert scores["has_wheel"] == 1
    assert scores["new_on_github"] == 1
    assert scores["recent_commit"] == 1
    assert scores["multiple_releases"] == 3
    assert matrix["total"] >= 19

    # Make the package seem outdated
    pkg.now = pytz.UTC.localize(
        datetime.datetime.utcnow() + datetime.timedelta(365)
    )
    matrix = pkg.get_score_matrix()
    scores = {x["slug"]: x["normalized"] for x in matrix["entries"]}
    assert scores["recent_commit"] == 0


@responses.activate
@patch("aura.package.get_reverse_dependencies", return_value=[])
def test_bad_package_score(mock1, mock_github, mock_pypi_rest_api, mock_pypi_stats):
    mock_pypi_rest_api(responses)
    mock_github(responses)

    pkg = package.PackageScore("badboy")
    matrix = pkg.get_score_matrix()
    assert matrix["total"] == 0


@responses.activate
def test_package_diff_candidates(mock_pypi_rest_api):
    mock_pypi_rest_api(responses)
    convert = lambda x: (x[0]["filename"], x[1]["filename"])
    requests = package.PypiPackage.from_cached("requests")
    requests2 = package.PypiPackage.from_cached("requests2")

    candidates = tuple(map(convert, requests.get_diff_candidates(requests2)))
    assert ('requests-2.16.0.tar.gz', 'requests2-2.16.0.tar.gz') in candidates
    assert ('requests-2.24.0.tar.gz', 'requests2-2.16.0.tar.gz') not in candidates

    requests.opts["diff_include_latest"] = True
    candidates = tuple(map(convert, requests.get_diff_candidates(requests2)))
    assert ('requests-2.16.0.tar.gz', 'requests2-2.16.0.tar.gz') in candidates
    assert ('requests-2.24.0.tar.gz', 'requests2-2.16.0.tar.gz') in candidates


@pytest.mark.parametrize("uri,expected_metadata",(
        (
            "pypi://wheel?filename=wheel-0.33.0-py2.py3-none-any.whl&release=all",
            {
                "package_file": "wheel-0.33.0-py2.py3-none-any.whl",
                "package_name": "wheel",
                "package_release": "0.33.0",
                "scheme": "pypi"
            }
        ),
        (
            "pypi://wheel?release=0.34.2",
            {
                "package_file": "wheel-0.34.2.tar.gz",
                "package_name": "wheel",
                "package_release": "0.34.2",
                "scheme": "pypi"
            }
        ),
))
@responses.activate
def test_correct_location_metadata(uri, expected_metadata, mock_pypi_rest_api, fuzzy_rule_match):
    mock_pypi_rest_api(responses)
    ref = str(uuid.uuid4())
    static_meta = {"test_key": "test_value", "reference": ref}

    handler = URIHandler.from_uri(uri)
    locations = tuple(handler.get_paths(metadata=static_meta.copy()))

    import pprint
    pprint.pprint(locations[0].metadata)

    assert len(locations) == 1
    assert fuzzy_rule_match(locations[0].metadata, expected_metadata)
    assert fuzzy_rule_match(locations[0].metadata, static_meta)


@pytest.mark.parametrize("requirement,extras,should_match", (
    (
        "win-inet-pton; sys_platform == \"win32\" and python_version == \"2.7\" and extra == 'socks'", (), False
    ),
    (
        "win-inet-pton; sys_platform == \"win32\" and python_version == \"2.7\" and extra == 'socks'", ("blah", "test"), False
    ),
    (
        "win-inet-pton; sys_platform == \"win32\" and python_version == \"2.7\" and extra == 'socks'", ("socks",), True
    ),
    (
        "win-inet-pton; sys_platform == \"win32\" and python_version == \"2.7\" and extra == 'socks'", ("socks", "blah"), True
    ),
    (
        "req", (), True
    ),
    (
        "req", ("blah",), True
    ),
    (
        "idna (>=2.5,<3)", (), True
    ),
    (
        "idna (>=2.5,<3)", ("blah",), True
    )
))
@responses.activate
def test_dependency_markers(requirement: str, extras: tuple, should_match:bool, mock_pypi_rest_api):
    parsed_req = package.Requirement(requirement)
    assert package.DependencyTree.is_marker_valid(parsed_req, extras) is should_match
