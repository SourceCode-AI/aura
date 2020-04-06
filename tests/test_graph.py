from unittest import mock

import responses

from aura import config
from aura import graph


def test_author_packages():
    packages = graph.get_pypi_author_packages("intense.feel")
    print(packages)
    assert len(packages) >= 2
    assert "Sweepatic-urlnorm" in packages
    assert "Sweepatic-PyExifTool" in packages


@responses.activate
def test_pypi_package_dependencies():
    responses.add(
        responses.GET,
        "https://libraries.io/api/pypi/wheel/dependents",
        json=[{"name": "dep1"}, {"name": "dep2"}]
    )

    with mock.patch.object(config, "get_token", return_value="blah"):
        dependencies = graph.get_pypi_dependents("wheel")

    assert dependencies == ["dep1", "dep2"]


@responses.activate
def test_attack_vector_graph():
    responses.add(
        responses.GET,
        "https://libraries.io/api/pypi/wheel/dependents",
        json=[{"name": "dep1"}, {"name": "dep2"}]
    )
    pass # TODO
