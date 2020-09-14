from pytest import fixture, skip

try:
    import networkx
except ImportError:
    skip("networkx module is not installed", allow_module_level=True)


from aura import graph
from aura import package




GRAPH_DATA = {
    "dependencies": {
        "abc": ["abc1", "abc2"],
        "abc2": ["abc3"]
    },
    "authors": {
        "john1": ["abc"]
    }
}


def mock_authors(name):
    return [["Owner", x] for x in GRAPH_DATA["authors"].get(name, [])]


def mock_reverse_dependencies(pkg):
    return GRAPH_DATA["dependencies"].get(pkg, [])


@fixture()
def mock_graph():
    package.get_packages_for_author = mock_authors
    package.get_reverse_dependencies = mock_reverse_dependencies


def test_attack_vector_graph(mock_graph):
    g = graph.AttackVectorGraph()
    g.user_compromised("john1")
    nodes = dict(g.g.nodes(data=True))

    assert "User john1" in nodes
    assert "abc" in nodes
    assert "abc1" in nodes
    assert "abc2" in nodes
    assert "abc3" in nodes
