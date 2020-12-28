from unittest.mock import patch

import pytest

from aura.analyzers.detections import Detection
from aura.analyzers.base import NodeAnalyzerV2
from aura.analyzers.python.readonly import ReadOnlyAnalyzer
from aura import plugins


def test_get_analyzers_custom(fixtures):
    apth = fixtures.path("dummy_analyzer.py")

    analyzer_responses = [
        (f"{apth}:ClassAnalyzer", {"class_analyzer_response"}),
        (f"{apth}:path_analyzer", {"path_analyzer_response"}),
        (apth, {"class_analyzer_response", "path_analyzer_response"})
    ]

    for analyzer_name, expected_responses in analyzer_responses:
        analyzers = plugins.get_analyzers([analyzer_name])
        responses = set()
        for a in analyzers:
            for r in a():
                assert isinstance(r, Detection), r
                responses.add(r.detection_type)

        assert len(expected_responses-responses) == 0, responses


def test_load_entrypoint():
    plugins.load_entrypoint("aura.analyzers")
    analyzers_whitelist = {"file_analyzer", "archive", "secrets", "taint_analysis", "setup_py", "sqli"}

    result = analyzers_whitelist - set(plugins.PLUGIN_CACHE["analyzers"].keys())
    assert len(result) == 0, result

    for name in analyzers_whitelist:
        assert name == plugins.PLUGIN_CACHE["analyzers"][name].analyzer_id


def test_plugin_cache():
    plugins.load_entrypoint("aura.analyzers")

    with patch("aura.plugins.initialize_analyzer", side_effect=ValueError):
        plugins.get_analyzers(["file_analyzer", "archive", "secrets", "taint_analysis", "setup_py", "sqli"])


@pytest.mark.parametrize("analyzer", (
        None,
        plugins,  # whole module
))
def test_initialize_analyzer_fail(analyzer):
    with pytest.raises(TypeError) as exc_info:
        plugins.initialize_analyzer(analyzer)

    assert f"Could not initialize the '{analyzer}' analyzer" in str(exc_info.value)


def test_node_analyzer_initialization():
    class TestAnalyzer(NodeAnalyzerV2): pass

    plugins.initialize_analyzer(TestAnalyzer, "some_name")
    assert isinstance(ReadOnlyAnalyzer.hooks[0], TestAnalyzer)
    assert ReadOnlyAnalyzer.hooks[0].analyzer_id == "some_name"
    assert plugins.PLUGIN_CACHE["analyzers"]["some_name"] is ReadOnlyAnalyzer.hooks[0]

def test_func_analyzer_initialization():
    def dummy_analyzer(): pass

    assert not hasattr(dummy_analyzer, "analyzer_id")
    plugins.initialize_analyzer(dummy_analyzer, "some_name")
    assert dummy_analyzer.analyzer_id == "some_name"
    assert plugins.PLUGIN_CACHE["analyzers"]["some_name"] is dummy_analyzer
