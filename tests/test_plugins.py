from unittest.mock import patch

from aura.analyzers.detections import Detection
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

