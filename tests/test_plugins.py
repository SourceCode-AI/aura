from aura.analyzers.rules import Rule
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
                assert isinstance(r, Rule), r
                responses.add(r.detection_type)

        assert len(expected_responses-responses) == 0, responses
