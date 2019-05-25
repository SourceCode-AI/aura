import json

from click.testing import CliRunner

from aura import cli
from aura import typos


def test_analyze_info_data():
    uri1 = 'pypi://requests2'
    uri2 = 'pypi://requests'
    ta = typos.TypoAnalyzer(uri1, uri2)
    ta.analyze_info_data()
    assert ta.flags['similar_description'] is True
    assert ta.flags['same_docs'] is True
    assert ta.flags['same_homepage'] is True

    uri2 = 'pypi://simplejson'
    ta = typos.TypoAnalyzer(uri1, uri2)
    ta.analyze_info_data()
    assert ta.flags['similar_description'] is False
    assert ta.flags['same_homepage'] is False


def test_distance():
    ratios = typos.diff_distance("requests", "requestes")
    print(f"Diff Ratios: {ratios}")
    assert all((x > 0.9) for x in ratios)

    dm = typos.damerau_levenshtein("requests", "requestes")
    assert dm == 1


def test_typosquatting_generator():
    runner = CliRunner()
    result = runner.invoke(
        cli.cli,
        ['find-typosquatting', '--max-distance', '1', '--limit', '10' ]
    )
    if result.exception:
        raise result.exception

    for line in result.output.split('\n'):
        if not line.strip():
            continue
        entry = json.loads(line)
        assert len(entry.keys()) == 2
        assert 'original' in entry
        assert 'typosquatting' in entry
