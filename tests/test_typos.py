import json
import io
from unittest.mock import MagicMock, Mock

import pytest
from click.testing import CliRunner

from aura import cli
from aura import typos


def test_analyze_info_data():
    uri1 = 'pypi://requests2'
    uri2 = 'pypi://requests'
    ta = typos.TypoAnalyzer(uri1, uri2)
    ta.analyze_info_data()
    assert ta.flags['same_docs'] is True
    assert ta.flags['same_homepage'] is False

    uri2 = 'pypi://simplejson'
    ta = typos.TypoAnalyzer(uri1, uri2)
    ta.analyze_info_data()
    assert ta.flags['same_homepage'] is False


def test_distance():
    ratios = typos.diff_distance("requests", "requestes")
    assert all((x > 0.9) for x in ratios)

    dm = typos.damerau_levenshtein("requests", "requestes")
    assert dm == 1


def test_typosquatting_generator():
    typos.get_all_pypi_packages = MagicMock(
        return_value=[
            'requests',
            'requestes',
            'requests2',
            'requests3',
            'request',
            'grequest',
        ]
    )


    runner = CliRunner()
    result = runner.invoke(
        cli.cli,
        ['find-typosquatting', '--max-distance', '1', '--limit', '10' ]
    )
    if result.exception:
        raise result.exception

    line_count = 0
    for line in result.output.split('\n'):
        if not line.strip():
            continue
        line_count += 1
        entry = json.loads(line)
        assert len(entry.keys()) == 2
        assert 'original' in entry
        assert 'typosquatting' in entry

    assert line_count > 0 and line_count <= 10


def test_generate_stats():
    from google.cloud import bigquery

    query_result = [
        {"package_name": "urllib3", "downloads": 65405956},
        {"package_name": "pip", "downloads": 54903481},
        {"package_name": "six", "downloads": 54052080}
    ]

    bigquery.Client = Mock()
    instance = bigquery.Client.return_value
    instance.query.return_value = iter(query_result)

    out_file = io.StringIO()
    typos.generate_stats(out_file, limit=2)

    instance.query.assert_called_once()

    out_value = out_file.getvalue().strip()
    idx = None
    assert out_value

    for idx, line in enumerate(out_value.split("\n")):
        assert idx < 3, (idx, line)
        decoded = json.loads(line)
        assert decoded == query_result[idx], decoded

    assert idx == 2, out_value


@pytest.mark.parametrize(
    "typo",
    [       #Typosquatting name, *list of legitimate packages
            ("pip2", "pip"),
            ("urllib", "urllib3"),
            ("py-yaml", "pyyaml"),
            ("future", "futures"),
            ("jinja3", "jinja2"),
            ("googleapicore", "google-api-core")
    ]
)
def test_check_name_valid(typo):
    """
    Verify that the check_name works correctly by looking up valid typosquatting packages
    """
    typo_name, *typo_list = typo

    results = typos.check_name(typo_name)
    for legit in typo_list:
        assert legit in results, results


@pytest.mark.parametrize(
    "typo",
    (
        "raatatata",
        "FlAsK",
        "botocore",
        "urllib3",
        ":) Hi there!"
    )
)
def test_check_name_invalid(typo):
    """
    Verify tha the check_name works correctly by looking up invalid package names without typosquatting
    """
    results = typos.check_name(typo)
    assert len(results) == 0, results
