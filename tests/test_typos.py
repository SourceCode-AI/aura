import os
import json
from itertools import product
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from aura import cli
from aura import config
from aura import typos



def test_distance():
    ratios = typos.diff_distance("requests", "requestes")
    assert all((x > 0.9) for x in ratios)

    dm = typos.damerau_levenshtein("requests", "requestes")
    assert dm == 1


@patch("aura.typos.get_all_pypi_packages")
def disable_test_typosquatting_generator(mock, tmp_path, mock_pypi_stats):  # FIXME
    stats: Path = tmp_path / "pypi_stats.json"
    stats.write_text("\n".join(json.dumps(x) for x in config.iter_pypi_stats()))
    os.environ["AURA_PYPI_STATS"] = str(stats)
    try:
        mock.return_value = [
            'requests',
            'requestes',
            'requests2',
            'requests3',
            'request',
            'grequest',
        ]

        runner = CliRunner(mix_stderr=False)
        result = runner.invoke(
            cli.cli,
            ['find-typosquatting', '--limit', '10', '-f', 'json'],
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
    finally:
        del os.environ["AURA_PYPI_STATS"]


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
def test_check_name_valid(typo, mock_pypi_stats):
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
def test_check_name_invalid(typo, mock_pypi_stats):
    """
    Verify tha the check_name works correctly by looking up invalid package names without typosquatting
    """
    results = typos.check_name(typo)
    assert len(results) == 0, results


@patch("aura.cache.PyPIPackageList._get_package_list")
def test_generate_combinations(pypi_mock):
    left = ["al", "bl", "dup"]
    # The `dup` value from right should be filtered out by `generate_combinations` as it is already in the left side
    right = ["ar", "br", "dup"]

    pypi_mock.return_value = right

    valid = set(product(left, right[:2]))
    combinations = set(typos.generate_combinations(left=left))

    assert valid == combinations
