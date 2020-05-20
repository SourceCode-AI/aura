import os
import re
import json

import pytest
import responses
from click.testing import CliRunner

from aura import cli
from aura.analyzers.python.readonly import ReadOnlyAnalyzer


@pytest.mark.timeout(5)
@pytest.mark.parametrize("exec_mode", ("--async", "--no-async"))
def test_simple_cli_analysis(exec_mode, fixtures):
    pth = fixtures.path('basic_ast.py')
    output = fixtures.scan_test_file("basic_ast.py", args=[exec_mode])

    assert output["name"].endswith(pth.split("/")[-1])
    assert "url" in output["tags"]


@pytest.mark.extended
def test_complex_cli_analysis(fixtures, fuzzy_rule_match):
    output = fixtures.scan_test_file("obfuscated.py")

    hits = [
        {
            "type": "StringMatch",
            "extra": {
                "signature_id": "url",
                "string": "https://example.com/index.html",
            },
            "tags": ["url"]
        },
        {
            "type": "StringMatch",
            "extra": {
                "signature_id": "url",
                "string": "http://malware.com/CnC"
            },
            "tags": ["url"]
        },
        {
            "type": "YaraMatch",
            "location": re.compile(r".*obfuscated\.py$"),
            "extra": {
                "rule": "eicar_substring_test"
            }
        },
        {
            "type": "YaraMatch",
            "location": re.compile(r".*obfuscated\.py:\d+\$blob$"),
            "extra": {
                "rule": "eicar_substring_test"
            }
        }
    ]

    for x in hits:
        assert any(fuzzy_rule_match(h, x) for h in output['hits']), x


@pytest.mark.extended
def test_custom_analyzer(fixtures):
    runner = CliRunner()
    pth = fixtures.path('obfuscated.py')
    # The import system will mess up custom analyzer
    # Backup currently imported analyzers and restore them after the test
    hooks = ReadOnlyAnalyzer.hooks[:]
    try:
        result = runner.invoke(
            cli.cli, ['scan', os.fspath(pth), '-a', 'custom_analyzer:CustomAnalyzer']
        )

        if result.exception:
            raise result.exception

        assert result.exit_code == 0
        # TODO: add tests to test specific functionality of the custom analyzer
    finally:
        ReadOnlyAnalyzer.hooks = hooks


def test_min_score_option(fixtures):
    output = fixtures.scan_test_file(
        "obfuscated.py", args=["--min-score", 1000], decode=False
    )
    assert len(output.output.strip()) == 0, output.output

    output = fixtures.scan_test_file("obfuscated.py", args=["--min-score", 10])
    assert type(output) == dict
    assert output["score"] > 0


@pytest.mark.parametrize(
    "tag_filter",
    (
        ("!test_code",),
        ("shell_injection",),
        ("test_code", "shell_injection"),
        ("test_code",),
        ("!shell_injection",),
        ("ratata_does_not_exists"),
        ("!ratata_does_not_exists"),
    ),
)
def test_tag_filtering(tag_filter, fixtures):
    args = []
    for tag in tag_filter:
        args += ["-t", tag]

    output = fixtures.scan_test_file("shelli.py", args=args)

    for hit in output["hits"]:
        for tag in tag_filter:
            if tag.startswith("!"):
                assert tag[1:] not in hit["tags"], (tag, hit)
            else:
                assert tag in hit["tags"], (tag, hit)


def test_info_command(fixtures):
    result = fixtures.get_cli_output(['info'])


def test_ast_parser(fixtures):
    pth = fixtures.path('obfuscated.py')

    result = fixtures.get_cli_output(['parse_ast', os.fspath(pth)])
    # TODO: add functionality to test the parser output


def test_r2c_integration():
    f_name = 'r2c_test_output.json'
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(cli.cli, ['r2c', 'scan', '--out', f_name])

        if result.exception:
            raise result.exception

        assert result.exit_code == 0
        with open(f_name, 'r') as fd:
            data = json.loads(fd.read())

    assert 'results' in data
    assert 'errors' in data


@responses.activate
def test_fetching_pypi_stats():
    url = "https://cdn.sourcecode.ai/datasets/typosquatting/pypi_stats.json"

    stats_content = json.dumps([
        {"package": "pkg1", "downloads": 6},
        {"package": "pkg2", "downloads": 4}
    ])

    responses.add(
        responses.GET,
        url=url,
        body=stats_content,
        status = 200,
        adding_headers={
            "Content-length": str(len(stats_content)),
            "Content-type": "application/json"
        }
    )

    f_name = "my_stats.json"
    runner = CliRunner()
    with runner.isolated_filesystem():
        assert not os.path.exists(f_name)
        assert not os.path.exists(f"{f_name}.bak")

        with open(f_name, "w") as fd:
            fd.write("hello_world")

        result = runner.invoke(cli.cli, ["fetch-pypi-stats", "-o", f_name])
        assert result.exit_code == 0, result.stdout
        assert os.path.exists(f_name)

        with open(f_name, "r") as fd:
            for line in fd:
                assert json.loads(line)["package"] in ("pkg1", "pkg2"), line

        assert os.path.exists(f"{f_name}.bak")
        with open(f"{f_name}.bak", "r") as fd:
            assert fd.read() == "hello_world"
