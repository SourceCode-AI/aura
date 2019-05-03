import os
import json
import traceback

from click.testing import CliRunner

from aura import cli


def test_simple_cli_analysis(fixtures):
    runner = CliRunner()
    pth = fixtures.path('basic_ast.py')

    result = runner.invoke(
        cli.cli,
        ['scan', os.fspath(pth), "--format", "json"],
        obj = {'min_score': 0}
    )

    if result.exception:
        raise result.exception

    assert result.exit_code == 0, result.output
    output = json.loads(result.output)

    assert output['name'] == pth.split('/')[-1]
    assert 'url' in output['tags']


def test_complex_cli_analysis(fixtures):
    runner = CliRunner()
    pth = fixtures.path("obfuscated.py")

    result = runner.invoke(
        cli.cli,
        ['scan', os.fspath(pth), '--format', 'json'],
        obj={'min_score': 0}
    )

    if result.exception:
        raise result.exception

    assert result.exit_code == 0
    output = json.loads(result.output)

    urls = set()

    for x in output['hits']:
        if x['type'] == "URL":
            urls.add(x['extra']['url'])

    assert "https://example.com/index.html" in urls
