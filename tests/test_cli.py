import os
import json

from click.testing import CliRunner

from aura import cli
from aura.analyzers.python.readonly import ReadOnlyAnalyzer


def test_simple_cli_analysis(fixtures):
    pth = fixtures.path('basic_ast.py')
    output = fixtures.scan_test_file('basic_ast.py')

    assert output['name'] == pth.split('/')[-1]
    assert 'url' in output['tags']


def test_complex_cli_analysis(fixtures, fuzzy_rule_match):
    output = fixtures.scan_test_file('obfuscated.py')

    hits = [
        {
            'type': 'URL',
            'extra': {
                'url': 'https://example.com/index.html'
            }
        },
        {
            'type': 'URL',
            'extra': {
                'url': 'http://malware.com/CnC'
            }
        },
        {
            'type': 'YaraMatch',
            'rule': 'eicar_substring_test'
        }
    ]

    for x in hits:
        assert any(fuzzy_rule_match(h, x) for h in output['hits']), x


def test_custom_analyzer(fixtures):
    runner = CliRunner()
    pth = fixtures.path('obfuscated.py')
    # The import system will mess up custom analyzer
    # Backup currently imported analyzers and restore them after the test
    hooks = ReadOnlyAnalyzer.hooks[:]
    try:
        result = runner.invoke(
            cli.cli,
            ['scan', os.fspath(pth), '-a', 'custom_analyzer:CustomAnalyzer']
        )

        if result.exception:
            raise result.exception

        assert result.exit_code == 0
        # TODO: add tests to test specific functionality of the custom analyzer
    finally:
        ReadOnlyAnalyzer.hooks = hooks


def test_info_command(fixtures):
    result = fixtures.get_cli_output(['info'])


def test_ast_parser(fixtures):
    pth = fixtures.path('obfuscated.py')

    result = fixtures.get_cli_output(
        ['parse_ast', os.fspath(pth)]
    )
    # TODO: add functionality to test the parser output


def test_r2c_integration(fixtures):
    f_name = 'r2c_test_output.json'
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(
            cli.cli,
            ['r2c', 'scan', '--out', f_name]
        )

        if result.exception:
            raise result.exception

        assert result.exit_code == 0
        with open(f_name, 'r') as fd:
            data = json.loads(fd.read())

    assert 'results' in data
    assert 'errors' in data
