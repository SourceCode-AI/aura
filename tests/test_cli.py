import os
import re
import json
import tempfile
import warnings
from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from aura import cli
from aura.analyzers.data_finder import DataFinder

try:
    import yara
except ImportError:
    yara = None


OBFUSCATED_DEFAULT_MATCHES = [
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


@pytest.mark.parametrize("exec_mode", ("--async", "--no-async"))
def test_simple_cli_analysis(exec_mode, fixtures):
    pth = fixtures.path('basic_ast.py')
    output = fixtures.scan_test_file("basic_ast.py", args=[exec_mode])

    assert output["name"].endswith(pth.split("/")[-1])
    assert "url" in output["tags"]


@pytest.mark.e2e
@pytest.mark.skipif(yara is None, reason="Yara module/analyzer is not installed")
def test_complex_cli_analysis(fixtures):
    with patch.object(DataFinder, "get_min_size", return_value=10) as m:
        fixtures.scan_and_match("obfuscated.py", OBFUSCATED_DEFAULT_MATCHES)


@pytest.mark.e2e
def test_custom_analyzer(fixtures):
    fixtures.scan_and_match(
        "obfuscated.py",
        matches=[
            {
                "type": "CustomAnalyzer",
                "tags": ["test-code", "custom_tag"],
                "extra": {
                    "string_content": "Hello world"
                }
            },
            {
                "type": "CustomAnalyzer",
                "tags": ["test-code", "custom_tag"],
                "extra": {
                    "string_content": "~/.profile"
                }
            }
        ],
        excludes=OBFUSCATED_DEFAULT_MATCHES,
        args=["-a", "custom_analyzer:CustomAnalyzer"]
    )


def test_scan_min_score_option(fixtures):
    output = fixtures.scan_test_file(
        "obfuscated.py", args=["--format", "json://-?min_score=1000"], decode=False
    )
    assert len(output.output.strip()) == 0, output.output

    output = fixtures.scan_test_file("obfuscated.py", args=["--format", "json://-?min_score=10"])
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
        ("ratata_does_not_exists",),
        ("!ratata_does_not_exists",),
    ),
)
def test_tag_filtering(tag_filter, fixtures):
    args = []
    for tag in tag_filter:
        args += ["-t", tag]

    output = fixtures.scan_test_file("shelli.py", args=args)

    for hit in output["detections"]:
        for tag in tag_filter:
            if tag.startswith("!"):
                assert tag[1:] not in hit["tags"], (tag, hit)
            else:
                assert tag in hit["tags"], (tag, hit)


@pytest.mark.e2e
def test_info_command(fixtures, tmp_path, mock_pypi_stats):
    from aura import config
    stats: Path = tmp_path / "pypi_stats.json"
    stats.write_text("\n".join(json.dumps(x) for x in config.iter_pypi_stats()))
    os.environ["AURA_PYPI_STATS"] = str(stats)
    try:
        result = fixtures.get_cli_output(['info'])
    finally:
        del os.environ["AURA_PYPI_STATS"]


def test_ast_parser(fixtures):
    pth = fixtures.path('obfuscated.py')

    result = fixtures.get_cli_output(['parse_ast', os.fspath(pth)])
    assert "aura.analyzers.python.nodes" in result.stdout
    assert "http://malware.com/CnC" in result.stdout
    assert "Hello world" in result.stdout
    assert "adalaraoawa aoalalaeaH" not in result.stdout

    result = fixtures.get_cli_output(['parse_ast', os.fspath(pth), "-s", "raw"])
    assert "aura.analyzers.python.nodes" not in result.stdout
    assert "http://malware.com/CnC" not in result.stdout
    assert "Hello world" not in result.stdout
    assert "adalaraoawa aoalalaeaH" in result.stdout


@pytest.mark.e2e
def test_async_cleanup(fixtures):
    from aura.uri_handlers import base

    base.cleanup_locations()
    tmp_dir = Path(tempfile.gettempdir())
    before = set(tmp_dir.glob("aura_pkg__sandbox*"))
    if before:
        warnings.warn(f"tmp folder already contains aura leftovers! {tmp_dir}")

    _ = fixtures.scan_test_file("mirror/wheel-0.34.2.tar.gz", args=["--async", "-a", "archive"])

    # Make sure that the temp dir is properly cleaned up also when using async mode
    leftovers = set(tmp_dir.glob("aura_pkg__sandbox*")) - before
    assert len(leftovers) == 0, 0
