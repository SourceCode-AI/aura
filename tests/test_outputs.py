import re
import json
import tempfile
import sqlite3
from pathlib import Path

import pytest

from aura import diff
from aura.uri_handlers.base import ScanLocation
from aura.output.base import DiffOutputBase
from aura.exceptions import FeatureDisabled


try:
    import jsonschema
except ImportError:
    jsonschema = None



DIFF_MATCHES = [
    {
        "operation": "M",
        "a_ref": "src.py",
        "b_ref": "src.py",
        "new_detections": [
            {
                "type": "ModuleImport",
                "extra": {
                    "name": "b_import",
                    "root": "b_import"
                },
                "line": "import b_import",
                "location": "src.py"
            },
            {
                "type": "FunctionCall",
                "extra": {
                    "function": "eval"
                },
                "line": 'eval("b")',
                "location": "src.py"
            }
        ],
        "removed_detections": [
            {
                "type": "ModuleImport",
                "extra": {
                    "name": "a_import",
                    "root": "a_import"
                },
                "line": "import a_import",
                "location": "src.py"
            },
            {
                "type": "FunctionCall",
                "extra": {
                    "function": "eval"
                },
                "line": 'eval("a")',
                "location": "src.py"
            }
        ]
    }
]

DIFFS = (
    diff.Diff(
        operation="A",
        a_scan=None,
        b_scan=ScanLocation(
            "added_file.py",
        )
    ),
    diff.Diff(
        operation="D",
        a_scan=ScanLocation(
            "removed_file.py"
        ),
        b_scan=None
    ),
    diff.Diff(
        operation="M",
        a_scan=ScanLocation(
            "modified_file.py"
        ),
        b_scan=ScanLocation(
            "modified_file.py"
        ),
        similarity=0.8,
        diff="This is a diff of the modified file"
    )
)


@pytest.mark.e2e
def test_text_scan_output_e2e(fixtures):
    """
    Test different output formats
    """
    scan_path = fixtures.path('flask_app.py')

    # Test plain text output
    cli = fixtures.get_cli_output(['scan', scan_path, '--format', 'text'])
    output = cli.output
    assert 'Scan results for ' in output
    assert 'Scan score: ' in output
    # TODO: add more patterns to test for in text output


def test_sqlite_scan_output(fixtures, tmp_path: Path):
    scan_path = str(fixtures.path("flask_app.py"))
    db_path = tmp_path / "aura_test_output.sqlite"
    _ = fixtures.get_cli_output(
        ['scan', scan_path, '--format', f'sqlite://{db_path}']
    )
    db = sqlite3.connect(db_path)
    db.row_factory = sqlite3.Row

    inputs = [dict(x) for x in db.execute(
        "SELECT * FROM inputs WHERE input=?",
        (scan_path,)
    ).fetchall()]
    assert len(inputs) == 1

    input_id = inputs[0]["id"]

    locations = [dict(x) for x in db.execute("SELECT * FROM locations").fetchall()]

    assert len(locations) == 1
    for loc in locations:
        assert loc["input"] == input_id

    loc_id = locations[0]["id"]

    detections = [dict(x) for x in db.execute("SELECT * FROM detections").fetchall()]
    assert len(detections) > 3
    for d in detections:
        assert d["location"] == loc_id


def test_non_existing(fixtures):
    """
    Test the behaviour if a non-existing location is passed to aura for scanning
    Aura should fail with exit code 1
    Printing error message to stdout
    No traceback should be printed as it should be handled by cli instead of propagating to interpreter
    """
    pth = 'does_not_exists_on_earth.py'
    cli = fixtures.get_cli_output(['scan', pth], check_exit_code=False)

    assert (cli.exception is None) or (type(cli.exception) == SystemExit)
    assert cli.exit_code == 1
    # Check that stderr doesn't contain traceback information
    # assert "Traceback" not in cli.stderr
    # stderr should contain the error message
    assert "Invalid location" in cli.stderr
    # stdout should not contain any of these
    assert "Traceback" not in cli.stdout
    assert "Invalid location" not in cli.stdout


@pytest.mark.parametrize(
    "output_type",
    (
        "text",
        "json",
        "sqlite"
    )
)
@pytest.mark.e2e
def test_output_not_created_when_below_minimum_score(output_type, fixtures, tmp_path: Path):
    """
    Test that an output file is never created if the minimum score is never reached
    This also tests that the output results are not outputted on stdout
    """

    out_file = tmp_path / "aura_test_output"

    cli = fixtures.scan_test_file(
        "misc.py",
        decode=False,
        args=[
            "--format", f"{output_type}://{out_file}?min_score=1000",
        ]
    )

    assert len(list(tmp_path.iterdir())) == 0
    assert not out_file.exists()

    for keyword in ("os.system", "eval", "__reduce__"):
        assert keyword not in cli.stdout, (keyword, cli.stdout)


@pytest.mark.parametrize(
    "scan_file",
    (
        "djamgo-0.0.1-py3-none-any.whl",
        "evil.tar.gz",
        "misc.py",
        "obfuscated.py",
        "malformed_xmls/bomb.xml"
    )
)
@pytest.mark.e2e
def test_output_path_formatting(scan_file, fixtures):
    """
    Test that in the output, the paths have correct output formats:
    - Archives have $ denoting the path afterwards indicate the path in the archive
    - Paths should not contain parts of a temporary directory
    """
    temp_prefix = tempfile.gettempdir()
    output = fixtures.scan_test_file(scan_file)["detections"]

    for hit in output:
        location: str = hit.get("location")
        signature: str = hit["signature"]
        if not location:
            continue

        # Check that the location does not expose temporary directory used by aura
        assert not location.startswith(temp_prefix)
        # Location should never end only with $ which is special character in aura indicating path inside the archive
        # `$` should always be followed by a path
        assert not location.endswith(f"$")
        # Having scan_file multiple times in a location might indicate a problem with stripping path via parent
        assert location.count(scan_file) <= 1
        # Signatures also should not contain any temporary paths
        assert temp_prefix not in signature


@pytest.mark.e2e
def test_diff_output_comprehensive(fixtures, fuzzy_rule_match):
    arch1 = fixtures.path("mirror/wheel-0.34.2-py2.py3-none-any.whl")
    arch2 = fixtures.path("mirror/wheel-0.33.0-py2.py3-none-any.whl")

    matches = [
        {
            "operation": "M",
            "a_ref": "wheel-0.34.2-py2.py3-none-any.whl",
            "b_ref": "wheel-0.33.0-py2.py3-none-any.whl",
            "a_size": 26502,
            "b_size": 21497,
            "a_mime": "application/zip",
            "b_mime": "application/zip",
            "a_md5": "8a2e3b6aca9665a0c6abecc4f4ea7090",
            "b_md5": "6731b8ca8703150e2304613a25ff674f",
        },
        {
            "operation": "M",
            "a_ref": "wheel-0.34.2-py2.py3-none-any.whl$wheel/wheelfile.py",
            "b_ref": "wheel-0.33.0-py2.py3-none-any.whl$wheel/wheelfile.py",
            "a_size": 7298,
            "b_size": 7168,
            "a_mime": "text/x-python",
            "b_mime": "text/x-python",
            "a_md5": "8d4db173db397856d959ad08cd4745e7",
            "b_md5": "f92b90ab7015c47a95553f4224551229",
            #"similarity": lambda x: x > 0.6,
            "removed_detections": [
                {
                    "type": "ModuleImport",
                    "extra": {
                        "root": "stat",
                        "name": "stat"
                    },
                    "line": "import stat"
                }
            ]
        },
        {
            "operation": "M",
            "a_ref": "wheel-0.34.2-py2.py3-none-any.whl$wheel/cli/pack.py",
            "b_ref": "wheel-0.33.0-py2.py3-none-any.whl$wheel/cli/pack.py",
            "a_size": 3208,
            "b_size": 2268,
            "a_mime": "text/x-python",
            "b_mime": "text/x-python",
            "a_md5": "67ba28165400d5b8c829d1b78989de45",
            "b_md5": "57241c2632d667f1f5bac5ce77fecfd7",
            "new_detections": [
                {
                    "type": "FunctionCall",
                    "extra": {
                        "function": "open"
                    },
                    "line": "with open(os.path.join(directory, dist_info_dir, 'WHEEL')) as f:"
                }
            ],
            "removed_detections": [
                {
                    "type": "FunctionCall",
                    "extra": {
                        "function": "open"
                    },
                    "line": "with open(wheel_file_path) as f:"
                }
            ]
        },
        {
            "operation": "D",
            "a_ref": "wheel-0.34.2-py2.py3-none-any.whl$wheel/macosx_libfile.py",
            "a_size": 11858,
            "a_mime": "text/x-python",
            "a_md5": "10e61b8b920752320dbe0562f75f81d5",
            "similarity": 0.0,
        }
    ]

    raw_output = fixtures.get_cli_output(["diff", arch1, arch2, "-f", "json"])
    output = json.loads(raw_output.stdout)
    diffs = output["diffs"]

    for match in matches:
        assert any(fuzzy_rule_match(x, match) for x in diffs), (match, diffs)


@pytest.mark.e2e
def test_diff_json_output_e2e(fixtures, fuzzy_rule_match):
    pth1 = fixtures.path("diffs/1_a")
    pth2 = fixtures.path("diffs/1_b")
    try:
        raw_output = fixtures.get_cli_output(["diff", pth1, pth2, "-f", "json"])
    except FeatureDisabled as exc:
        pytest.mark.skipif(reason=exc.args[0])

    output = json.loads(raw_output.stdout)
    diffs = output["diffs"]

    for match in DIFF_MATCHES:
        assert any(fuzzy_rule_match(x, match) for x in diffs), (match, diffs)


@pytest.mark.e2e
def test_diff_sqlite_output_e2e(fixtures, fuzzy_rule_match, tmp_path):
    pth1 = fixtures.path("diffs/1_a")
    pth2 = fixtures.path("diffs/1_b")
    db_path = tmp_path / "aura_test_diff_output.sqlite"

    try:
        _ = fixtures.get_cli_output(["diff", pth1, pth2, "-f", f"sqlite://{db_path}"])
    except FeatureDisabled as exc:
        pytest.mark.skipif(reason=exc.args[0])

    db = sqlite3.connect(db_path)
    db.row_factory = sqlite3.Row

    diffs = [dict(x) for x in db.execute("SELECT * FROM diffs").fetchall()]
    diff_ids = {x["id"]: x for x in diffs}

    detections = [dict(x) for x in db.execute("SELECT * FROM detections").fetchall()]

    for d in detections:
        if d["is_new"]:
            diff_ids[d["diff"]].setdefault("new_detections", []).append(d)
        else:
            diff_ids[d["diff"]].setdefault("removed_detections", []).append(d)

    for match in DIFF_MATCHES:
        assert any(fuzzy_rule_match(x, match) for x in diffs), (match, diffs)


@pytest.mark.skipif(jsonschema is None, reason="jsonschema module is not installed")
@pytest.mark.e2e
def test_gitlab_sast_output_e2e(fixtures):
    schema_pth = fixtures.path("gitlab-sast-schema.json")

    with open(schema_pth, "r") as fd:
        schema = json.loads(fd.read())

    output = fixtures.scan_test_file("flask_app.py", args=["-f", "gitlab-sast"])
    jsonschema.validate(output, schema)


@pytest.mark.skipif(jsonschema is None, reason="jsonschema module is not installed")
@pytest.mark.parametrize("infile", (
    "flask_app.py",
    "obfuscated.py",
    "r.tar.gz",
    "evil.zip"
))
@pytest.mark.e2e
def test_sarif_output_e2e(infile, fixtures):
    schema_pth = fixtures.path("sarif-schema.json")

    with open(schema_pth, "r") as fd:
        schema = json.loads(fd.read())

    output = fixtures.scan_test_file(infile, args=["-f", "sarif"])
    jsonschema.validate(output, schema)



def test_text_output(capsys):
    analyzer = diff.DiffAnalyzer()
    analyzer.diffs = DIFFS

    formatter = DiffOutputBase.from_uri("text")
    with formatter:
        formatter.output_diff(analyzer)

    captured = capsys.readouterr()
    assert len(captured.err) == 0, captured.err

    assert "File added" in captured.out, captured.out
    assert "Path: added_file.py" in captured.out, captured.out

    assert "File removed" in captured.out, captured.out
    assert "Path: removed_file.py" in captured.out, captured.out

    assert "Similarity: 80%" in captured.out, captured.out
    assert "A Path: modified_file.py" in captured.out, captured.out
    assert "B Path: modified_file.py" in captured.out, captured.out
    assert "This is a diff of the modified file" in captured.out, captured.out
