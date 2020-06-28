import re
import json
import tempfile
import sqlite3
from pathlib import Path

import pytest


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


def test_text_scan_output(fixtures):
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

    files = [dict(x) for x in db.execute("SELECT * FROM files").fetchall()]
    assert len(files) == 1
    for f in files:
        assert f["location"] == loc_id

    with open(scan_path, 'rb') as fd:
        data = fd.read()
        assert data == files[0]['data']


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
        "r.tar.gz",
        "malformed_xmls/bomb.xml"
    )
)
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


def test_diff_output_comprehensive(fixtures, fuzzy_rule_match):
    arch1 = fixtures.path("mirror/wheel-0.34.2-py2.py3-none-any.whl")
    arch2 = fixtures.path("mirror/wheel-0.33.0-py2.py3-none-any.whl")

    matches = [
        {
            "operation": "R",
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
            "a_ref": re.compile(r".*/wheel-0\.34\.2-py2\.py3-none-any\.whl\$wheel/wheelfile\.py$"),
            "b_ref": re.compile(r".*/wheel-0\.33\.0-py2\.py3-none-any\.whl\$wheel/wheelfile\.py$"),
            "a_size": 7298,
            "b_size": 7168,
            "a_mime": "text/x-python",
            "b_mime": "text/x-python",
            "a_md5": "8d4db173db397856d959ad08cd4745e7",
            "b_md5": "f92b90ab7015c47a95553f4224551229",
            "similarity": lambda x: x > 0.9,
            "diff": lambda x: len(x) > 100,
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
            "a_ref": re.compile(r".*/wheel-0\.34\.2-py2\.py3-none-any\.whl\$wheel/cli/pack\.py$"),
            "b_ref": re.compile(r".*/wheel-0\.33\.0-py2\.py3-none-any\.whl\$wheel/cli/pack\.py$"),
            "a_size": 3208,
            "b_size": 2268,
            "a_mime": "text/x-python",
            "b_mime": "text/x-python",
            "a_md5": "67ba28165400d5b8c829d1b78989de45",
            "b_md5": "57241c2632d667f1f5bac5ce77fecfd7",
            "similarity": lambda x: x> 0.7,
            "diff": lambda x: len(x) > 100,
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
            "a_ref": re.compile(r".*/wheel-0\.34\.2-py2\.py3-none-any\.whl\$wheel/macosx_libfile\.py$"),
            "b_ref": None,
            "a_size": 11858,
            "b_size": 0,
            "a_mime": "text/plain",
            "b_mime": None,
            "a_md5": "10e61b8b920752320dbe0562f75f81d5",
            "b_md5": None,
            "similarity": 0,
        }
    ]

    raw_output = fixtures.get_cli_output(["diff", arch1, arch2, "-f", "json"])
    output = json.loads(raw_output.stdout)
    diffs = output["diffs"]

    for match in matches:
        assert any(fuzzy_rule_match(x, match) for x in diffs), (match, diffs)


def test_diff_json_output(fixtures, fuzzy_rule_match):
    pth1 = fixtures.path("diffs/1_a")
    pth2 = fixtures.path("diffs/1_b")

    raw_output = fixtures.get_cli_output(["diff", pth1, pth2, "-f", "json"])
    output = json.loads(raw_output.stdout)
    diffs = output["diffs"]

    for match in DIFF_MATCHES:
        assert any(fuzzy_rule_match(x, match) for x in diffs), (match, diffs)


def test_diff_sqlite_output(fixtures, fuzzy_rule_match, tmp_path):
    pth1 = fixtures.path("diffs/1_a")
    pth2 = fixtures.path("diffs/1_b")
    db_path = tmp_path / "aura_test_diff_output.sqlite"

    _ = fixtures.get_cli_output(["diff", pth1, pth2, "-f", f"sqlite://{db_path}"])

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
