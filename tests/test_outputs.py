import tempfile
import sqlite3
from pathlib import Path

import pytest


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
    scan_path = fixtures.path("flask_app.py")
    db_path = tmp_path / "aura_test_output.sqlite"
    _ = fixtures.get_cli_output(
        ['scan', scan_path, '--format', f'sqlite://{db_path}']
    )
    db = sqlite3.connect(db_path)
    db.row_factory = sqlite3.Row

    inputs = [dict(x) for x in db.execute('SELECT * FROM inputs').fetchall()]
    assert len(inputs) >= 1

    input_ids = {
        x["location"].split("/")[-1]: x["id"] for x in inputs
    }

    hits = [dict(x) for x in db.execute('SELECT * FROM hits').fetchall()]
    assert len(hits) > 3

    files = [dict(x) for x in db.execute(
        'SELECT * FROM files WHERE id=?',
        (input_ids["flask_app.py"],)
    ).fetchall()]
    assert len(files) == 1

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
