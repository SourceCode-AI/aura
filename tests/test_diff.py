import tempfile
import os
import re
import json
import shutil
from pathlib import Path
from dataclasses import is_dataclass, asdict

from aura import diff
from aura.uri_handlers.base import ScanLocation


def create_same_files(pth: Path, fixtures):
    filename = "wheel-0.34.2.tar.gz"
    file_pth = fixtures.path(f"mirror/{filename}")

    assert os.path.exists(file_pth)

    struct = []

    # Same file in the same directory (no FS changes)
    dest1 = pth / "same_files/same_directory" / filename
    dest1.parent.mkdir(parents=True)
    os.symlink(src=file_pth, dst=dest1)
    struct.append((
        ScanLocation(dest1.parent),
        ScanLocation(dest1.parent),
        dest1
    ))

    # Same file in the same directory but with the renamed filename
    dest2 = pth / "same_files/renamed_file" / "wheel_renamed.tar.gz"
    dest2.parent.mkdir(parents=True)
    os.symlink(src=file_pth, dst=dest2)
    struct.append((
        ScanLocation(dest1.parent),
        ScanLocation(dest2.parent),
        {"operation": "R", "a_ref": dest1.name, "b_ref": dest2.name}
    ))

    # File has been moved to a subdirectory
    dest2 = pth / "same_files/sub_directory/sub_directory" / filename
    dest2.parent.mkdir(parents=True)
    os.symlink(src=file_pth, dst=dest2)
    struct.append((
        ScanLocation(dest1.parent),
        ScanLocation(dest2.parent.parent),
        {"operation": "R", "a_ref": dest1.name, "b_ref": f"sub_directory/{filename}"}
    ))

    return struct


def create_add_file(pth: Path, fixtures):
    filename = "wheel-0.34.2.tar.gz"
    file_pth = fixtures.path(f"mirror/{filename}")

    assert os.path.exists(file_pth)

    struct = []

    # Add a new file to the same directory
    dest1 = pth / "add_file/empty_directory"
    dest1.mkdir(parents=True)
    dest2 = pth / "add_file/directory1" / filename
    dest2.parent.mkdir(parents=True)
    os.symlink(src=file_pth, dst=dest2)
    struct.append((
        ScanLocation(dest1),
        ScanLocation(dest2.parent),
        {
            "operation": "A",
            "a_ref": None,
            "b_ref": filename,
            "a_size": 0,
            "b_size": 58330
        }
    ))

    # Add a new file into subdirectory
    dest2 = pth / "add_file/directory2/subdirectory" / filename
    dest2.parent.mkdir(parents=True)
    os.symlink(src=file_pth, dst=dest2)
    struct.append((
        ScanLocation(dest1),
        ScanLocation(dest2.parent.parent),
        {
            "operation": "A",
            "a_ref": None,
            "b_ref": f"subdirectory/{filename}",
            "a_size": 0,
            "b_size": 58330
        }
    ))

    return struct


def create_del_file(pth: Path, fixtures):
    filename = "wheel-0.34.2.tar.gz"
    file_pth = fixtures.path(f"mirror/{filename}")

    assert os.path.exists(file_pth)

    struct = []

    dest1 = pth / "del_file/file_location/subdirectory" / filename
    dest1.parent.mkdir(parents=True)
    dest2 = pth / "del_file/empty_directory"
    dest2.mkdir(parents=True)
    os.symlink(src=file_pth, dst=dest1)
    struct.append((
        ScanLocation(dest1.parent),
        ScanLocation(dest2),
        {
            "operation": "D",
            "a_ref": filename,
            "b_ref": None,
            "a_size": 58330,
            "b_size": 0
        }
    ))

    struct.append((
        ScanLocation(dest1.parent.parent),
        ScanLocation(dest2),
        {
            "operation": "D",
            "a_ref": f"subdirectory/{filename}",
            "b_ref": None,
            "a_size": 58330,
            "b_size": 0
        }
    ))

    return struct


def create_similar_file(pth: Path, fixtures):
    struct = []

    filename = "misc.py"
    file_pth = Path(fixtures.path(filename))
    assert os.path.exists(file_pth)
    with file_pth.open("r") as fd:
        file_content = fd.readlines()
    del file_pth

    dest1 = pth / "similar_file/file" / filename
    dest1.parent.mkdir(parents=True)
    with dest1.open("w") as fd:
        fd.writelines(file_content)

    dest2 = pth / "similar_file/directory1/subdirectory" / filename
    dest2.parent.mkdir(parents=True)
    with dest2.open("w") as fd:
        fd.writelines(file_content[:5])

    struct.append((
        ScanLocation(dest1.parent),
        ScanLocation(dest2.parent),
        {
            "operation": "M",
            "a_ref": filename,
            "b_ref": filename,
            "a_mime": "text/x-python",
            "b_mime": "text/x-python"
        }
    ))
    return struct


def test_diff_same(fixtures, fuzzy_rule_match):
    with tempfile.TemporaryDirectory("aura_pytest_diff_") as tmp:
        ptmp = Path(tmp)
        struct = create_same_files(pth=ptmp, fixtures=fixtures)

        for p1, p2, result in struct:
            d = diff.DiffAnalyzer()
            d.compare(p1, p2)
            diffs = [asdict(x) for x in d.diffs]

            if isinstance(result, dict):
                assert any(fuzzy_rule_match(x, result) for x in diffs), diffs
            else:
                assert any(os.fspath(x[0]) == os.fspath(result) for x in d.same_files)


def test_diff_file_added(fixtures, fuzzy_rule_match):
    with tempfile.TemporaryDirectory("aura_pytest_diff_") as tmp:
        ptmp = Path(tmp)
        struct = create_add_file(pth=ptmp, fixtures=fixtures)

        for p1, p2, result in struct:
            d = diff.DiffAnalyzer()
            d.compare(p1, p2)
            diffs = [asdict(x) for x in d.diffs]

            assert any(fuzzy_rule_match(x, result) for x in diffs), diffs


def test_diff_file_removed(fixtures, fuzzy_rule_match):
    with tempfile.TemporaryDirectory("aura_pytest_diff_") as tmp:
        ptmp = Path(tmp)
        struct = create_del_file(pth=ptmp, fixtures=fixtures)

        for p1, p2, result in struct:
            d = diff.DiffAnalyzer()
            d.compare(p1, p2)
            diffs = [asdict(x) for x in d.diffs]

            assert any(fuzzy_rule_match(x, result) for x in diffs), diffs


def test_diff_file_similar(fixtures, fuzzy_rule_match):
    with tempfile.TemporaryDirectory("aura_pytest_diff_") as tmp:
        ptmp = Path(tmp)
        struct = create_similar_file(pth=ptmp, fixtures=fixtures)

        for p1, p2, result in struct:
            d = diff.DiffAnalyzer()
            d.compare(p1, p2)
            diffs = [asdict(x) for x in d.diffs]

            assert any(fuzzy_rule_match(x, result) for x in diffs), diffs


def test_diff_archives(fixtures, fuzzy_rule_match):
    arch1 = fixtures.path("mirror/wheel-0.34.2-py2.py3-none-any.whl")
    arch2 = fixtures.path("mirror/wheel-0.34.2.tar.gz")
    matches = [
        {
            "a_md5": "8a2e3b6aca9665a0c6abecc4f4ea7090",
            "a_mime": "application/zip",
            "a_ref": "wheel-0.34.2-py2.py3-none-any.whl",
            "b_md5": "ce2a27f99c130a927237b5da1ff5ceaf",
            "b_mime": "application/gzip",
            "b_ref": "wheel-0.34.2.tar.gz",
            "diff": "",
            "operation": "R"
        }
    ]

    d = diff.DiffAnalyzer()
    d.compare(
        ScanLocation(arch1, strip_path=os.fspath(fixtures.BASE_PATH)),
        ScanLocation(arch2, strip_path=os.fspath(fixtures.BASE_PATH)),
    )

    diffs = [asdict(x) for x in d.diffs]

    for match in matches:
        assert any(fuzzy_rule_match(x, match) for x in diffs), (match, diffs)


def test_diff_json_output(fixtures, fuzzy_rule_match):
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
            "diff": lambda x: len(x) > 100
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
            "diff": lambda x: len(x) > 100
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
