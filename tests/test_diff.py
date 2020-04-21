import tempfile
import os
import shutil
from pathlib import Path

from aura import diff


def create_same_files(pth: Path, fixtures):
    filename = "wheel-0.34.2.tar.gz"
    file_pth = fixtures.path(f"mirror/{filename}")

    assert os.path.exists(file_pth)

    struct = []

    # Same file in the same directory (no FS changes)
    dest1 = pth / "same_files/same_directory" / filename
    dest1.parent.mkdir(parents=True)
    os.symlink(src=file_pth, dst=dest1)
    struct.append((dest1.parent, dest1.parent, dest1))

    # Same file in the same directory but with the renamed filename
    dest2 = pth / "same_files/renamed_file" / "wheel_renamed.tar.gz"
    dest2.parent.mkdir(parents=True)
    os.symlink(src=file_pth, dst=dest2)
    struct.append((
        dest1.parent,
        dest2.parent,
        {"operation": "R", "a_rel_path": dest1.name, "b_rel_path": dest2.name}
    ))

    # File has been moved to a subdirectory
    dest2 = pth / "same_files/sub_directory/sub_directory" / filename
    dest2.parent.mkdir(parents=True)
    os.symlink(src=file_pth, dst=dest2)
    struct.append((
        dest1.parent,
        dest2.parent.parent,
        {"operation": "R", "a_rel_path": dest1.name, "b_rel_path": "sub_directory/wheel-0.34.2.tar.gz"}
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
        dest1,
        dest2.parent,
        {
            "operation": "A",
            "a_rel_path": filename,
            "b_rel_path": filename,
            "a_size": 0,
            "b_size": 58330
        }
    ))

    # Add a new file into subdirectory
    dest2 = pth / "add_file/directory2/subdirectory" / filename
    dest2.parent.mkdir(parents=True)
    os.symlink(src=file_pth, dst=dest2)
    struct.append((
        dest1,
        dest2.parent.parent,
        {
            "operation": "A",
            "a_rel_path": f"subdirectory/{filename}",
            "b_rel_path": f"subdirectory/{filename}",
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
        dest1.parent,
        dest2,
        {
            "operation": "D",
            "a_rel_path": filename,
            "a_ref": filename,
            "b_rel_path": filename,
            "a_size": 58330,
            "b_size": 0
        }
    ))

    struct.append((
        dest1.parent.parent,
        dest2,
        {
            "operation": "D",
            "a_rel_path": f"subdirectory/{filename}",
            "b_rel_path": f"subdirectory/{filename}",
            "a_ref": f"subdirectory/{filename}",
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
        dest1.parent,
        dest2.parent,
        {
            "operation": "M",
            "a_rel_path": filename,
            "b_rel_path": filename,
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

            if isinstance(result, dict):
                assert any(fuzzy_rule_match(x, result) for x in d.diffs), d.diffs
            else:
                assert any(os.fspath(x[0]) == os.fspath(result) for x in d.same_files)


def test_diff_file_added(fixtures, fuzzy_rule_match):
    with tempfile.TemporaryDirectory("aura_pytest_diff_") as tmp:
        ptmp = Path(tmp)
        struct = create_add_file(pth=ptmp, fixtures=fixtures)

        for p1, p2, result in struct:
            d = diff.DiffAnalyzer()
            d.compare(p1, p2)

            assert any(fuzzy_rule_match(x, result) for x in d.diffs), d.diffs


def test_diff_file_removed(fixtures, fuzzy_rule_match):
    with tempfile.TemporaryDirectory("aura_pytest_diff_") as tmp:
        ptmp = Path(tmp)
        struct = create_del_file(pth=ptmp, fixtures=fixtures)

        for p1, p2, result in struct:
            d = diff.DiffAnalyzer()
            d.compare(p1, p2)

            assert any(fuzzy_rule_match(x, result) for x in d.diffs), d.diffs


def test_diff_file_similar(fixtures, fuzzy_rule_match):
    with tempfile.TemporaryDirectory("aura_pytest_diff_") as tmp:
        ptmp = Path(tmp)
        struct = create_similar_file(pth=ptmp, fixtures=fixtures)

        for p1, p2, result in struct:
            d = diff.DiffAnalyzer()
            d.compare(p1, p2)

            assert any(fuzzy_rule_match(x, result) for x in d.diffs), d.diffs
