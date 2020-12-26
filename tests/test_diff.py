import os
import uuid
import random
import string
import difflib
from math import floor
from pathlib import Path
from unittest import mock

import pytest

from aura.utils import lzset, walk
from aura.output.base import DiffOutputBase
from aura.analyzers.archive import extract
from aura.exceptions import FeatureDisabled

try:
    from aura import diff
    from aura.uri_handlers.base import ScanLocation, URIHandler
except FeatureDisabled as exc:
    pytest.skip(exc.args[0], allow_module_level=True)


WHEEL_CLOSURE = {
    "added": [
        'wheel/macosx_libfile.py',
        'wheel/cli/install.py',
        'wheel/_version.py',
        'wheel-0.34.2.dist-info/RECORD'
    ],
    "modified": [
        ('wheel/metadata.py', 'wheel/metadata.py', 0.6130030959752322),
        ('wheel/cli/convert.py', 'wheel/cli/convert.py', 0.6757215619694398),
        ('wheel/cli/__init__.py', 'wheel/cli/__init__.py', 0.8142523364485982),
        ('wheel-0.33.0.dist-info/entry_points.txt', 'wheel-0.34.2.dist-info/entry_points.txt', 1.0),
        ('wheel/cli/pack.py', 'wheel/cli/pack.py', 0.5618374558303887),
        ('wheel/__init__.py', 'wheel/__init__.py', 0.2153846153846154),
        ('wheel-0.33.0.dist-info/METADATA', 'wheel-0.34.2.dist-info/METADATA', 0.6801275239107333),
        ('wheel/__main__.py', 'wheel/__main__.py', 1.0),
        ('wheel/pep425tags.py', 'wheel/pep425tags.py', 0.4527544691718351),
        ('wheel-0.33.0.dist-info/top_level.txt', 'wheel-0.34.2.dist-info/top_level.txt', 1.0),
        ('wheel-0.33.0.dist-info/LICENSE.txt', 'wheel-0.34.2.dist-info/LICENSE.txt', 1.0),
        ('wheel/util.py', 'wheel/util.py', 0.7647058823529411),
        ('wheel/pkginfo.py', 'wheel/pkginfo.py', 1.0),
        ('wheel/cli/unpack.py', 'wheel/cli/unpack.py', 1.0),
        ('wheel/wheelfile.py', 'wheel/wheelfile.py', 0.6109435588108574),
        ('wheel-0.33.0.dist-info/WHEEL', 'wheel-0.34.2.dist-info/WHEEL', 0.9295774647887324),
        ('wheel/bdist_wheel.py', 'wheel/bdist_wheel.py', 0.5423879272081669)
    ],
    "removed": [
        'wheel-0.33.0.dist-info/RECORD'
    ]
}


def derive_similar(data: str, similarity: float):
    assert len(data) >= 100
    perc = 0.01/floor(len(data)/100.0)

    diff = 0.0
    idx = 0
    while 1-(diff+perc) >= similarity:
        data = data[:idx] + random.choice(string.printable) + data[idx+1:]
        diff += perc
        idx += 1

    return data


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


def get_directory_content(pth):  # TODO: use ScanLocation.list_recursive instead
    for f in walk(pth):
        yield ScanLocation(
            f,
            strip_path=str(pth)
        )


def test_diff_same_renamed(fixtures, tmp_path):
    orig_pth = fixtures.path("diffs/1_a/src.py")
    a_pth = tmp_path / "a.py"
    os.symlink(src=orig_pth, dst=a_pth)
    b_pth = tmp_path / "b.py"
    os.symlink(src=orig_pth, dst=b_pth)

    a_loc = ScanLocation(a_pth, strip_path=str(tmp_path))
    b_loc = ScanLocation(b_pth, strip_path=str(tmp_path))

    d = diff.DiffAnalyzer()
    d.compare(a_loc, b_loc)

    assert len(d.diffs) == 1
    x = d.diffs[0]

    assert x.operation == "M"
    assert x.a_scan is a_loc
    assert x.b_scan is b_loc
    assert x.similarity == 1.0
    assert x.diff is None


def test_diff_file_added(fixtures):
    b_loc = ScanLocation(fixtures.path("diffs/1_a/src.py"))

    d = diff.DiffAnalyzer()
    d.compare([], [b_loc])

    assert len(d.diffs) == 1
    x = d.diffs[0]

    assert x.operation == "A"
    assert x.a_scan is None
    assert x.b_scan is b_loc
    assert x.similarity == 0.0
    assert x.diff is None


def test_diff_file_removed(fixtures):
    a_loc = ScanLocation(fixtures.path("diffs/1_a/src.py"))
    d = diff.DiffAnalyzer()
    d.compare([a_loc], [])

    assert len(d.diffs) == 1
    x = d.diffs[0]

    assert x.operation == "D"
    assert x.a_scan is a_loc
    assert x.b_scan is None
    assert x.similarity == 0.0
    assert x.diff is None


def test_diff_file_similar(fixtures):
    a_loc = ScanLocation(fixtures.path("diffs/1_a/src.py"))
    b_loc = ScanLocation(fixtures.path("diffs/1_b/src.py"))

    d = diff.DiffAnalyzer()
    d.compare(a_loc, b_loc)

    assert len(d.diffs) == 1
    x = d.diffs[0]

    assert x.operation == "M"
    assert x.a_scan is a_loc
    assert x.b_scan is b_loc
    assert x.similarity > 0.8 and x.similarity < 1.0
    assert x.diff is not None

    assert "+import b_import" in x.diff
    assert "-import a_import" in x.diff
    assert " import unchanged" in x.diff
    assert '-eval("a")' in x.diff
    assert '+eval("b")' in x.diff
    assert ' eval("same")' in x.diff


def test_diff_archives(fixtures, fuzzy_rule_match):
    arch1 = fixtures.path("mirror/wheel-0.34.2-py2.py3-none-any.whl")
    arch2 = fixtures.path("mirror/wheel-0.34.2.tar.gz")
    matches = [
        {
            "a_md5": "8a2e3b6aca9665a0c6abecc4f4ea7090",
            "a_mime": "application/zip",
            "a_ref": "mirror/wheel-0.34.2-py2.py3-none-any.whl",
            "b_md5": "ce2a27f99c130a927237b5da1ff5ceaf",
            "b_mime": "application/gzip",
            "b_ref": "mirror/wheel-0.34.2.tar.gz",
            "diff": None,
            "operation": "M"
        }
    ]

    d = diff.DiffAnalyzer()
    d.compare(
        ScanLocation(arch1, strip_path=os.fspath(fixtures.BASE_PATH)),
        ScanLocation(arch2, strip_path=os.fspath(fixtures.BASE_PATH)),
    )

    diffs = [x.as_dict() for x in d.diffs]

    for match in matches:
        assert any(fuzzy_rule_match(x, match) for x in diffs), (match, diffs)


def test_same_scan_location_is_rename():
    sc = ScanLocation(location = f"{uuid.uuid4()}.txt", size=666)
    sc._lzset = {"a"}
    assert sc.is_renamed_file(sc) == 1.0


@pytest.mark.parametrize(["l_name", "r_name", "expected"],(
    ("a.txt", "a.txt", 1.0),
    ("a.txt", "b.txt", 1.0),
    ("subdir/a.txt", "a.txt", 1.0),
    ("a.txt", "subdir/a.txt", 1.0),
    ("a/b/x", "x", 1.0),
    ("x", "a/b/x", 1.0),
    ("a/x", "b/x", 1.0),
    ("a/b/c/x", "x", 0.0),
    ("x", "a/b/c/x", 0.0)
))
def test_is_rename_different_depths(l_name, r_name, expected):
    sc1 = ScanLocation(location=l_name, size=8)
    sc1._lzset = {"a"}
    sc2 = ScanLocation(location=r_name, size=8)
    sc2._lzset = {"a"}
    assert sc1.is_renamed_file(sc2) == expected


def test_derive_similar(random_text):
    original = random_text(200)

    for x in range(0, 100, 5):
        similarity = x/100.0
        modified = derive_similar(original, similarity)
        result = difflib.SequenceMatcher(None, original, modified).ratio()
        assert result > (similarity-0.1)
        assert result < (similarity+0.1)


def disabled_test_is_rename_ratios(random_text):
    original = random_text(1000)
    orig_location = ScanLocation(location="pytest_orig_location.txt", size=len(original))
    orig_location._lzset = lzset(original)

    for x in range(0, 100, 20):
        similarity = x/100.0
        modified = derive_similar(original, similarity)
        modified_location = ScanLocation(location="pytest_modified_location.txt", size=len(modified))
        modified_location._lzset = lzset(modified)
        ratio = orig_location.is_renamed_file(modified_location)
        # FIXME: The +/- 40% diff in result is way too high
        threshold = 0.4
        assert ratio >= similarity-threshold, similarity
        assert ratio <= similarity+threshold, similarity


def test_file_matcher_closure(fixtures, tmp_path):
    arch1 = fixtures.path("mirror/wheel-0.33.0-py2.py3-none-any.whl")
    arch2 = fixtures.path("mirror/wheel-0.34.2-py2.py3-none-any.whl")
    loc1 = ScanLocation(arch1, strip_path=os.fspath(fixtures.BASE_PATH))
    loc2 = ScanLocation(arch2, strip_path=os.fspath(fixtures.BASE_PATH))

    apath1 = tmp_path / "arch1"
    apath2 = tmp_path / "arch2"

    list(extract(loc1, destination=str(apath1)))
    list(extract(loc2, destination=str(apath2)))

    left_content = list(get_directory_content(apath1))
    right_content = list(get_directory_content(apath2))

    fm = diff.FileMatcher(left_content, right_content)
    closure = fm.get_closure()
    added = [str(x) for x in closure["added"]]
    modified = {(str(x[0]), str(x[1])): x[2] for x in closure["modified"]}
    removed = [str(x) for x in closure["removed"]]

    for a in WHEEL_CLOSURE["added"]:
        assert a in added

    for r in WHEEL_CLOSURE["removed"]:
        assert r in removed

    for left_name, right_name, ratio in WHEEL_CLOSURE["modified"]:
        assert (left_name, right_name) in modified
        assert modified[(left_name, right_name)] == pytest.approx(ratio)

    # Test that there are not duplicate elements on right or left side of modified files matches
    assert len(set(x[0] for x in modified)) == len(modified)
    assert len(set(x[1] for x in modified)) == len(modified)


@mock.patch("aura.analyzers.archive.archive_analyzer")
def test_archive_diff_hook(mock1, fixtures):
    from aura.analyzers.archive import diff_archive

    extract_loc1 = ScanLocation("blabla_location1")
    extract_loc2 = ScanLocation("blabla_location2")
    mock1.side_effect = [[extract_loc1], [extract_loc2]]
    assert extract_loc1.metadata.get("b_scan_location") != extract_loc2

    arch1 = fixtures.path("mirror/wheel-0.33.0-py2.py3-none-any.whl")
    arch2 = fixtures.path("mirror/wheel-0.34.2-py2.py3-none-any.whl")

    loc1 = ScanLocation(arch1)
    loc2 = ScanLocation(arch2)

    d = diff.Diff(
        operation="M",
        a_scan=loc1,
        b_scan=loc2
    )

    result = list(diff_archive(d))

    mock1.assert_any_call(location=d.a_scan)
    mock1.assert_any_call(location=d.b_scan)
    assert len(result) == 1
    assert result[0] == extract_loc1
    assert result[0].metadata["b_scan_location"] == extract_loc2


def test_closure_archive_files(fixtures):
    arch1 = fixtures.path("mirror/wheel-0.34.2-py2.py3-none-any.whl")
    arch2 = fixtures.path("mirror/wheel-0.34.2.tar.gz")

    loc1 = ScanLocation(arch1, strip_path=str(fixtures.BASE_PATH))
    loc2 = ScanLocation(arch2, strip_path=str(fixtures.BASE_PATH))

    closure = diff.FileMatcher(left_files=[loc1], right_files=[loc2]).get_closure()
    assert len(closure["modified"]) == 1
    x = closure["modified"][0]

    assert x[0] == loc1
    assert x[1] == loc2
    assert x[2] > 0.0  # Similarity ratio

    assert len(closure["added"]) == 0
    assert len(closure["removed"]) == 0


def test_local_diff_paths(fixtures):
    arch1 = "wheel-0.34.2-py2.py3-none-any.whl"
    arch2 = "wheel-0.33.0-py2.py3-none-any.whl"

    uri1, uri2 = URIHandler.diff_from_uri(fixtures.path(f"mirror/{arch1}"), fixtures.path(f"mirror/{arch2}"))

    paths = list(uri1.get_diff_paths(uri2))
    assert len(paths) == 1
    assert len(paths[0]) == 2

    #Scan Locations should be normalized so that the str repr outputs only the latest part (filename) of the full path
    assert str(paths[0][0]) == arch1
    assert str(paths[0][1]) == arch2


def empty_generator(location):
    yield from []


@pytest.mark.parametrize("op,left,right", (
        (
            "A",
            None,
            ScanLocation("nonexistent/location1.txt", metadata={"md5": "loc1", "mime": "text/x-python"})
        ),
        (
            "R",
            ScanLocation("nonexistent/location2.txt", metadata={"md5": "loc2", "mime": "text/x-python"}),
            None
        ),
        # different MD5s, both should be scanned
        (
            "M",
            ScanLocation("nonexistent/location3.txt", metadata={"md5": "loc3", "mime": "text/x-python"}),
            ScanLocation("nonexistent/location4.txt", metadata={"md5": "loc4", "mime": "text/x-python"})
        ),
        # Same MD5s, scan should be skipped as there is no change in file content
        (
            "M",
            ScanLocation("nonexistent/location5.txt", metadata={"md5": "same", "mime": "text/x-python"}),
            ScanLocation("nonexistent/location6.txt", metadata={"md5": "same", "mime": "text/x-python"})
        )
))
@mock.patch("aura.package_analyzer.Analyzer.analyze", return_value=[(), ()])
def test_diffs_analyzed(analyzer_mock, op, left, right):
    sample_diff = diff.Diff(
        operation=op,
        a_scan=left,
        b_scan=right
    )

    d = diff.DiffAnalyzer()
    d.diffs = [sample_diff]
    d.analyze_changes()

    if right is None and left is None:
        analyzer_mock.assert_not_called()
        return

    if right is not None and left is not None and right.md5 == left.md5:
        analyzer_mock.assert_not_called()
        return

    analyzer_mock.assert_called()

    if right:
        analyzer_mock.assert_any_call(location=right)

    if left:
        analyzer_mock.assert_any_call(location=left)
