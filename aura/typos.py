# -*- coding: utf-8 -*-
import json
import difflib
import itertools
import xmlrpc.client
from pathlib import Path
from typing import Optional, Generator, Iterable, Tuple, Callable, List

from packaging.utils import canonicalize_name

from . import config
from . import cache
from . import package


logger = config.get_logger(__name__)
WAREHOUSE_XML_RPC = "https://pypi.python.org/pypi"


def threshold_or_default(threshold: Optional[int]) -> int:
    """
    Return default threshold if none is set otherwise proxy the value
    """
    if threshold is None:
        return int(config.get_settings("aura.pypi_download_threshold", fallback=10000))
    else:
        return threshold


def damerau_levenshtein(s1: str, s2: str, max_distance: int=3, cap=None) -> int:
    """
    Compute damerau-levenshtein distance of two strings
    This algorithm is optimized to stop computation of distance once the max distance was reached

    Original Source:
    https://gist.githubusercontent.com/giststhebearbear/4145811/raw/7ae7fc157ee9aebedafc10320bf6349374d52fdd/leven.py

    :param s1: first string
    :param s2: second string
    :param max_distance: maximum allowed distance
    :param cap: cap the max distance or return a given cap value if max_distance was reached
    """
    #  get smallest string so our rows are minimized
    s1, s2 = (s1, s2) if len(s1) <= len(s2) else (s2, s1)
    #  set lengths
    l1, l2 = len(s1), len(s2)
    #  We are simulating an NM matrix where n is the longer string
    #  and m is the shorter string. By doing this we can minimize
    #  memory usage to O(M).
    #  Since we are simulating the matrix we only maintain two rows
    #  at a time the current row and the previous rows.
    #  A move from the current cell looking at the cell before it indicates
    #  consideration of an insert operation.
    #  A move from the current cell looking at the cell above it indicates
    #  consideration of a deletion
    #  Both operations are cost 1
    #  A move from the current cell to the cell up and to the left indicates
    #  an edit operation of 0 cost for a matching character and a 1 cost for
    #  a non matching characters
    transpositionRow = None
    prevRow = None

    #  build first leven matrix row
    #  The first row represents transformation from an empty string
    #  to the shorter string making it static [0-n]
    #  since this row is static we can set it as
    #  curRow and start computation at the second row or index 1
    curRow = list(range(0, l1 + 1))

    # use second length to loop through all the rows being built
    # we start at row one
    for rowNum in range(1, l2 + 1):
        #  set transposition, previous, and current
        #  because the rowNum always increments by one
        #  we can use rowNum to set the value representing
        #  the first column which is indicitive of transforming TO
        #  the empty string from our longer string
        #  transposition row maintains an extra row so that it is possible
        #  for us to apply Damarou's formula
        transpositionRow, prevRow, curRow = prevRow, curRow, [rowNum] + [0] * l1

        #  consider if we have passed the max distance if all paths through
        #  the transposition row are larger than the max we can stop calculating
        #  distance and return the last element in that row and return the max
        if transpositionRow:
            if not any(cellValue < max_distance for cellValue in transpositionRow):
                if cap is True:
                    return max_distance
                else:
                    return cap

        for colNum in range(1, l1 + 1):
            insertionCost = curRow[colNum - 1] + 1
            deletionCost = prevRow[colNum] + 1
            changeCost = prevRow[colNum - 1] + (
                0 if s1[colNum - 1] == s2[rowNum - 1] else 1
            )
            #  set the cell value - min distance to reach this
            #  position
            curRow[colNum] = min(insertionCost, deletionCost, changeCost)

            #  test for a possible transposition optimization
            #  check to see if we have at least 2 characters
            if 1 < rowNum <= colNum:
                #  test for possible transposition
                if (
                    s1[colNum - 1] == s2[colNum - 2]
                    and s2[colNum - 1] == s1[colNum - 2]
                ):
                    curRow[colNum] = min(
                        curRow[colNum], transpositionRow[colNum - 2] + 1
                    )

    #  the last cell of the matrix is ALWAYS the shortest distance between the two strings
    distance = curRow[-1]
    if distance > max_distance:
        return None
    else:
        return distance


def diff_distance(s1, s2, cutoff=0.8, cut_return=None):
    """
    This is the same implementation as difflib.get_close_matches with a modification
    that this function just compare 2 given strings instead of returning close matches from an arrray
    Reference:
    https://github.com/python/cpython/blob/01b731fc2b04744a11e32f93aba8bfb9ddb3dd29/Lib/difflib.py#L722

    :param s1: first string
    :param s2: second string
    :param cutoff: cutoff value
    :param cut_return: value to return if ratio is below the cutoff value
    :return: 3-value tuple (real_quick_ratio, quick_ratio, ratio) if greater then cutoff otherwise `cut_teturn` value
    """
    s = difflib.SequenceMatcher()
    s.set_seq1(s1)
    s.set_seq2(s2)

    ratios = (s.real_quick_ratio(), s.quick_ratio(), s.ratio())

    if all(map(lambda x: x >= cutoff, ratios)):
        return ratios
    else:
        return cut_return


def get_popular_packages(
        json_path: Optional[Path]=None,
        download_threshold: Optional[int]=10000
) -> Iterable[str]:
    if json_path is None:
        json_path = config.get_pypi_stats_path()

    if not json_path.exists():
        raise ValueError(f"PyPI stats file does not exists: {json_path}")

    download_threshold = threshold_or_default(download_threshold)
    popular = []

    with json_path.open("r") as fd:
        for line in fd:
            x = json.loads(line)

            if int(x.get("downloads", 0)) < download_threshold:
                break

            popular.append(canonicalize_name(x["package_name"]))

    return popular


def generate_combinations(
        left: Iterable[str],
        right: Optional[Iterable[str]] = None
) -> Generator[Tuple[str, str], None, None]:
    if right is None:
        right =cache.PyPIPackageList.proxy()

    #yield from itertools.product(left, right)
    set_left = set(left)

    for x, y in itertools.product(left, right):
        if y in set_left:
            continue
        else:
            yield (x, y)

    #yield from itertools.product(left, itertools.filterfalse(lambda x: x not in set_left, right))


def enumerator(
        generator: Generator[Tuple[str, str], None, None],
        method: Callable[[str, str], int],
        extended: bool = False,
) -> Generator[Tuple[str, str], None, None]:
    """
    Iterate over the list of package pairs as generated by `generator`.
    These package pairs are usually combinations/product of a list of packages
    A given `method` is then applied to package pair that acts as a filter, usually a levenshtein distance or similar metric
    """

    pkg_cache = {}
    pkg_score_cache = {}

    for (orig, typo) in generator:
        res = method(orig, typo)
        if res and res < 2:
            if orig not in pkg_cache:
                orig_pkg = package.PypiPackage.from_cached(orig)
                pkg_cache[orig] = orig_pkg
            else:
                orig_pkg = pkg_cache[orig]

            if orig not in pkg_score_cache:
                orig_score = package.PackageScore(orig, orig_pkg, fetch_github=extended)
                pkg_score_cache[orig] = orig_score
            else:
                orig_score = pkg_score_cache[orig]

            if typo not in pkg_cache:
                typo_pkg = package.PypiPackage.from_cached(typo)
                pkg_cache[typo] = typo_pkg
            else:
                typo_pkg = pkg_cache[typo]

            if typo not in pkg_score_cache:
                typo_score = package.PackageScore(typo, typo_pkg, fetch_github=extended)
                pkg_score_cache[typo] = typo_score
            else:
                typo_score = pkg_score_cache[typo]

            data = {
                "original": orig,
                "typo": typo,
                "orig_pkg": orig_pkg,
                "orig_score": orig_score,
                "typo_pkg": typo_pkg,
                "typo_score": typo_score,
            }

            yield data


def check_name(name: str, full_list: bool=False, download_threshold: Optional[int]=None) -> List[str]:
    """
    Check a name of a package if it is a possible typosquatting package
    A list of popular python packages is enumerated in order of most downloaded as defined in pypi_stats dataset
    If a more popular package is found that is within the edit distance of "3" (damerau-levenshtein), it is added to the list of possible typosquattings

    :param name: Name of a package to check for typosquatting candidates
    :param full_list: Flag if the traversal should stop once the package list reaches the ``name`` package.
                        Generally it is not expected for more a popular package to typosquat a less popular package
    :param download_threshold: Stop traversal of a package list once a threshold of minimum number of downloads is reached
    :return: a list of possible typosquatting candidates that the given package might be typosquatting
    :rtype: List[str]
    """
    download_threshold = threshold_or_default(download_threshold)
    name = canonicalize_name(name)
    typos = []

    for line in config.iter_pypi_stats():
        pkg_name = canonicalize_name(line["package_name"])
        downloads = int(line.get("downloads", 0))
        if downloads < download_threshold:
            break

        if name == pkg_name:
            if full_list:
                continue
            else:
                break

        dist = damerau_levenshtein(name, pkg_name)
        if dist and dist < 3:
            typos.append(pkg_name)

    return typos

