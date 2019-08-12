#-*- coding: utf-8 -*-
import json
import sys
import difflib
import itertools
import xmlrpc.client
from functools import partial
from pathlib import Path

import click
import dateutil.parser

from . import diff
from . import config
from .utils import normalize_name
from .uri_handlers.base import URIHandler


logger = config.get_logger(__name__)
WAREHOUSE_XML_RPC = 'https://pypi.python.org/pypi'
PYPI_STATS_QUERY = """
SELECT file.project as package_name, count(file.project) as downloads
FROM `the-psf.pypi.downloads*`
WHERE
    _TABLE_SUFFIX
    BETWEEN FORMAT_DATE(
      '%Y%m%d', DATE_SUB(CURRENT_DATE(), INTERVAL 30 DAY))
    AND FORMAT_DATE('%Y%m%d', CURRENT_DATE())
GROUP BY package_name
ORDER BY downloads DESC"""


class TypoAnalyzer(object):
    def __init__(self, uri1, uri2):
        self.pkg1 = URIHandler.from_uri(uri1)
        if self.pkg1 is None:
            raise ValueError(f"Invalid uri: '{uri1}'")

        self.pkg2 = URIHandler.from_uri(uri2)
        if self.pkg2 is None:
            raise ValueError(f"Invalid uri: '{uri2}'")

        self.mirror = None  # local_mirror
        self.flags = {}
        # self.__order()
        # self.analyze()

    def __order(self):
        """
        Order the given 2 packages so the first one is the "original" and 2nd is a typosquatting candidate
        By "original" here we mean that package pointed to by pkg1 was released before pkg2 as it is very unlikely,
        that an older package is typosquatting newer package

        Some analysis methods require this order that the pkg2 is the potentionally offending package
        """
        releases1 = [dateutil.parser.parse(x['upload_time']) for x in itertools.chain(*self.pkg1.package['releases'].values())]
        releases2 = [dateutil.parser.parse(x['upload_time']) for x in itertools.chain(*self.pkg2.package['releases'].values())]

        self.releases1 = (min(releases1), max(releases1)) if releases1 else (None, None)
        self.releases2 = (min(releases2), max(releases2)) if releases2 else (None, None)

        # Switch the packages in place if they are in wrong order
        if releases2 and not releases1 or self.releases2[0] < self.releases1[0]:
            self.pk1, self.pkg2 = self.pkg2, self.pkg1
            self.releases1, self.releases2 = self.releases2, self.releases1

    def analyze(self):
        self.analyze_info_data()

    def analyze_info_data(self):
        sum1 = self.pkg1.package['info']['summary'] or ''
        sum2 = self.pkg2.package['info']['summary'] or ''
        #TODO: migrate as ssdeep is no longer a dependency of Aura
        #self.flags['similar_description'] = (ssdeep.compare(ssdeep.hash(sum1), ssdeep.hash(sum2)) > 80)

        page1 = self.pkg1.package['info']['home_page'] or ''
        page2 = self.pkg2.package['info']['home_page'] or ''
        self.flags['same_homepage'] = (page1 == page2)

        docs1 = self.pkg1.package['info']['docs_url'] or ''
        docs2 = self.pkg2.package['info']['docs_url'] or ''
        self.flags['same_docs'] = (docs1 == docs2)

        releases1 = set(self.pkg1.package['releases'].keys())
        releases2 = set(self.pkg2.package['releases'].keys())
        self.flags['has_subreleases'] = (releases2.issubset(releases1))

    def diff_releases(self, original_release=None, other_release=None):
        ver = self.pkg2.package['info']['version'] if other_release is None else other_release

        if original_release is None:
            # Check if there are any releases
            if ver is None:
                return

            if ver in self.pkg1.package['releases']:  # If there's a matching release, diff against it
                self.diff_releases(original_release=ver)
            # Diff against latest release
            # self.diff_releases(original_release=self.pkg1['info']['version'])
            return

        for x in self.pkg1.package['releases'][original_release]:
            for y in self.pkg2.package['releases'][ver]:
                if x['packagetype'] != y['packagetype']:
                    continue

                with self.pkg1.package.url2local(x['url']) as pth1, self.pkg2.package.url2local(y['url']) as pth2:
                    ctx = {'a_ref': x['filename'], 'b_ref': y['filename']}
                    da = diff.DiffAnalyzer()
                    da.compare(pth1, pth2, ctx=ctx)
                    da.pprint()


def get_all_pypi_packages():
    repo = xmlrpc.client.ServerProxy(WAREHOUSE_XML_RPC, use_builtin_types=True)
    yield from map(normalize_name, repo.list_packages())


def damerau_levenshtein(s1, s2, max_distance=3, cap=None):
    # Original Source:
    # https://gist.githubusercontent.com/giststhebearbear/4145811/raw/7ae7fc157ee9aebedafc10320bf6349374d52fdd/leven.py

    #  get smallest string so our rows are minimized
    s1, s2 = (s1, s2) if len(s1) <= len(s2) else (s2, s1)
    #  set lengths
    l1, l2 = len(s1), len(s2)
    #  We are simulatng an NM matrix where n is the longer string
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
            changeCost = prevRow[colNum - 1] + (0 if s1[colNum - 1] == s2[rowNum - 1] else 1)
            #  set the cell value - min distance to reach this
            #  position
            curRow[colNum] = min(insertionCost, deletionCost, changeCost)

            #  test for a possible transposition optimization
            #  check to see if we have at least 2 characters
            if 1 < rowNum <= colNum:
                #  test for possible transposition
                if s1[colNum - 1] == s2[colNum - 2] and s2[colNum - 1] == s1[colNum - 2]:
                    curRow[colNum] = min(curRow[colNum], transpositionRow[colNum - 2] + 1)

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

    if all(map(lambda x: x>=cutoff, ratios)):
        return ratios
    else:
        return cut_return


def generate_popular(json_path, full_list=None):

    if not json_path.exists():
        raise ValueError(f"PyPI stats file does not exists: {json_path}")

    if full_list is None:
        full_list = get_all_pypi_packages()
    # We need to convert generator to tuple because we run it in multiple loops
    full_list = tuple(full_list)

    with open(json_path, 'r') as fd:
        for line in fd:
            x = json.loads(line)
            pkg1 = normalize_name(x['package_name'])
            for pkg2 in full_list:
                if pkg1 != pkg2:
                    yield (pkg1, pkg2)


def enumerator(generator=None, method=None):
    for (pkg1, pkg2) in generator:
        res = method(pkg1, pkg2)
        if res and res < 2:
            yield (pkg1, pkg2)


def check_name(name):
    pth = config.get_relative_path('pypi_stats')
    typos = []
    with pth.open() as fd:
        for line in fd:
            line = json.loads(line)
            if name == line['package_name']:
                continue

            dist = damerau_levenshtein(name, line['package_name'])
            if dist and dist < 3:
                typos.append(line['package_name'])

    return typos


def generate_stats(output:click.File, limit=None):
    try:
        from google.cloud import bigquery
        client = bigquery.Client()
    except Exception:
        logger.error("Error creating BigQuery client, Aura is probably not correctly configured. Please consult docs.")
        sys.exit(1)

    if limit:
        q = PYPI_STATS_QUERY + f" LIMIT {int(limit)}"
    else:
        q = PYPI_STATS_QUERY

    logger.info("Running Query on PyPI download dataset")
    query_job = client.query(
        q,
        location = 'US',
    )

    for row in query_job:
        output.write(json.dumps(dict(row)) + '\n')

    logger.info("PyPI download stats generation finished")

