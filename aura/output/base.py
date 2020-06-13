from __future__ import annotations

import os.path
from abc import ABCMeta, abstractmethod
from dataclasses import dataclass, field
from urllib import parse
from typing import List, Union, Mapping, Optional

import pkg_resources

from .. import exceptions
from ..diff import Diff

OUTPUT_HANDLERS = None
DIFF_OUTPUT_HANDLERS = None


@dataclass()
class ScanOutputBase(metaclass=ABCMeta):
    min_score: int = 0
    output_location: str = "-"
    tag_filters: list = field(default_factory=list)
    verbosity: int = 1

    @abstractmethod
    def __enter__(self):
        ...

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    @classmethod
    def from_uri(cls, uri: str, opts: Optional[dict] = None) -> ScanOutputBase:
        if opts is None:
            opts = {}

        parsed = parse.urlparse(uri)
        parsed_qs = dict(parse.parse_qsl(parsed.query, keep_blank_values=True))

        if set(opts.keys()) & set(parsed_qs.keys()):
            raise exceptions.InvalidOutput("You can't specify the same options both via uri and command line options at the same time")

        for fmt_name, fmt in cls.get_all_output_formats().items():
            if fmt_name == uri:   # This will match "text" so we don't need to specify "text://<something>"
                return fmt(**opts)

            if fmt.is_supported(parsed_uri=parsed):
                fmt_class = fmt
                break
        else:
            raise exceptions.InvalidOutput("No such output format")

        # TODO: add support for tags from uri

        if parsed.netloc and parsed.path:
            opts["output_location"] = os.path.join(parsed.netloc, parsed.path)
        else:
            opts["output_location"] = parsed.netloc or parsed.path

        for opt in ():  # TODO
            if opt in parsed_qs:
                opts[opt] = qs_to_bool(parsed_qs[opt])

        for opt in ("min_score", "verbosity"):
            if opt in parsed_qs:
                opts[opt] = int(parsed_qs[opt])

        return fmt_class(**opts)

    def compile_filter_tags(self, tags: Optional[List[str]]):
        """
        compile input filter tags into an easy to use list of lambda's so the output hits can be filtered using map
        """
        for t in tags:
            # normalize tags to lowercase with `-` replaced to `_`
            t = t.strip().lower().replace('-', '_')

            if not t:
                continue

            if t.startswith("!"):  # It a tag is prefixed with `!` then it means to exclude findings with such tag
                self.tag_filters.append(lambda x: t[1:] not in x)
            else:
                self.tag_filters.append(lambda x: t in x)

    @classmethod
    @abstractmethod
    def is_supported(cls, parsed_uri) -> bool:
        ...

    @abstractmethod
    def output(self, hits, scan_metadata: dict):
        ...

    def filtered(self, hits):
        """
        Helper function get a list of filtered results regardless of the output type
        This list of results should then be serialized by a specific output format

        :param hits: input hits/results that will be filtered
        :return: a list of filtered results
        """
        hits = sorted(hits)

        processed = []

        for x in hits:
            # normalize tags
            tags = [t.lower().replace('-', '_') for t in x.tags]

            # if verbosity is below 2, informational results are filtered
            # norm is that informational results should have a score of 0
            if self.verbosity < 2 and x.informational and x.score == 0:
                continue
            elif not all(f(tags) for f in self.tag_filters):
                continue
            elif self.verbosity < 3 and x.name == "ASTParseError" and x._metadata.get("source") == "blob":
                continue
            else:
                processed.append(x)

        total_score = sum(x.score for x in processed)

        if self.min_score and self.min_score > total_score:
            raise exceptions.MinimumScoreNotReached(f"Score of {total_score} did not meet the minimum {self.min_score}")

        return processed

    @classmethod
    def get_all_output_formats(cls) -> Mapping[str, ScanOutputBase]:
        global OUTPUT_HANDLERS

        if not OUTPUT_HANDLERS:
            OUTPUT_HANDLERS = {}
            for x in pkg_resources.iter_entry_points("aura.output_handlers"):
                handler = x.load()
                OUTPUT_HANDLERS[x.name] = handler

        return OUTPUT_HANDLERS


@dataclass()
class DiffOutputBase(metaclass=ABCMeta):
    detections: bool = True
    all_detections: bool = False  # TODO: finish support for this
    output_same_renames: bool = False
    patch: bool = True
    output_location: str = "-"

    @classmethod
    def from_uri(cls, uri: str) -> DiffOutputBase:
        parsed = parse.urlparse(uri)
        parsed_qs = dict(parse.parse_qsl(parsed.query, keep_blank_values=True))

        for fmt_name, fmt in cls.get_all_output_formats().items():
            if fmt_name == uri:
                return fmt()

            if fmt.is_supported(parsed_uri=parsed):
                fmt_class = fmt
                break
        else:
            raise exceptions.InvalidOutput("No such output format")

        opts = {}

        if parsed.netloc and parsed.path:
            opts["output_location"] = os.path.join(parsed.netloc, parsed.path)
        else:
            opts["output_location"] = parsed.netloc or parsed.path

        for opt in ("detections", "all_detections", "output_same_renames", "patch"):
            if opt in parsed_qs:
                opts[opt] = qs_to_bool(parsed_qs[opt])

        return fmt_class(**opts)

    def filtered(self, diffs: List[Diff]) -> List[Diff]:
        out = []

        for diff in diffs:
            if not self.output_same_renames:
                if diff.operation == "R" and diff.similarity == 1.0:
                    continue

            out.append(diff)

        return out

    @classmethod
    @abstractmethod
    def is_supported(cls, parsed_uri) -> bool:
        ...

    @abstractmethod
    def output_diff(self, diffs: List[Diff]):
        ...

    @classmethod
    def get_all_output_formats(cls) -> Mapping[str, DiffOutputBase]:
        global DIFF_OUTPUT_HANDLERS

        if not DIFF_OUTPUT_HANDLERS:
            DIFF_OUTPUT_HANDLERS = {}
            for x in pkg_resources.iter_entry_points("aura.diff_output_handlers"):
                handler = x.load()
                DIFF_OUTPUT_HANDLERS[x.name] = handler

        return DIFF_OUTPUT_HANDLERS

    @abstractmethod
    def __enter__(self):
        ...

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass


def qs_to_bool(qs: Union[str, bool]) -> bool:
    """
    Convert value from query string to the bool format

    :param qs: value from the query string
    :type qs: str
    :return: converted value as bool
    :rtype: bool
    """
    if type(qs) == bool:
        return qs

    qs = qs.lower()
    if qs in ("y", "yes", "true", "1", "42", "jawohl", "da"):
        return True
    else:
        return False
