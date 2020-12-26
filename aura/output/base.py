from __future__ import annotations

import os.path
from abc import ABCMeta, abstractmethod
from dataclasses import dataclass, field
from urllib import parse
from typing import List, Union, Mapping, Optional, Iterable

import pkg_resources

from .. import exceptions
from ..type_definitions import DiffType, DiffAnalyzerType


OUTPUT_HANDLER_CACHE = {}


class OutputBase(metaclass=ABCMeta):
    def __init__(self, *args, **kwargs):
        pass

    @classmethod
    @abstractmethod
    def protocol(cls) -> str:
        ...

    @classmethod
    @abstractmethod
    def entrypoint(cls) -> str:
        ...

    @classmethod
    def is_supported(cls, parsed_uri) -> bool:
        return parsed_uri.scheme == cls.protocol()

    @classmethod
    def get_all_output_formats(cls) -> Mapping[str, OutputBase]:
        handlers = OUTPUT_HANDLER_CACHE.setdefault(cls.entrypoint(), {})

        if not handlers:
            for x in pkg_resources.iter_entry_points(cls.entrypoint()):
                handler = x.load()
                handlers[x.name] = handler

        return handlers

    @classmethod
    def get_format(cls, uri: str, parsed=None) -> OutputBase:
        if not parsed:
            parsed = parse.urlparse(uri)

        for fmt_name, fmt in cls.get_all_output_formats().items():
            if fmt_name == uri:  # This will match also "protocol" so we don't need to specify "protocol://"
                return fmt
            elif fmt.is_supported(parsed_uri=parsed):
                return fmt

        raise exceptions.InvalidOutput(f"No such output format `{uri}`")


@dataclass()
class ScanOutputBase(OutputBase, metaclass=ABCMeta):
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
    def entrypoint(cls) -> str:
        return "aura.output_handlers"

    @classmethod
    def from_uri(cls, uri: str, opts: Optional[dict] = None) -> ScanOutputBase:
        if opts is None:
            opts = {}

        parsed = parse.urlparse(uri)
        parsed_qs = dict(parse.parse_qsl(parsed.query, keep_blank_values=True))

        if set(opts.keys()) & set(parsed_qs.keys()):
            raise exceptions.InvalidOutput("You can't specify the same options both via uri and command line options at the same time")

        fmt_class = cls.get_format(uri, parsed)

        # TODO: add support for tags from uri

        if parsed.netloc and parsed.path:
            opts["output_location"] = os.path.join(parsed.netloc, parsed.path)
        elif uri != fmt_class.protocol():
            opts["output_location"] = parsed.netloc or parsed.path

        tags = opts.pop("tags", [])

        for opt in ():  # TODO
            if opt in parsed_qs:
                opts[opt] = qs_to_bool(parsed_qs[opt])

        for opt in ("min_score", "verbosity"):
            if opt in parsed_qs:
                opts[opt] = int(parsed_qs[opt])

        obj: ScanOutputBase = fmt_class(**opts)
        obj.compile_filter_tags(tags)
        return obj

    def compile_filter_tags(self, tags: Iterable[str]):
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


@dataclass()
class TyposquattingOutputBase(OutputBase, metaclass=ABCMeta):
    @classmethod
    def entrypoint(cls) -> str:
        return "aura.typosquatting_output_handlers"

    @classmethod
    def from_uri(cls, uri: str) -> TyposquattingOutputBase:
        return cls.get_format(uri)()

    @abstractmethod
    def output_typosquatting(self, entries):
        ...


@dataclass()
class DiffOutputBase(OutputBase, metaclass=ABCMeta):
    detections: bool = True
    output_same_renames: bool = False
    patch: bool = True
    output_location: str = "-"

    @classmethod
    def entrypoint(cls) -> str:
        return "aura.diff_output_handlers"

    @classmethod
    def from_uri(cls, uri: str, opts: Optional[dict] = None) -> DiffOutputBase:
        parsed = parse.urlparse(uri)
        parsed_qs = dict(parse.parse_qsl(parsed.query, keep_blank_values=True))

        if opts is None:
            opts = {}

        fmt_class = cls.get_format(uri, parsed)

        if parsed.netloc and parsed.path:
            opts["output_location"] = os.path.join(parsed.netloc, parsed.path)
        elif uri != fmt_class.protocol():
            opts["output_location"] = parsed.netloc or parsed.path

        for opt in ("detections", "all_detections", "output_same_renames", "patch"):
            if opt in parsed_qs:
                opts[opt] = qs_to_bool(parsed_qs[opt])

        return fmt_class(**opts)

    def filtered(self, diffs: List[DiffType]) -> List[DiffType]:
        out = []

        for diff in diffs:
            if not self.output_same_renames:
                # Can't use only MD5 because tests will fail
                # (files do not exists so both md5s are set to none hence equal)
                if diff.operation in "RM" and diff.a_scan.md5 == diff.b_scan.md5 and diff.similarity == 1.0:
                    continue

            out.append(diff)

        return out

    @abstractmethod
    def output_diff(self, diff_analyzer: DiffAnalyzerType):
        ...

    @abstractmethod
    def __enter__(self):
        ...

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass


@dataclass()
class InfoOutputBase(OutputBase, metaclass=ABCMeta):
    @classmethod
    def entrypoint(cls) -> str:
        return "aura.info_output_handlers"

    @classmethod
    def from_uri(cls, uri: str) -> InfoOutputBase:
        return cls.get_format(uri)()

    @abstractmethod
    def output_info_data(self, data):
        ...


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
