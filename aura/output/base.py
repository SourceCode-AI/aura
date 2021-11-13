from __future__ import annotations

import os.path
from abc import ABCMeta, abstractmethod
from dataclasses import dataclass, field
from urllib import parse
from typing import List, Union, Mapping, Optional, Iterable, Any, Type

import pkg_resources

from . import filtering
from .. import exceptions
from ..analyzers.detections import Detection
from ..type_definitions import DiffType, DiffAnalyzerType


OUTPUT_HANDLER_CACHE = {}


@dataclass()
class OutputBase(metaclass=ABCMeta):
    out_fd: Any = None

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
    def get_all_output_formats(cls) -> Mapping[str, Type[OutputBase]]:
        handlers = OUTPUT_HANDLER_CACHE.setdefault(cls.entrypoint(), {})

        if not handlers:
            for x in pkg_resources.iter_entry_points(cls.entrypoint()):
                handler = x.load()
                handlers[x.name] = handler

        return handlers

    @classmethod
    def get_format(cls, uri: str, parsed: Optional[parse.ParseResult] = None) -> Type[OutputBase]:
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
    output_location: str = "-"
    filter_config: filtering.FilterConfiguration  = field(default_factory=filtering.FilterConfiguration)

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

        filter_opts = {
            "tag_filters": opts.pop("tags", []),
            "min_score": int(parsed_qs.get("min_score", 0)),
            "verbosity": int(parsed_qs.get("verbosity", 1))
        }

        filter_cfg = filtering.FilterConfiguration(**filter_opts)

        for opt in ():  # TODO
            if opt in parsed_qs:
                opts[opt] = qs_to_bool(parsed_qs[opt])

        obj: ScanOutputBase = fmt_class(filter_config=filter_cfg, **opts)
        return obj

    @abstractmethod
    def output(self, hits: List[Detection], scan_metadata: dict):
        ...


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
