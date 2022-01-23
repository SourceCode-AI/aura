from __future__ import annotations

import dataclasses
import os
import shutil
import hashlib
import datetime
import pickle
import concurrent.futures
import typing as t
from html.parser import HTMLParser
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional, List, Generator, Iterable, BinaryIO, Tuple, Set, Dict, Type

import click
import requests
from packaging.utils import canonicalize_name

from . import utils
from . import config
from .pattern_matching import ASTPattern
from .json_proxy import loads, dumps


logger = config.get_logger(__name__)


class SimpleIndexParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.pkgs = []
        self.current_tag = None

    def handle_starttag(self, tag, attrs) -> None:
        self.current_tag = tag

    def handle_endtag(self, tag: str) -> None:
        self.current_tag = None

    def handle_data(self, data: str) -> None:
        if self.current_tag == "a":
            self.pkgs.append(canonicalize_name(data))


class CacheItem:
    def __init__(self, path: Path):
        self.path = path
        self.metadata = loads(path.read_text())

        self.cls = CACHE_TYPES[self.type]
        self.item_path = path.parent / f"{self.cls.prefix}{self.metadata['id']}"
        self.item_stat = self.item_path.stat()
        # Used to avoid re-listing the cache content to find deleted items
        # Used for example in tests to assert which cache items were deleted
        self._deleted = False

    @classmethod
    def iter_items(cls, tags=None) -> Iterable[CacheItem]:
        tags = set(tags or ())

        if (cache_location:=Cache.get_location()) is None:
            return

        for x in cache_location.iterdir():
            if not x.name.endswith(".metadata.json"):
                continue

            obj = cls(x)

            if tags:
                if obj.type in tags or tags.intersection(obj.tags):
                    yield obj
            else:
                yield obj

    @property
    def mtime(self) -> int:
        return int(self.item_stat.st_mtime)

    @property
    def size(self) -> int:
        return self.item_stat.st_size

    @property
    def is_expired(self) -> bool:
        now = datetime.datetime.utcnow()
        modified = datetime.datetime.utcfromtimestamp(self.mtime)
        exp_threshold = get_expiration()
        return now > modified+exp_threshold

    @property
    def type(self) -> str:
        return self.metadata["type"]

    @property
    def tags(self) -> Set[str]:
        return set(self.metadata.get("tags", ()))

    def delete(self):
        self.item_path.unlink(missing_ok=True)
        self.path.unlink(missing_ok=True)
        self._deleted = True

    @classmethod
    def analyze(cls) -> Generator[CacheItem, None, None]:
        items = list(cls.iter_items())
        items.sort(key=lambda x: -x.size)
        yield from items

    @classmethod
    def cleanup(cls, items: Optional[Iterable[CacheItem]]=None):
        cache_loc = Cache.get_location()
        if cache_loc is None:
            return

        total, used, free = shutil.disk_usage(cache_loc)
        remaining = used
        threshold = get_cache_threshold()

        if items is None:
            items = cls.analyze()

        for x in items:  # type: CacheItem
            if x.is_expired:
                pass
            elif remaining < threshold:
                continue

            remaining -= x.size
            x.delete()


@dataclasses.dataclass(slots=True, kw_only=True)
class CacheRequest(ABC):
    cache_id: Optional[str]

    @abstractmethod
    def create_cache_id(self) -> str:
        ...

    @abstractmethod
    def proxy(self) -> t.Any:
        ...


class Cache(ABC):
    req: CacheRequest
    prefix: t.ClassVar[str]
    DISABLE_CACHE = bool(os.environ.get("AURA_NO_CACHE"))
    __location: Optional[Path] = None

    def __init__(self, cache_request: CacheRequest):
        self.req = cache_request

    @classmethod
    @abstractmethod
    def proxy(cls, cache_request: CacheRequest):
        ...

    @property
    def cache_file_location(self) -> Optional[Path]:
        if location:=self.get_location():
            return location / f"{self.prefix}{self.req.cache_id}"
        return None

    @property
    def metadata_location(self) -> Optional[Path]:
        if location:=self.get_location():
            return location / f"{self.prefix}{self.req.cache_id}.metadata.json"
        return None

    @property
    def is_valid(self) -> bool:
        if (c_location:=self.cache_file_location):
            return c_location.exists()

        return False

    @property
    @abstractmethod
    def metadata(self) -> dict:
        ...

    @classmethod
    def get_location(cls) -> Optional[Path]:
        if cls.DISABLE_CACHE:
            return None

        if cls.__location is None:
            c = os.environ.get("AURA_CACHE_LOCATION") or config.CFG["aura"].get("cache_location")
            if c:
                c = Path(c).expanduser().resolve()
                logger.debug(f"Cache location set to {c}")

                if not c.exists():
                    c.mkdir(parents=True)
                cls.__location = c

        return cls.__location

    def save_metadata(self):
        if (loc:=self.metadata_location):
            loc.write_text(dumps(self.metadata))
        else:
            raise ValueError(f"Could not determine the metadata location")

    def delete(self):
        if self.cache_file_location:
            self.cache_file_location.unlink(missing_ok=True)
        if self.metadata_location:
            self.metadata_location.unlink(missing_ok=True)


@dataclasses.dataclass(slots=True, kw_only=True)
class URLCacheRequest(CacheRequest):
    url: str
    cache_id: t.Optional[str] = None
    tags: t.Optional[t.List[str]] = None
    session: t.Any = None
    throw_exc: bool = True

    def __post_init__(self):
        if self.session is None:
            self.session = requests

        if self.cache_id is None:
            self.cache_id = self.create_cache_id()

    def create_cache_id(self) -> str:
        burl: bytes

        if type(self.url) == bytes:
            burl = t.cast(bytes, self.url)
        elif type(self.url) == str:
            burl = self.url.encode()
        else:
            raise ValueError(f"Unknown type received: `{repr(self.url)}`")

        return hashlib.md5(burl).hexdigest()

    def proxy(self):
        return CACHE_TYPES["url"].proxy(self)


class URLCache(Cache):
    prefix = "url_"
    req: URLCacheRequest

    @classmethod
    def proxy(cls, cache_request: URLCacheRequest) -> str:
        if cls.get_location() is None:
            resp = cache_request.session.get(cache_request.url)
            if cache_request.throw_exc:
                resp.raise_for_status()
            return resp.text

        cache_obj = cls(cache_request)

        if cache_obj.is_valid:
            logger.info(f"Loading {cache_request.cache_id} from cache")
            return cache_obj.fetch()

        try:
            resp = cache_request.session.get(cache_request.url)
            if cache_request.throw_exc:
                resp.raise_for_status()
            if loc:=cache_obj.cache_file_location:
                loc.write_text(resp.text)
            else:
                raise RuntimeError(f"Could not determine cache location for `{cache_obj}`")
            cache_obj.save_metadata()
            return resp.text
        except Exception:
            cache_obj.delete()
            raise

    @property
    def metadata(self) -> dict:
        return {
            "url": self.req.url,
            "id": self.req.cache_id,
            "tags": self.req.tags,
            "type": self.prefix.rstrip("_")
        }

    def fetch(self) -> str:
        return self.cache_file_location.read_text()


@dataclasses.dataclass(slots=True, kw_only=True)
class FileDownloadRequest(URLCacheRequest):
    fd: Optional[BinaryIO]=None

    def proxy(self):
        CACHE_TYPES["filedownload"].proxy(self)


class FileDownloadCache(URLCache):
    prefix = "filedownload_"
    req: FileDownloadRequest

    @classmethod
    def proxy(cls, cache_request: FileDownloadRequest):
        if cls.get_location() is None:
            if cache_request.fd is None:
                logger.warning("FD is set to None but cache is disabled, URL caching has zero effect")
                return

            return utils.download_file(cache_request.url, fd=cache_request.fd)

        cache_obj = cls(cache_request)

        if cache_obj.is_valid:
            logger.debug(f"Loading {cache_obj.cid} from cache")
            if cache_request.fd:
                cache_obj.fetch()
            return

        try:
            cache_obj.download()
            cache_obj.save_metadata()
            if cache_request.fd:
                cache_obj.fetch()
        except Exception:
            cache_obj.delete()
            raise

    def fetch(self):
        with self.cache_file_location.open("rb") as cfd:
            shutil.copyfileobj(cfd, self.req.fd)
            self.req.fd.flush()

    def download(self):
        with self.cache_file_location.open("wb") as cfd:
            utils.download_file(self.req.url, cfd, session=self.req.session)
            cfd.flush()


@dataclasses.dataclass(slots=True, kw_only=True)
class MirrorRequest(CacheRequest):
    src: Path
    cache_id: Optional[str] = None
    tags: List[str] = dataclasses.field(default_factory=list)

    def __post_init__(self):
        if self.cache_id is None:
            self.cache_id = self.create_cache_id()

    def create_cache_id(self) -> str:
        return f"{self.src.name}"

    def proxy(self):
        return CACHE_TYPES["mirror"].proxy(self)


class MirrorCache(Cache):
    prefix = "mirror_"

    @classmethod
    def proxy(cls, cache_request: MirrorRequest) -> Path:
        if cls.get_location() is None:  # Caching is disabled
            return cache_request.src

        cache_obj = cls(cache_request)

        if cache_obj.is_valid:
            logger.debug(f"Retrieving package mirror JSON {cache_obj.req.cache_id} from cache")
            return cache_obj.cache_file_location

        # If the mirror is a mounted network drive (common configuration), this would trigger a network traffic/calls
        # We want to prevent any network traffic for performance reasons if possible,
        # so we check if the path exists AFTER we check for the cache entry, e.g. `cache_obj.is_valid`
        if not cache_request.src.exists():
            return cache_request.src

        try:
            cache_obj.fetch()
            return cache_obj.cache_file_location
        except Exception as exc:
            cache_obj.delete()
            raise exc

    @property
    def metadata(self) -> dict:
        return {
            "src": str(self.req.src),
            "id": self.req.cache_id,
            "tags": self.req.tags,
            "type": self.prefix.rstrip("_")
        }

    def fetch(self):
        shutil.copyfile(src=self.req.src, dst=self.cache_file_location, follow_symlinks=True)
        self.save_metadata()


@dataclasses.dataclass(slots=True, kw_only=True)
class PyPIPackageListRequest(CacheRequest):
    cache_id: str = ""
    tags: List[str] = dataclasses.field(default_factory=list)

    def create_cache_id(self) -> str:
        return ""

    def proxy(self):
        return CACHE_TYPES["pypi_package_list"].proxy(self)


class PyPIPackageList(Cache):
    prefix = "pypi_package_list"

    @classmethod
    def _get_package_list(cls) -> List[str]:
        parser = SimpleIndexParser()
        parser.feed(requests.get("https://pypi.org/simple/").text)
        return parser.pkgs

    @classmethod
    def proxy(cls, cache_request: PyPIPackageListRequest) -> List[str]:
        if cls.get_location() is None:
            return cls._get_package_list()

        cache_obj = cls(cache_request)
        if cache_obj.is_valid and (c_location:=cache_obj.cache_file_location):
            return loads(c_location.read_text())

        try:
            return cache_obj.fetch()
        except Exception as exc:
            cache_obj.delete()
            raise exc

    @property
    def metadata(self) -> dict:
        return {
            "id": self.req.cache_id,
            "tags": self.req.tags,
            "type": self.prefix
        }

    def fetch(self):
        packages = self._get_package_list()
        self.save_metadata()
        self.cache_file_location.write_text(dumps(packages))
        return packages


@dataclasses.dataclass(slots=True, kw_only=True)
class ASTPatternsRequest(CacheRequest):
    default: t.ClassVar = None

    patterns: list = dataclasses.field(default_factory=lambda: config.SEMANTIC_RULES.get("patterns", []))
    cache_id: Optional[str] = None
    tags: List[str] = dataclasses.field(default_factory=list)
    compiled_patterns: t.Any = None

    def __post_init__(self):
        if self.cache_id is None:
            self.cache_id = self.create_cache_id()

    def create_cache_id(self) -> str:
        # This will also make sure that cached AST patterns are invalidated if they change
        return utils.fast_checksum(dumps(self.patterns))

    def compile(self) -> Tuple[ASTPattern, ...]:
        if not self.compiled_patterns:
            with concurrent.futures.ThreadPoolExecutor() as e:
                self.compiled_patterns = tuple(e.map(ASTPattern, self.patterns))
        return self.compiled_patterns

    @classmethod
    def get_default(cls) -> ASTPatternsRequest:
        if not cls.default:
            cls.default = cls(patterns=config.SEMANTIC_RULES.get("patterns", []))

        assert cls.default is not None
        return cls.default

    def proxy(self) -> Tuple[ASTPattern, ...]:
        return CACHE_TYPES["ast_patterns"].proxy(self)


class ASTPatternCache(Cache):
    prefix = "ast_patterns_"
    req: ASTPatternsRequest

    @classmethod
    def proxy(cls, cache_request: ASTPatternsRequest) -> Tuple[ASTPattern, ...]:
        if cls.get_location() is None:
            return cache_request.compile()

        cache_obj = cls(cache_request)

        if cache_obj.is_valid:
            return pickle.loads(cache_obj.cache_file_location.read_bytes())

        try:
            cache_obj.save_metadata()
            cache_obj.cache_file_location.write_bytes(pickle.dumps(cache_obj.req.compile()))
            return cache_obj.req.compile()
        except Exception as exc:
            cache_obj.delete()
            raise exc

    @property
    def metadata(self) -> dict:
        return {
            "id": self.req.cache_id,
            "tags": self.req.tags,
            "type": "ast_patterns"
        }


CACHE_TYPES: Dict[str, Type[Cache]] = {
    "url": URLCache,
    "filedownload": FileDownloadCache,
    "mirror": MirrorCache,
    "pypi_package_list": PyPIPackageList,
    "ast_patterns": ASTPatternCache
}


def get_cache_threshold() -> int:
    desc = config.CFG.get("cache", {}).get("max-size", 0)
    return utils.convert_size(desc)


def purge(standard: bool=False):
    if Cache.DISABLE_CACHE:
        return

    mode = config.get_cache_mode()
    if mode not in ("ask", "auto", "always"):
        raise ValueError(f"Cache mode has invalid value in the configuration: '{mode}'")

    if mode == "ask" and standard:
        if click.confirm("Would you like to purge the cache?"):
            CacheItem.cleanup()
    elif (mode == "auto" and standard) or mode == "always":
        CacheItem.cleanup()


def get_expiration(category: str="default") -> datetime.timedelta:
    exp_section = config.CFG.get("cache", {}).get("expiration", {})
    exp_hours = exp_section.get(category) or exp_section.get("default") or 0
    return datetime.timedelta(hours=exp_hours)
