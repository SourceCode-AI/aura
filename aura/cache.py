from __future__ import annotations

import os
import shutil
import hashlib
import datetime
import pickle
import xmlrpc.client
import concurrent.futures
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional, List, Generator, Iterable, BinaryIO, Tuple, Set

import click
import requests
from packaging.utils import canonicalize_name

from . import utils
from . import config
from .pattern_matching import ASTPattern
from .json_proxy import loads, dumps


logger = config.get_logger(__name__)


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
    def iter_items(cls, tags=None) -> Generator[CacheItem, None, None]:
        tags = set(tags or ())

        for x in Cache.get_location().iterdir():
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
        return self.item_stat.st_mtime

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


class Cache(ABC):
    prefix = ""
    DISABLE_CACHE = bool(os.environ.get("AURA_NO_CACHE"))
    __location: Optional[Path] = None

    @abstractmethod
    def __init__(self, *args, **kwargs):
        ...

    @classmethod
    @abstractmethod
    def cache_id(cls, arg) -> str:
        ...

    @classmethod
    @abstractmethod
    def proxy(cls, **kwargs):
        ...

    @property
    def cache_file_location(self) -> Path:
        return self.get_location() / f"{self.prefix}{self.cid}"

    @property
    def metadata_location(self) -> Path:
        return self.get_location() / f"{self.prefix}{self.cid}.metadata.json"

    @property
    def is_valid(self) -> bool:
        if self.cache_file_location.exists():
            return True

        return False

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
        self.metadata_location.write_text(dumps(self.metadata))

    def delete(self):
        self.cache_file_location.unlink(missing_ok=True)
        self.metadata_location.unlink(missing_ok=True)


class URLCache(Cache):
    prefix = "url_"

    def __init__(self, url: str, cache_id=None, tags: Optional[List[str]]=None):
        self.url = url
        self.tags = tags or []
        self.cid = cache_id or self.cache_id(url=url)

    @classmethod
    def cache_id(cls, url: [str, bytes]) -> str:
        if type(url) == bytes:
            burl = url
        else:
            burl = url.encode()

        return hashlib.md5(burl).hexdigest()

    @classmethod
    def proxy(cls, *, url: str, cache_id=None, tags=None, session=None, throw_exc=True) -> str:
        if session is None:
            session = requests

        if cls.get_location() is None:
            resp = session.get(url)
            if throw_exc:
                resp.raise_for_status()
            return resp.text

        cache_obj = cls(url=url, cache_id=cache_id, tags=tags)

        if cache_obj.is_valid:
            logger.info(f"Loading {cache_obj.cid} from cache")
            return cache_obj.fetch()

        try:
            resp = session.get(url)
            if throw_exc:
                resp.raise_for_status()
            cache_obj.cache_file_location.write_text(resp.text)
            cache_obj.save_metadata()
            return resp.text
        except Exception:
            cache_obj.delete()
            raise

    @property
    def metadata(self) -> dict:
        return {
            "url": self.url,
            "id": self.cid,
            "tags": self.tags,
            "type": self.prefix.rstrip("_")
        }

    def fetch(self) -> str:
        return self.cache_file_location.read_text()


class FileDownloadCache(URLCache):
    prefix = "filedownload_"

    @classmethod
    def proxy(cls, *, url, fd: Optional[BinaryIO]=None, cache_id=None, tags=None, session=None):
        if cls.get_location() is None:
            if fd is None:
                logger.warning("FD is set to None but cache is disabled, URL caching has zero effect")
                return

            return utils.download_file(url, fd=fd)

        cache_obj = cls(url=url, cache_id=cache_id, tags=tags)

        if cache_obj.is_valid:
            logger.debug(f"Loading {cache_obj.cid} from cache")
            if fd:
                cache_obj.fetch(fd)
            return

        try:
            cache_obj.download()
            cache_obj.save_metadata()
            if fd:
                cache_obj.fetch(fd)
        except Exception:
            cache_obj.delete()
            raise

    def fetch(self, fd):
        with self.cache_file_location.open("rb") as cfd:
            shutil.copyfileobj(cfd, fd)
            fd.flush()

    def download(self, session=None):
        with self.cache_file_location.open("wb") as cfd:
            utils.download_file(self.url, cfd, session=session)
            cfd.flush()


class MirrorJSON(Cache):
    prefix = "mirrorjson_"

    def __init__(self, src: Path, cache_id=None, tags: Optional[List[str]]=None):
        self.src = src
        self.tags = tags or []
        self.cid = cache_id or self.cache_id(src)

    @classmethod
    def cache_id(cls, src: Path) -> str:
        return src.name

    @classmethod
    def proxy(cls, *, src: Path) -> Path:
        if cls.get_location() is None:  # Caching is disabled
            return src

        cache_obj = MirrorJSON(src=src)

        if cache_obj.is_valid:
            logger.debug(f"Retrieving package mirror JSON {cache_obj.cid} from cache")
            return cache_obj.cache_file_location

        # If the mirror is a mounted network drive (common configuration), this would trigger a network traffic/calls
        # We want to prevent any network traffic for performance reasons if possible,
        # so we check if the path exists AFTER we check for the cache entry, e.g. `cache_obj.is_valid`
        if not src.exists():
            return src

        try:
            cache_obj.fetch(src=src)
            return cache_obj.cache_file_location
        except Exception as exc:
            cache_obj.delete()
            raise exc

    @property
    def metadata(self) -> dict:
        return {
            "src": str(self.src),
            "id": self.cid,
            "tags": self.tags,
            "type": "mirrorjson"
        }

    def fetch(self, src: Path):
        shutil.copyfile(src=src, dst=self.cache_file_location, follow_symlinks=True)
        self.save_metadata()


class MirrorFile(Cache):
    prefix = "mirror_"

    def __init__(self, src: Path, cache_id=None, tags: Optional[List[str]]=None):
        self.src = src
        self.tags = tags or []
        self.cid = cache_id or self.cache_id(src)

    @classmethod
    def cache_id(cls, arg: Path) -> str:
        return arg.name

    @classmethod
    def proxy(cls, *, src: Path, cache_id=None, tags=None) -> Path:
        if cls.get_location() is None:  # Caching is disabled
            return src

        cache_obj = cls(src=src, cache_id=cache_id, tags=tags)

        if cache_obj.is_valid:
            logger.debug(f"Retrieving mirror file path {cache_obj.cid} from cache")
            return cache_obj.cache_file_location

        if not src.exists():
            return src

        try:
            cache_obj.fetch()
            return cache_obj.cache_file_location
        except Exception as exc:
            cache_obj.delete()
            raise exc

    @property
    def metadata(self) -> dict:
        return {
            "src": self.src,
            "id": self.cid,
            "tags": self.tags,
            "type": "mirror"
        }

    def fetch(self):
        shutil.copyfile(src=self.src, dst=self.cache_file_location, follow_symlinks=True)
        self.save_metadata()


class PyPIPackageList(Cache):
    prefix = "pypi_package_list"

    def __init__(self, cache_id="", tags: Optional[List[str]]=None):
        self.cid = cache_id
        self.tags = tags or []

    @classmethod
    def cache_id(cls, arg) -> str:
        return ""

    @classmethod
    def _get_package_list(cls) -> List[str]:
        repo = xmlrpc.client.ServerProxy(
            "https://pypi.python.org/pypi", use_builtin_types=True
        )
        return [canonicalize_name(x) for x in repo.list_packages()]

    @classmethod
    def proxy(cls) -> List[str]:
        if cls.get_location() is None:
            return cls._get_package_list()

        cache_obj = cls()
        if cache_obj.is_valid:
            return loads(cache_obj.cache_file_location.read_text())

        try:
            return cache_obj.fetch()
        except Exception as exc:
            cache_obj.delete()
            raise exc

    @property
    def metadata(self) -> dict:
        return {
            "id": self.cid,
            "tags": self.tags,
            "type": self.prefix
        }

    def fetch(self):
        packages = self._get_package_list()
        self.save_metadata()
        self.cache_file_location.write_text(dumps(packages))
        return packages


class ASTPatternCache(Cache):
    prefix = "ast_patterns_"
    # We want to store the compiled patterns also here as it is accessed very frequently
    # (de)serializing the ast patterns on each access would be very slow
    _AST_PATTERN_CACHE = None
    _SIGNATURE_HASH = None

    def __init__(self, cache_id=None, tags: Optional[List[str]]=None):
        self.cid = cache_id or self.get_patterns_hash()
        self.tags = tags or []

    @classmethod
    def _compile_all(cls):
        if cls._AST_PATTERN_CACHE is None:
            with concurrent.futures.ThreadPoolExecutor() as e:
                cls._AST_PATTERN_CACHE = tuple(e.map(ASTPattern, config.SEMANTIC_RULES.get("patterns", [])))

        return cls._AST_PATTERN_CACHE

    @classmethod
    def get_patterns_hash(cls) -> str:
        """
        Compute the checksum of signatures/configuration
        ast pattern cache should be invalidated if the configuration changes
        """
        if cls._SIGNATURE_HASH is None:
            payload = dumps(config.SEMANTIC_RULES.get("patterns", []))
            cls._SIGNATURE_HASH = utils.fast_checksum(payload)

        return cls._SIGNATURE_HASH

    @classmethod
    def cache_id(cls, arg) -> str:
        return cls.get_patterns_hash()

    @classmethod
    def proxy(cls, cache_id=None) -> Tuple[ASTPattern, ...]:
        if cls._AST_PATTERN_CACHE:
            return cls._AST_PATTERN_CACHE

        if cls.get_location() is None:
            return cls._compile_all()

        cache_obj = cls(cache_id=cache_id)
        if cache_obj.is_valid:
            return pickle.loads(cache_obj.cache_file_location.read_bytes())

        try:
            patterns = cls._compile_all()
            cache_obj.save_metadata()
            cache_obj.cache_file_location.write_bytes(pickle.dumps(patterns))
            return patterns
        except Exception as exc:
            cache_obj.delete()
            raise exc

    @property
    def metadata(self) -> dict:
        return {
            "id": self.cid,
            "tags": self.tags,
            "type": "ast_patterns"
        }


CACHE_TYPES = {
    "url": URLCache,
    "filedownload": FileDownloadCache,
    "mirror": MirrorFile,
    "mirrorjson": MirrorJSON,
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
