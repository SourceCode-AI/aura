import os
import shutil
import hashlib
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional

from . import utils
from . import config

logger = config.get_logger(__name__)


class Cache(ABC):
    DISABLE_CACHE = bool(os.environ.get("AURA_NO_CACHE"))
    __location: Optional[Path] = None

    @abstractmethod
    def __init__(self, cache_id):
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
        return self.get_location() / self.cid

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

    @classmethod
    def purge_cache(cls):  # TODO
        total, used, free = shutil.disk_usage(cls.get_location())
        cache_items = [x for x in cls.get_location().iterdir()]
        cache_items.sort(key=lambda x: x.stat().st_mtime)

    @classmethod
    def proxy_url(cls, *, url, fd, cache_id=None):
        return URLCache.proxy(url=url, fd=fd, cache_id=cache_id)

    @classmethod
    def proxy_mirror(cls, *, src: Path, cache_id=None):
        if cls.get_location() is None:  # Caching is disabled
            return src

        if cache_id is None:
            cache_id = src.name

        cache_id = f"mirror_{cache_id}"
        cache_pth: Path = cls.get_location() / cache_id

        if cache_pth.exists():
            logger.debug(f"Retrieving mirror file path {cache_id} from cache")
            return cache_pth

        if not src.exists():
            return src

        try:
            shutil.copyfile(src, cache_pth, follow_symlinks=True)
            return cache_pth
        except Exception as exc:
            cache_pth.unlink(missing_ok=True)
            raise exc

    def delete(self):
        self.cache_file_location.unlink(missing_ok=True)


class URLCache(Cache):
    def __init__(self, cache_id):
        self.cid = f"url_{cache_id}"

    @classmethod
    def cache_id(cls, url: [str, bytes]) -> str:
        if type(url) == bytes:
            burl = url
        else:
            burl = url.encode()

        return hashlib.md5(burl).hexdigest()

    @classmethod
    def proxy(cls, *, url, fd, group=None, cache_id=None):
        if cls.get_location() is None:
            return utils.download_file(url, fd=fd)

        metadata = {
            "url": url,
            "group": group,
            "type": "url"
        }

        if cache_id is None:
            cache_id = cls.cache_id(url=url)

        cache_obj = cls(cache_id)

        if cache_obj.is_valid:
            logger.info(f"Loading {cache_obj.cid} from cache")
            cache_obj.fetch(fd)
            return

        try:
            cache_obj.download(url)
            cache_obj.fetch(fd)
        except Exception as exc:
            cache_obj.delete()
            raise exc

    def fetch(self, fd):
        with self.cache_file_location.open("rb") as cfd:
            shutil.copyfileobj(cfd, fd)
            fd.flush()

    def download(self, url):
        with self.cache_file_location.open("wb") as cfd:
            utils.download_file(url, cfd)
            cfd.flush()


class MirrorJSON(Cache):
    def __init__(self, cache_id):
        self.cid = f"mirrorjson_{cache_id}"

    @classmethod
    def cache_id(cls, src: Path) -> str:
        return src.name

    def fetch(self, src: Path):
        shutil.copyfile(src=src, dst=self.cache_file_location, follow_symlinks=True)

    @classmethod
    def proxy(cls, *, src: Path):
        if cls.get_location() is None:  # Caching is disabled
            return src

        cache_id = MirrorJSON.cache_id(src=src)
        cache_obj = MirrorJSON(cache_id)

        if cache_obj.is_valid:
            logger.debug(f"Retrieving package mirror JSON {cache_obj.cid} from cache")
            return cache_obj.cache_file_location

        if not src.exists():
            return src

        try:
            cache_obj.fetch(src=src)
            return cache_obj.cache_file_location
        except Exception as exc:
            cache_obj.delete()
            raise exc
