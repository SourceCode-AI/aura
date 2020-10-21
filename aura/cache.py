import os
import shutil
import hashlib
import logging
from pathlib import Path
from typing import Optional

from . import utils
from . import config

logger = logging.getLogger(__name__)


class Cache:
    DISABLE_CACHE = bool(os.environ.get("AURA_NO_CACHE"))
    __location: Optional[Path] = None

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
        if cls.get_location() is None:
            return utils.download_file(url, fd=fd)

        if cache_id is None:
            cache_id = hashlib.md5(url).hexdigest()

        cache_id = f"url_{cache_id}"
        cache_pth: Path = cls.get_location()/cache_id

        if cache_pth.is_file():
            logger.info(f"Loading {cache_id} from cache")
            with cache_pth.open("rb") as cfd:
                shutil.copyfileobj(cfd, fd)
                return

        try:
            with cache_pth.open("wb") as cfd:
                utils.download_file(url, cfd)
                cfd.flush()
            with cache_pth.open("rb") as cfd:
                shutil.copyfileobj(cfd, fd)
        except Exception as exc:
            cache_pth.unlink(missing_ok=True)
            raise exc

    @classmethod
    def proxy_mirror(cls, *, src: Path, cache_id=None):
        if not src.exists():
            return None
        elif cls.get_location() is None:
            return src

        if cache_id is None:
            cache_id = src.name

        cache_id = f"mirror_{cache_id}"
        cache_pth: Path = cls.get_location() / cache_id

        try:
            if not cache_pth.exists():
                with cache_pth.open("wb") as cfd:
                    with src.open("rb") as fd:
                        shutil.copyfileobj(fd, cfd)
                        cfd.flush()
            return cache_pth
        except Exception as exc:
            cache_pth.unlink(missing_ok=True)
            raise exc
