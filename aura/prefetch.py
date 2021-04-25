import asyncio
import logging
from typing import Iterable, TextIO

import tqdm

from . import github
from . import mirror
from . import cache
from .worker_executor import non_blocking, AsyncQueue
from .exceptions import NoSuchPackage
from .uri_handlers.base import URIHandler


logger = logging.getLogger(__name__)


async def fetch_package(uri_queue, github_prefetcher):
    try:
        while True:
            uri = await uri_queue.get()
            try:
                logger.info(f"Prefetching: `{uri}`")
                handler = await non_blocking(URIHandler.from_uri, uri)
                for x in await non_blocking(handler.get_paths):
                    if pkg := x.metadata.get("package_instance"):
                        source_url = pkg.source_url
                        if source_url:
                            await github_prefetcher.queue.put(source_url)
            except NoSuchPackage:
                logger.info(f"Package does not exists: `{uri}`")
            except Exception:
                logger.exception(f"An error occurred while prefetching the uri: `{uri}`")
            finally:
                uri_queue.task_done()
    except asyncio.CancelledError:
        pass


def prefetch_mirror(uris: Iterable[str], workers=10):
    logger.info("Caching AST patterns")
    cache.ASTPatternCache.proxy()

    logger.info("Caching list of packages on pypi")
    cache.PyPIPackageList.proxy()

    #logger.info("Prefetching package JSON information")
    #lm = mirror.LocalMirror()
    #pkgs = tuple(lm.list_packages())
    #for x in tqdm.tqdm(pkgs, leave=False):
    #    lm.get_json(x)

    loop = asyncio.get_event_loop()

    pf = github.GitHubPrefetcher()
    loop.create_task(pf.process())

    uri_queue = AsyncQueue(desc="Mirror package prefetch")

    workers = [loop.create_task(fetch_package(uri_queue, pf)) for _ in range(workers)]

    for uri in uris:
        uri_queue.put_nowait(uri)

    logger.info("Waiting for prefetch workers to finish")

    loop.run_until_complete(uri_queue.join())

    # Cancel prefetch workers
    for worker in workers:
        worker.cancel()

    # Wait for all tasks to finish
    logger.info("All coroutines spawned, waiting for work to finish...")
    loop.run_until_complete(pf.queue.put(github.GitHubPrefetcher.STOP))

    pending = asyncio.all_tasks(loop=loop)
    loop.run_until_complete(asyncio.gather(*pending))

    loop.stop()
    loop.close()



def read_uris(file_input: TextIO) -> Iterable[str]:
    for line in file_input:
        line = line.strip()
        if line.startswith("#") or not line:
            continue
        else:
            if (not line.startswith("mirror://")) and mirror.LocalMirror.get_mirror_path():
                line = "mirror://" + line

            yield line
