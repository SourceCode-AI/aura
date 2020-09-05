import time
from concurrent import futures
from typing import Optional

import tqdm

from . import config


Wait = object()


class AuraExecutor:
    def __init__(self, fork: Optional[bool]=None, *, job_queue=None):
        if fork is None:
            self.fork = config.CFG["aura"].get("async", True)  # FIXME
        else:
            self.fork = fork

        if self.fork:
            self.executor = futures.ProcessPoolExecutor()
        else:
            self.executor = futures.ThreadPoolExecutor()

        self.jobs = set()
        self.total = 0
        self.completed = 0
        self.q = job_queue
        self.pg = tqdm.tqdm(
            desc="Analyzing files",
            bar_format="{desc}: {percentage:3.0f}%|{bar}| {n_fmt}/{total_fmt}",
            leave=False,
            disable=config.PROGRESSBAR_DISABLED
        )

    def __len__(self):
        return sum(x.done() for x in self.jobs)

    def __bool__(self):
        """
        Returns `False` if all jobs finished executing, otherwise returns `True`
        """
        return len(self.jobs) != 0 and all(x.done() for x in self.jobs)

    def __iter__(self) -> futures.Future:
        for future in futures.as_completed(tuple(self.jobs)):
            self.jobs.remove(future)
            self._update_progress()
            yield future

    def __del__(self):
        self.pg.close()

    def completed_cb(self, _):
        self.completed += 1
        self._update_progress()

    def submit(self, fn, *args, **kwargs) -> futures.Future:
        future = self.executor.submit(fn, *args, **kwargs)
        future.add_done_callback(self.completed_cb)
        self.total += 1
        self.jobs.add(future)
        self._update_progress()
        return future

    def wait(self):
        while not bool(self):
            time.sleep(0.05)

    def _update_progress(self):
        if config.PROGRESSBAR_DISABLED:
            return

        if self.q is not None:
            total = self.total + self.q.qsize()
        else:
            total = self.total

        self.pg.reset(total)
        self.pg.n = self.completed
        self.pg.refresh()
