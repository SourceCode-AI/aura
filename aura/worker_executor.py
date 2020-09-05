import queue
import multiprocessing
import time
from concurrent import futures
from typing import Optional

from . import config


Wait = object()


class AuraExecutor:
    def __init__(self, fork: Optional[bool]=None):
        if fork is None:
            self.fork = config.CFG["aura"].get("async", True)
        else:
            self.fork = fork

        if self.fork:
            self.executor = futures.ProcessPoolExecutor()
        else:
            self.executor = futures.ThreadPoolExecutor()

        self.queue = []
        self.total = 0
        self.completed = 0


class MultiprocessingExecutor:
    _instance = None

    def __init__(self):
        self.manager = multiprocessing.Manager()
        self.worker_pool = self.get_pool()
        self.jobs = []

    def get_pool(self):
        return multiprocessing.Pool(
            #processes=processes,
            maxtasksperchild=1
        )

    def join(self):
        self.worker_pool.join()

    def close(self):
        self.worker_pool.close()

    def wait(self):
        while any((not x.ready()) for x in self.jobs):
            time.sleep(0.05)

    def create_queue(self):
        return self.manager.Queue()

    def apply_async(self, func, args=None, kwds=None):
        job = self.worker_pool.apply_async(
            func=func,
            args=(args or ()),
            kwds=(kwds or {}),
            error_callback=self.log_error
        )
        self.jobs.append(job)
        return job

    def log_error(self, traceback):
        raise traceback


class LocalExecutor(MultiprocessingExecutor):
    def __init__(self):
        self.jobs = []

    def join(self):
        pass

    def close(self):
        pass

    def apply_async(self, func, args=None, kwds=None):
        if args is None:
            args = ()
        if kwds is None:
            kwds = {}

        try:
            return func(*args, **kwds)
        except Exception as exc:
            self.log_error(exc)

    def wait(self):
        pass

    def create_queue(self):
        return queue.Queue()
