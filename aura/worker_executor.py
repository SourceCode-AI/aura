import queue
import multiprocessing
from multiprocessing.pool import ThreadPool
from functools import partial
import time

from tqdm import tqdm


class Wait:
    __slots__ = ()


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


class ProgressBar(tqdm):  # TODO: move to different location
    def __init__(self, *, queue, **kwargs):
        super(ProgressBar, self).__init__(**kwargs)
        queue.put = partial(self.put_queue, progress=self, func=queue.put)
        self._track_queue = queue
        self._queue_total = 0

    def _update_queue(self):
        self.reset(self._queue_total)
        self.n = self._queue_total - self._track_queue.qsize()
        self.refresh()

    @staticmethod
    def put_queue(*args, progress, func, **kwargs):
        progress._queue_total += 1
        progress._update_queue()
        return func(*args, **kwargs)
