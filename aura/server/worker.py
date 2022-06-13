import time
import multiprocessing as mp
from multiprocessing.pool import Pool
from functools import partial
from concurrent import futures
from typing import Optional

from .. import config
from ..output.filtering import FilterConfiguration
from ..commands import scan_uri
from ..exceptions import PluginDisabled

try:
    from ..output import postgres
    import psycopg2
except (PluginDisabled):
    postgres = None
    psycopg2 = None


CLEANUP = object()
logger = config.get_logger(__name__)
try:
    mp.set_start_method("spawn")
except RuntimeError:
    pass


class ServerWorker:
    def __init__(self, pg_uri: str, max_workers=1):
        if postgres is None:
            raise PluginDisabled("Postgres plugin is not enabled in aura, check the documentation")

        self.pg_uri = pg_uri
        self.db_session = postgres.get_session(pg_uri)

        self.pool = Pool(
            processes=1,
            maxtasksperchild=3,
            context=mp.get_context("spawn")
        )

        self.tasks = {}
        self.max_workers = max_workers
        self.max_tasks_per_process = 2

    @staticmethod
    def default_worker_func(task_data: dict) -> None:
        meta = {"format": task_data["format"]}
        if not (filter_cfg := task_data.get("filter_cfg")):
            filter_cfg = FilterConfiguration()

        if (ref:=task_data.get("reference")):
            meta["reference"] = ref

        scan_uri(
            task_data["uri"],
            metadata=meta,
            filter_cfg=filter_cfg
        )

    @staticmethod
    def cleanup(*args) -> None:
        import gc

        from ..uri_handlers import base
        from ..utils import KeepRefs

        gc.collect()
        KeepRefs.cleanup()
        base.cleanup_locations()


    def fetch_task(self) -> Optional[dict]:
        with self.db_session.begin():
            row = self.db_session.execute(postgres.sa.text("""
            UPDATE pending_scans
            SET status=1, updated=(now() at time zone 'utc')
            WHERE queue_id = (
                    SELECT queue_id
                    FROM pending_scans
                    WHERE status = 0
                    ORDER BY updated DESC
                    LIMIT 1
                    FOR UPDATE SKIP LOCKED
                )
            RETURNING queue_id, uri, reference;
            """)).fetchone()
            if not row:
                return None
            else:
                self.db_session.commit()
                return {"scan_id": row[0], "uri": row[1], "reference": str(row[2]), "format": self.pg_uri}

    def loop(self, worker_func=None):
        if not worker_func:
            worker_func = ServerWorker.default_worker_func

        try:
            while True:
                if len(self.tasks) >= self.max_workers:
                    time.sleep(0.1)
                    continue

                task_data = self.fetch_task()

                if task_data is None:
                    logger.info("Nothing to do")
                    time.sleep(1)
                    continue
                else:
                    callback = partial(self.handle_result, task_data["scan_id"])

                    async_res = self.pool.apply_async(
                        func=worker_func,
                        args=(task_data,),
                        callback=lambda result: callback(),
                        error_callback=lambda exc: callback(exc=exc),
                    )
                    self.tasks[async_res] = task_data["scan_id"]
        finally:
            self.pool.close()
            self.pool.join()

    def cleanup_tasks(self):
        for t in tuple(self.tasks.keys()):
            if t.ready():
                self.handle_result(task_or_id=t)

    def handle_result(self, task_or_id, exc=None, status=2):
        task: mp.pool.AsyncResult

        if isinstance(task_or_id, int):
            for t, scan_id in self.tasks.items():
                if scan_id == task_or_id:
                    task = t
                    break
                return
        else:
            task = task_or_id

        try:
            with self.db_session():
                if not (scan_id := self.tasks.get(task)):
                    return

                if exc:
                    status = 3

                self.db_session.execute(postgres.sa.text("""
                                    UPDATE pending_scans
                                    SET status=:status
                                    WHERE queue_id=:scan_id
                                """), {"scan_id": scan_id, "status": status})

                self.db_session.commit()
                if exc:
                    raise exc
        finally:
            try:
                del self.tasks[task]
            except KeyError:
                pass
