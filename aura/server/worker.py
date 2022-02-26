import time
import multiprocessing as mp
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
        self.executor = futures.ProcessPoolExecutor(
            max_workers=max_workers,
            mp_context=mp.get_context("spawn")
        )
        self.tasks = {}
        self.max_workers = max_workers

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
                return
            else:
                self.db_session.commit()
                return {"scan_id": row[0], "uri": row[1], "reference": str(row[2]), "format": self.pg_uri}

    def loop(self, worker_func=None):
        if not worker_func:
            worker_func = ServerWorker.default_worker_func

        try:
            while True:
                if len(self.tasks) >= self.max_workers:
                    self.wait_for_tasks()

                task_data = self.fetch_task()

                if task_data is None:
                    logger.info("Nothing to do")
                    time.sleep(1)
                    continue
                else:
                    task_future = self.executor.submit(worker_func, task_data)
                    self.tasks[task_future] = task_data["scan_id"]
        finally:
            self.wait_for_tasks(when=futures.ALL_COMPLETED)

    def wait_for_tasks(self, when=futures.FIRST_COMPLETED):
        done, _ = futures.wait(self.tasks, return_when=when)

        with self.db_session():
            for f in done:
                f.result()

                if not (scan_id:=self.tasks.get(f)):
                    continue

                self.db_session.execute(postgres.sa.text("""
                    UPDATE pending_scans
                    SET status=2
                    WHERE queue_id=:scan_id
                """), {"scan_id": scan_id})

                self.db_session.commit()
                del self.tasks[f]
