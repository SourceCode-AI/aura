import time
from concurrent import futures
from typing import Optional

from .. import config
from ..exceptions import PluginDisabled

try:
    from ..output import postgres
    import psycopg2
except (PluginDisabled):
    postgres = None
    psycopg2 = None


logger = config.get_logger(__name__)


class ServerWorker:
    def __init__(self, pg_uri: str, worker_func, max_workers=1):
        if postgres is None:
            raise PluginDisabled("Postgres plugin is not enabled in aura, check the documentation")

        self.pg_uri = pg_uri
        self.conn = psycopg2.connect(**postgres.connection_opts_from_uri(pg_uri))
        self.executor = futures.ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="aura_server_worker")
        self.tasks = {}
        self.worker_func = worker_func
        self.max_workers = max_workers

    def fetch_task(self) -> Optional[dict]:
        with self.conn.cursor() as cur:
            cur.execute("""
            UPDATE pending_scans
            SET status=1, updated=(now() at time zone 'utc')
            WHERE scan_id = (
                    SELECT scan_id
                    FROM pending_scans
                    WHERE status = 0
                    ORDER BY updated DESC
                    LIMIT 1
                    FOR UPDATE SKIP LOCKED
                )
            RETURNING scan_id, uri, reference;
            """)
            row = cur.fetchone()
            if not row:
                return
            else:
                self.conn.commit()
                return {"scan_id": row[0], "uri": row[1], "reference": row[2]}

    def loop(self):
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
                    task_future = self.executor.submit(self.worker_func, task_data)
                    self.tasks[task_future] = task_data["scan_id"]
        finally:
            self.wait_for_tasks(when=futures.ALL_COMPLETED)

    def wait_for_tasks(self, when=futures.FIRST_COMPLETED):
        done, _ = futures.wait(self.tasks, return_when=when)

        with self.conn.cursor() as cur:
            for f in done:
                if not (scan_id:=self.tasks.get(f)):
                    continue

                cur.execute("UPDATE pending_scans SET status=2 WHERE scan_id=%s", (scan_id,))
                self.conn.commit()
                del self.tasks[f]