import json
import sqlite3
from dataclasses import dataclass
from typing import List, Any
from abc import ABCMeta, abstractmethod

from .base import ScanOutputBase, DiffOutputBase
from ..analyzers.detections import Detection
from ..utils import json_encoder
from ..exceptions import InvalidOutput, PluginDisabled


def check_sqlite_support():
    db = sqlite3.connect(":memory:")
    try:
        db.enable_load_extension(True)
    except AttributeError:
        raise PluginDisabled(
            "You SQLite installation does not support loading extensions"
        )

    opts = [x[0] for x in db.execute("PRAGMA compile_options").fetchall()]
    if "ENABLE_JSON1" not in opts:
        raise PluginDisabled(
            f"Your SQLite installation doesn't have support for JSON1, compile opts: {', '.join(opts)}"
        )


@dataclass()
class DiffBase(metaclass=ABCMeta):
    _db: Any = None

    def __enter__(self):
        if self.output_location == "-":
            raise InvalidOutput("SQLite format can't output to stdout")

        self._db = sqlite3.connect(self.output_location)
        self._initialize_db()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._db.close()

    @abstractmethod
    def _create_tables(self):
        ...

    def _initialize_db(self):
        self._db.enable_load_extension(True)
        opts = [x[0] for x in self._db.execute("PRAGMA compile_options").fetchall()]
        if "ENABLE_JSON1" not in opts:
            raise EnvironmentError(
                f"SQLite doesn't have support for JSON1, compile opts: {', '.join(opts)}"
            )

        self._create_tables()

    @classmethod
    def protocol(cls) -> str:
        return "sqlite"


@dataclass()
class SQLiteScanOutput(DiffBase, ScanOutputBase):
    def _create_tables(self):
        INPUT_SCHEMA = """
            CREATE TABLE IF NOT EXISTS inputs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                input VARCHAR(255) UNIQUE NOT NULL,
                metadata json
            )
        """

        LOCATION_SCHEMA = """
            CREATE TABLE IF NOT EXISTS locations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name VARCHAR(255) UNIQUE,
                local_path VARCHAR(255) NOT NULL,
                input INTEGER,
                metadata json,
                FOREIGN KEY (input) REFERENCES inputs(id)
            )
        """

        DETECTION_SCHEMA = """
            CREATE TABLE IF NOT EXISTS detections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                signature VARCHAR(255) UNIQUE,
                score INTEGER DEFAULT 0,
                type VARCHAR(64),
                data json NOT NULL,
                location INTEGER,
                FOREIGN KEY (location) REFERENCES locations(id)
            )
        """


        with self._db:
            self._db.execute(INPUT_SCHEMA)
            self._db.execute(LOCATION_SCHEMA)
            self._db.execute(DETECTION_SCHEMA)

    def output(self, hits: List[Detection], scan_metadata: dict):
        cur = self._db.cursor()
        try:
            location_ids = {}
            cur.execute("""
                INSERT INTO inputs (input, metadata) VALUES (?,?)
            """, [
                scan_metadata["name"],
                json.dumps(scan_metadata, default=json_encoder)
            ])

            input_id = cur.lastrowid

            for h in hits:
                norm_path = h.location
                location_meta = h._metadata
                full_path = str(location_meta["path"])
                detection = h._asdict()

                if norm_path in location_ids:
                    location_id = location_ids[norm_path]
                else:
                    try:
                        cur.execute("""
                            INSERT INTO locations(name, local_path, input, metadata)
                            VALUES (?,?,?,?)
                        """, [
                            norm_path,
                            full_path,
                            input_id,
                            json.dumps(location_meta, default=json_encoder)
                        ])
                        location_id = cur.lastrowid
                    except sqlite3.IntegrityError:
                        location_id = cur.execute(
                            "SELECT id FROM locations WHERE name=?", [norm_path]
                        ).fetchone()[0]

                    location_ids[norm_path] = location_id

                cur.execute("""
                    INSERT OR IGNORE into DETECTIONS (signature, score, type, data, location)
                    VALUES (?, ?, ?, ?, ?)
                """, [
                    h.signature,
                    h.score,
                    h.name,
                    json.dumps(detection, default=json_encoder),
                    location_id
                ])
        except:
            self._db.rollback()
            raise
        else:
            self._db.commit()


@dataclass()
class SQLiteDiffOutput(DiffBase, DiffOutputBase):
    def _create_tables(self):
        DIFF_SCHEMA = """
            CREATE TABLE IF NOT EXISTS diffs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                operation CHARACTER(1) CHECK( operation in ("A", "R", "M", "D")),
                a_ref VARCHAR(255),
                b_ref VARCHAR(255),
                a_size UNSIGNED INTEGER,
                b_size UNSIGNED_INTEGER,
                a_mime VARCHAR(64),
                b_mime VARCHAR(64),
                a_md5 CHARACTER(32),
                b_md5 CHARACTER(32),
                similarity DOUBLE
            )
        """

        PATCH_SCHEMA = """
            CREATE TABLE IF NOT EXISTS patches (
                diff INTEGER UNIQUE NOT NULL,
                patch TEXT NOT NULL,
                FOREIGN KEY (diff) REFERENCES diffs(id)
            )
        """

        DETECTION_SCHEMA = """
            CREATE TABLE IF NOT EXISTS detections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                is_new BOOL,
                is_removed BOOL,
                signature VARCHAR(255) NOT NULL,
                score UNSIGNED INTEGER DEFAULT 0,
                type VARCHAR(64) NOT NULL,
                data json NOT NULL,
                diff INTEGER NOT NULL,
                FOREIGN KEY (diff) REFERENCES diffs(id)
                CHECK ((is_new AND NOT is_removed) OR (is_removed AND NOT is_new))
            )
        """

        with self._db:
            self._db.execute(DIFF_SCHEMA)
            self._db.execute(PATCH_SCHEMA)
            self._db.execute(DETECTION_SCHEMA)

    def __insert_detection(self, cur, diff_id, detection, status):
        assert status in ("new", "removed")

        cur.execute("""
            INSERT into DETECTIONS (
                is_new,
                is_removed,
                signature,
                score,
                type,
                data,
                diff
            ) VALUES (?,?,?,?,?,?,?)
        """, [
            (status == "new"),
            (status == "removed"),
            detection.signature,
            detection.score,
            detection.name,
            json.dumps(detection._asdict(), default=json_encoder),
            diff_id
        ])

    def output_diff(self, diffs_analyzer):
        cur = self._db.cursor()
        try:
            for d in self.filtered(diffs_analyzer.diffs):
                data = d.as_dict()


                cur.execute("""
                    INSERT INTO diffs (
                        operation,
                        a_ref,
                        b_ref,
                        a_size,
                        b_size,
                        a_mime,
                        b_mime,
                        a_md5,
                        b_md5,
                        similarity
                    ) VALUES (?,?,?,?,?,?,?,?,?,?)
                """, [
                    data["operation"],
                    data.get("a_ref"),
                    data.get("b_ref"),
                    data.get("a_size"),
                    data.get("b_size"),
                    data.get("a_mime"),
                    data.get("b_mime"),
                    data.get("a_md5"),
                    data.get("b_md5"),
                    data["similarity"]
                ])

                diff_id = cur.lastrowid

                if d.diff and self.patch:
                    cur.execute("INSERT INTO patches (diff, patch) VALUES (?,?)", [diff_id, d.diff])

                if d.new_detections:
                    for detection in d.new_detections:
                        self.__insert_detection(
                            cur=cur,
                            diff_id = diff_id,
                            detection=detection,
                            status="new"
                        )

                if d.removed_detections:
                    for detection in d.removed_detections:
                        self.__insert_detection(
                            cur=cur,
                            diff_id=diff_id,
                            detection=detection,
                            status="removed"
                        )

        except:
            self._db.rollback()
            raise
        else:
            self._db.commit()


check_sqlite_support()
