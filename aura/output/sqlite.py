import json
import os
import sqlite3
from pathlib import Path
from typing import List

from .base import AuraOutput
from ..analyzers.rules import Rule
from ..utils import json_encoder
from ..exceptions import MinimumScoreNotReached


class SQLiteOutput(AuraOutput):
    def __init__(self, metadata):
        super(SQLiteOutput, self).__init__(metadata=metadata)
        self.db = None
        self.path = metadata.get("output_path")
        if self.path is None:
            raise ValueError("Argument --output-path is required with sqlite output")

    def __create_tables(self):
        INPUT_SCHEMA = """
            CREATE TABLE IF NOT EXISTS inputs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                input VARCHAR(255) UNIQUE NOT NULL,
                location VARCHAR(255),
                metadata TEXT
            )
        """

        HIT_SCHEMA = """
            CREATE TABLE IF NOT EXISTS hits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                signature VARCHAR(255) UNIQUE,
                score INTEGER DEFAULT 0,
                type VARCHAR(64),
                data TEXT NOT NULL,
                input INTEGER,
                FOREIGN KEY (input) REFERENCES input(id)
            )
        """

        FILES_SCHEMA = """
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER UNIQUE,
                data BLOB,
                FOREIGN KEY (id) REFERENCES input(id)
            )
        """

        with self.db:
            self.db.execute(INPUT_SCHEMA)
            self.db.execute(HIT_SCHEMA)
            self.db.execute(FILES_SCHEMA)

    def __initialize_db(self):
        self.db = sqlite3.connect(self.path)
        self.db.enable_load_extension(True)
        opts = [x[0] for x in self.db.execute("PRAGMA compile_options").fetchall()]
        if "ENABLE_JSON1" not in opts:
            raise EnvironmentError(
                f"SQLite doesn't have support for JSON1, compile opts: {', '.join(opts)}"
            )

        self.__create_tables()

    def output(self, hits: List[Rule]):
        try:
            self.filtered(hits)
        except MinimumScoreNotReached:
            return

        if self.db is None:
            self.__initialize_db()

        cur = self.db.cursor()

        try:
            input_ids = {}
            stored_files = set()

            for h in hits:
                norm_path = h.location
                if norm_path not in input_ids:
                    try:
                        cur.execute(
                            """
                            INSERT INTO inputs (input, location, metadata)
                            VALUES (?, ?, ?)
                        """,
                            [
                                os.fspath(h._metadata["path"]),
                                h.location,
                                json.dumps(h._metadata, default=json_encoder),
                            ],
                        )
                        input_id = cur.lastrowid
                    except sqlite3.IntegrityError:
                        input_id = cur.execute(
                            "SELECT id FROM inputs WHERE location=?",
                            (h.location,)
                        ).fetchone()[0]
                    finally:
                        input_ids[norm_path] = input_id
                else:
                    input_id = input_ids[norm_path]

                full_path = Path(h._metadata["path"])

                if h.location not in stored_files:
                    with full_path.open("rb") as fd:
                        content = fd.read()
                    cur.execute(
                        "INSERT OR IGNORE INTO files (id, data) VALUES (?, ?)",
                        (input_id, sqlite3.Binary(content)),
                    )
                    stored_files.add(h.location)

                hit_data = h._asdict()

                cur.execute(
                    "INSERT OR IGNORE INTO hits (signature, score, type, data, input) VALUES (?,?,?,?,?)",
                    (
                        h.signature,
                        h.score,
                        hit_data["type"],
                        json.dumps(hit_data, default=json_encoder),
                        input_id,
                    ),
                )

        except:
            self.db.rollback()
            raise
        else:
            self.db.commit()

    def output_diff(self, diffs):
        # TODO
        raise NotImplementedError("todo")
