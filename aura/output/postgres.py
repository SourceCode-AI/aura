import urllib.parse
import uuid
import logging
from abc import ABCMeta, abstractmethod
from dataclasses import dataclass
from typing import Sequence, Union
from pathlib import Path

import packaging.utils

from .base import ScanOutputBase
from ..scan_data import ScanData
from ..json_proxy import dumps
from ..exceptions import InvalidOutput, PluginDisabled

try:
    import psycopg2
    import psycopg2.extras
    from psycopg2.errors import UniqueViolation, DuplicateObject
except ImportError:
    raise PluginDisabled("`psycopg2` library is not installed")

logger = logging.getLogger(__name__)
psycopg2.extras.register_uuid()


@dataclass
class PGBase(metaclass=ABCMeta):
    def __enter__(self):
        if not self.uri:
            raise InvalidOutput("You must use full URI output specification for the postgres output format")
        elif self.output_location == "-":
            raise InvalidOutput("Postgres format can't output to the stdout")

        self.out_fd = psycopg2.connect(**connection_opts_from_uri(self.uri))
        self._initialize_db()
        return self.out_fd

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is None:
            self.out_fd.commit()
        else:
            self.out_fd.rollback()

        self.out_fd.close()
        self.out_fd = None

    @abstractmethod
    def _create_tables(self):
        ...

    def _initialize_db(self):
        # self._create_tables()
        pass

    @classmethod
    def protocol(cls) -> str:
        return "postgres"


@dataclass
class PostgresScanOutput(PGBase, ScanOutputBase):
    def _create_tables(self):
        SCAN_SCHEMA = """
            CREATE TABLE IF NOT EXISTS scans (
                id BIGSERIAL PRIMARY KEY,
                input VARCHAR(255) NOT NULL,
                reference uuid UNIQUE NOT NULL,
                scan_data jsonb compression LZ4 NOT NULL,
                metadata jsonb compression LZ4 NOT NULL,
                score int DEFAULT 0 NOT NULL,
                created timestamp without time zone default (NOW() at time zone 'utc'),
                package varchar(255),
                package_release varchar(64),
                pkg_filename varchar(255)
            )
        """

        LOCATION_SCHEMA = """
            CREATE TABLE IF NOT EXISTS locations (
                id BIGSERIAL PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                scan_id BIGINT NOT NULL,
                metadata jsonb compression LZ4 NOT NULL,
                idx_path tsvector,
                FOREIGN KEY (scan_id) REFERENCES scans(id),
                UNIQUE (name, scan_id)
            )
        """

        DETECTION_SCHEMA = """
            CREATE TABLE IF NOT EXISTS detections (
                id BIGSERIAL PRIMARY KEY,
                signature BIGINT NOT NULL,
                score INTEGER DEFAULT 0,
                type VARCHAR(64) NOT NULL,
                data jsonb compression LZ4 NOT NULL,
                scan_id BIGINT NOT NULL,
                location_id BIGINT NOT NULL,
                idx_vector tsvector,
                FOREIGN KEY (location_id) REFERENCES locations(id),
                UNIQUE (location_id, signature)
            )
        """

        TAGS_SCHEMA = """
            CREATE TABLE IF NOT EXISTS tags (
                id BIGSERIAL PRIMARY KEY,
                tag varchar(64) UNIQUE NOT NULL
            )
        """

        SCAN_TAGS_SCHEMA = """
            CREATE TABLE IF NOT EXISTS scan_tags (
                scan_id bigint not null,
                tag_id bigint not null,
                FOREIGN KEY (scan_id) REFERENCES scans(id),
                FOREIGN KEY (tag_id) REFERENCES tags(id),
                PRIMARY KEY (scan_id, tag_id)
            )
        """

        DETECTIONS_TAGS_SCHEMA = """
            CREATE TABLE IF NOT EXISTS detection_tags (
                detection_id bigint not null,
                tag_id bigint not null,
                FOREIGN KEY (detection_id) REFERENCES detections(id),
                FOREIGN KEY (tag_id) REFERENCES tags(id),
                PRIMARY KEY (detection_id, tag_id)
            )
        """

        DETECTION_FUNCS = (
            "CREATE INDEX IF NOT EXISTS tags ON detections USING GIN ((data->'tags') jsonb_path_ops)",

            # Search index for detections (text based)
            """
            CREATE OR REPLACE FUNCTION index_detection()
            RETURNS TRIGGER
            AS $$
            BEGIN
                NEW.idx_vector = to_tsvector('english', COALESCE ((NEW.data->'message')::text, '') || ' ' || COALESCE ((NEW.data->'line')::text, ''));
                RETURN NEW;
            END $$ LANGUAGE plpgsql;
            """,
            """
            CREATE TRIGGER  set_detection_index
            BEFORE INSERT OR UPDATE ON detections
            FOR EACH ROW
                EXECUTE PROCEDURE index_detection();
            """,

            # Search index for file paths
            """
            CREATE OR REPLACE FUNCTION index_filepath()
            RETURNS TRIGGER
            AS $$
            BEGIN
                NEW.idx_path = to_tsvector('english', REPLACE(REPLACE(NEW.name, '$', ' '), '/', ' '));
                RETURN NEW;
            END $$ LANGUAGE plpgsql;
            """,
            """
            CREATE TRIGGER set_filepath_index
            BEFORE INSERT OR UPDATE ON locations
            FOR EACH ROW
                EXECUTE PROCEDURE index_filepath();
            """,

            "CREATE INDEX detections_text_idx ON detections USING GIN (idx_vector)",
            "CREATE INDEX filepaths_text_idx ON locations USING GIN (idx_path)",

            """
            create table pending_scans (
                scan_id bigserial,
                created timestamp without time zone default (now() at time zone 'utc'),
                updated timestamp without time zone default (now() at time zone 'utc'),
                status smallint DEFAULT 0,
                uri VARCHAR(255),
                reference uuid
            );
            """,
        )

        with self.out_fd.cursor() as cur:
            cur.execute(SCAN_SCHEMA)
            cur.execute(LOCATION_SCHEMA)
            cur.execute(DETECTION_SCHEMA)
            cur.execute(TAGS_SCHEMA)
            cur.execute(SCAN_TAGS_SCHEMA)
            cur.execute(DETECTIONS_TAGS_SCHEMA)

            for idx in DETECTION_FUNCS:
                try:
                    cur.execute(idx)
                except DuplicateObject:
                    pass

        self.out_fd.commit()

    def output(self, scans: Sequence[ScanData]):
        with self.out_fd.cursor() as cur:
            tag_ids = {}

            for scan in scans:
                location_ids = {}
                if not (ref_id:=scan.metadata.get("reference")):
                    ref_id = str(uuid.uuid4())

                scan_data = scan.as_dict()
                scan_metadata = scan_data.pop("metadata", {})

                cur.execute("""
                    INSERT INTO scans
                    (input, reference, scan_data, metadata, score, package, package_release, pkg_filename)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING id
                """, (
                    scan_metadata["name"],
                    ref_id,
                    # TODO: add test for the \u0000
                    dumps(scan_data).replace("\\u0000", "").replace("\u0000", ""),  # This unicode character is not valid in postgres json column data
                    dumps(scan_metadata).replace("\\u0000", "").replace("\u0000", ""),
                    scan_data.get("score", 0),
                    scan_metadata.get("package_name"),
                    scan_metadata.get("package_release"),
                    scan_metadata.get("package_file")
                ))

                scan_id = cur.fetchone()[0]
                all_tags = set()

                for detection in scan.hits:
                    norm_path = detection.location

                    if norm_path in location_ids:
                        location_id = location_ids[norm_path]
                    else:
                        try:
                            cur.execute("""
                                INSERT INTO locations(name, scan_id, metadata) VALUES (%s, %s, %s) RETURNING id
                            """, (
                                norm_path,
                                scan_id,
                                dumps(detection._metadata).replace("\\u0000", "").replace("\u0000", "")
                            ))

                            location_id = cur.fetchone()[0]
                            location_ids[norm_path] = location_id
                        except UniqueViolation:
                            pass  # TODO load location id from db

                    # TODO handle unique violation
                    cur.execute("""
                        INSERT INTO detections
                        (signature, score, type, data, scan_id, location_id)
                        VALUES (%s, %s, %s, %s, %s, %s)
                        RETURNING id
                    """, (
                        detection.int_signature,
                        detection.score,
                        detection.slug,
                        dumps(detection).replace("\\u0000", "").replace("\u0000", ""),
                        scan_id,
                        location_id
                    ))
                    detection_id = cur.fetchone()

                    for tag in detection.tags:
                        if tag not in tag_ids:
                            cur.execute("""
                                WITH ins AS (
                                    INSERT INTO tags(tag)
                                    VALUES(%s)
                                    ON CONFLICT (tag) DO UPDATE
                                    SET tag=NULL
                                    WHERE FALSE -- never executes but locks the row
                                    RETURNING id
                                )
                                SELECT id FROM ins
                                UNION ALL
                                SELECT id FROM tags
                                WHERE tag=%s
                                LIMIT 1
                            """, (tag, tag))  # TODO use the while exec here
                            tag_ids[tag] = cur.fetchone()

                        cur.execute("""
                            INSERT INTO detection_tags
                            VALUES (%s, %s)
                        """, (detection_id, tag_ids[tag]))

                    all_tags |= set(detection.tags)

                for tag in all_tags:
                    cur.execute("""
                        INSERT INTO scan_tags
                        VALUES (%s, %s)
                    """, (scan_id, tag_ids[tag]))




def connection_opts_from_uri(uri: Union[urllib.parse.ParseResult, str]) -> dict:
    if type(uri) == str:
        uri = urllib.parse.urlparse(uri)

    conn_options = {
        "host": uri.hostname,
        "port": (uri.port or 5432)
    }

    if (dbname := uri.path.lstrip("/")):
        if "/" in dbname:
            raise InvalidOutput(f"Database name `{dbname}` can't contain `/` slashes")
    else:
        dbname = "aura"

    conn_options["dbname"] = dbname

    if uri.username:
        conn_options["user"] = uri.username

    if uri.password:
        conn_options["password"] = uri.password

    return conn_options


def parse_bandersnatch_log(log_path: Path):
    for line in log_path.read_text().splitlines():
        fname = Path(line).name

        if fname.endswith(".whl"):
            pkg_name, ver, *_ = packaging.utils.parse_wheel_filename(fname)
            pkg_name = packaging.utils.canonicalize_name(pkg_name)
            yield f"pypi://{pkg_name}?filename={fname}&version={str(ver)}"
        elif fname.endswith(".tar.gz"):
            pkg_name, ver = packaging.utils.parse_sdist_filename(fname)
            pkg_name = packaging.utils.canonicalize_name(pkg_name)
            yield f"pypi://{pkg_name}?filename={fname}&version={str(ver)}"
        elif fname.endswith(".egg"):
            pkg_name, ver, *_ = fname.split("-")
            pkg_name = packaging.utils.canonicalize_name(pkg_name)
            yield f"pypi://{pkg_name}?filename={fname}&version={str(ver)}"


def ingest_bandersnatch_log(log_path: str, pg_uri: str):
    with psycopg2.connect(**connection_opts_from_uri(pg_uri)) as connection:
        with connection.cursor() as cur:
            for uri in parse_bandersnatch_log(Path(log_path)):
                logger.info(f"Inserting URI into the scan queue: `{uri}`")
                cur.execute("INSERT INTO pending_scans (uri, reference) VALUES (%s, %s)", (uri, str(uuid.uuid4())))


def exec_while(cursor, fetch_func, stmt, vars):
    row = None
    while not row is None:
        cursor.execute(stmt, vars)
        row = fetch_func()

    return row
