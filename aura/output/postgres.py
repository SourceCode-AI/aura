import urllib.parse
import uuid
import logging
import datetime
from abc import ABCMeta, abstractmethod
from dataclasses import dataclass
from typing import Sequence, Union
from pathlib import Path

import packaging.utils

from .base import ScanOutputBase
from ..scan_data import ScanData
from ..json_proxy import dumps, loads
from ..exceptions import InvalidOutput, PluginDisabled

try:
    import sqlalchemy as sa
    from sqlalchemy import event
    from sqlalchemy.dialects.postgresql import TSVECTOR, JSONB, UUID
    from sqlalchemy.orm import scoped_session, sessionmaker, relationship
    from sqlalchemy.ext.declarative import declarative_base
    from sqlalchemy.ext.hybrid import hybrid_property
    from sqlalchemy.types import TypeEngine
except ImportError:
    raise PluginDisabled("`SQLAlchemy` library is not installed")


logger = logging.getLogger(__name__)
Base = declarative_base()


class ScanModel(Base):
    __tablename__ = "scans"

    id = sa.Column(sa.BIGINT, primary_key=True)
    input = sa.Column(sa.VARCHAR(255), nullable=False)
    reference = sa.Column(UUID, nullable=False, unique=True)
    scan_data = sa.Column(JSONB, nullable=False)
    metadata_col = sa.Column("metadata", JSONB, nullable=False)
    scan_score = sa.Column("score", sa.INTEGER, nullable=False, default=0)
    created = sa.Column(sa.TIMESTAMP, default=datetime.datetime.utcnow)
    package = sa.Column(sa.VARCHAR(255))
    package_release = sa.Column(sa.VARCHAR(64))
    pkg_filename = sa.Column(sa.VARCHAR(255))

    detections = relationship("DetectionModel", backref="scan")

    @hybrid_property
    def scan_id(self) -> int:
        return self.id


class DetectionModel(Base):
    __tablename__ = "detections"

    id = sa.Column(sa.BIGINT, primary_key=True)
    signature = sa.Column(sa.BIGINT, nullable=False)
    score = sa.Column(sa.INTEGER, default=0, nullable=False)
    slug = sa.Column(sa.VARCHAR(64), nullable=False)
    data = sa.Column(JSONB, nullable=False)
    scan_id = sa.Column(sa.BIGINT, sa.ForeignKey("scans.id"), nullable=False)
    location_id = sa.Column(sa.BIGINT, nullable=False)
    idx_vector = sa.Column(TSVECTOR, nullable=True)

    __table_args__ = (
        sa.UniqueConstraint("location_id", "signature"),
    )


class LocationModel(Base):
    __tablename__ = "locations"

    id = sa.Column(sa.BIGINT, primary_key=True)
    name = sa.Column(sa.VARCHAR(255), nullable=False)
    scan_id = sa.Column(sa.BIGINT, sa.ForeignKey("scans.id"), nullable=False)
    metadata_col = sa.Column("metadata", JSONB, nullable=False)
    idx_path = sa.Column(TSVECTOR, nullable=True)

    __table_args__ = (
        sa.UniqueConstraint("name", "scan_id"),
    )


class TagsModel(Base):
    __tablename__ = "tags"

    id = sa.Column(sa.BIGINT, primary_key=True)
    tag = sa.Column(sa.VARCHAR(64), unique=True, nullable=False)

    scans = relationship(
        "ScanModel", secondary="scan_tags",
        primaryjoin= "TagsModel.id == ScanTagsModel.tag_id",
        secondaryjoin="ScanTagsModel.scan_id == ScanModel.id",
        backref="tags"
    )

    detections = relationship(
        "DetectionModel", secondary="detection_tags",
        primaryjoin="TagsModel.id == DetectionTagsModel.tag_id",
        secondaryjoin="DetectionTagsModel.detection_id == DetectionModel.id",
    )


class ScanTagsModel(Base):
    __tablename__ = "scan_tags"

    scan_id = sa.Column(sa.BIGINT, sa.ForeignKey("scans.id"), nullable=False, primary_key=True)
    tag_id = sa.Column(sa.BIGINT, sa.ForeignKey("tags.id"), nullable=False, primary_key=True)


class DetectionTagsModel(Base):
    __tablename__ = "detection_tags"

    detection_id = sa.Column(sa.BIGINT, sa.ForeignKey("detections.id"), nullable=False, primary_key=True)
    tag_id = sa.Column(sa.BIGINT, sa.ForeignKey("tags.id"), nullable=False, primary_key=True)


class BehavioralIndicator(Base):
    __tablename__ = "indicators"

    id = sa.Column(sa.BIGINT, primary_key=True)
    slug = sa.Column(sa.VARCHAR(64), nullable=False, unique=True)
    name = sa.Column(sa.VARCHAR(255), nullable=False, unique=True)
    description = sa.Column(sa.TEXT, nullable=False)

    @hybrid_property
    def indicator_id(self) -> int:
        return self.id


class ScanIndicators(Base):
    __tablename__ = "scan_indicators"

    scan_id = sa.Column(sa.BIGINT, sa.ForeignKey("scans.id"), nullable=False, primary_key=True)
    indicator_id = sa.Column(sa.BIGINT, sa.ForeignKey("indicators.id"), nullable=False, primary_key=True)


class PendingScans(Base):
    __tablename__ = "pending_scans"

    queue_id = sa.Column(sa.BIGINT, primary_key=True)
    created = sa.Column(sa.TIMESTAMP, default=datetime.datetime.utcnow, nullable=False)
    updated = sa.Column(sa.TIMESTAMP, default=datetime.datetime.utcnow, nullable=False)
    status = sa.Column(sa.SMALLINT, default=0, nullable=False)
    uri = sa.Column(sa.VARCHAR(255), nullable=False)
    reference = sa.Column(UUID, default=lambda: str(uuid.uuid4()))


sa.event.listen(
    DetectionModel.__table__,
    "after_create",
    sa.DDL("""
        CREATE OR REPLACE FUNCTION index_detection()
        RETURNS TRIGGER
        AS $$
        BEGIN
            NEW.idx_vector = to_tsvector('english', COALESCE ((NEW.data->'message')::text, '') || ' ' || COALESCE ((NEW.data->'line')::text, ''));
            RETURN NEW;
        END $$ LANGUAGE plpgsql;
    """)
)

sa.event.listen(
    DetectionModel.__table__,
    "after_create",
    sa.DDL("""
        CREATE TRIGGER  set_detection_index
        BEFORE INSERT OR UPDATE ON detections
        FOR EACH ROW
            EXECUTE PROCEDURE index_detection();
    """)
)

sa.event.listen(
    DetectionModel.__table__,
    "after_create",
    sa.DDL("CREATE INDEX detections_text_idx ON detections USING GIN (idx_vector)")
)

sa.event.listen(
    LocationModel.__table__,
    "after_create",
    sa.DDL("""
        CREATE OR REPLACE FUNCTION index_filepath()
        RETURNS TRIGGER
        AS $$
        BEGIN
            NEW.idx_path = to_tsvector('english', REPLACE(REPLACE(NEW.name, '$', ' '), '/', ' '));
            RETURN NEW;
        END $$ LANGUAGE plpgsql;
    """)
)

sa.event.listen(
    LocationModel.__table__,
    "after_create",
    sa.DDL("""
        CREATE TRIGGER set_filepath_index
        BEFORE INSERT OR UPDATE ON locations
        FOR EACH ROW
            EXECUTE PROCEDURE index_filepath();
    """)
)

sa.event.listen(
    LocationModel.__table__,
    "after_create",
    sa.DDL("CREATE INDEX filepaths_text_idx ON locations USING GIN (idx_path)")
)


@dataclass
class PGBase(metaclass=ABCMeta):
    def __enter__(self):
        if not self.uri:
            raise InvalidOutput("You must use full URI output specification for the postgres output format")
        elif self.output_location == "-":
            raise InvalidOutput("Postgres format can't output to the stdout")

        self.engine = get_engine(self.uri)
        self.out_fd = scoped_session(sessionmaker(
            autocommit=False,
            autoflush=False,
            bind=self.engine
        ))
        return self.out_fd

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is None:
            self.out_fd.commit()
        else:
            self.out_fd.rollback()

        self.out_fd.close()
        self.out_fd = None

        self.engine.dispose()
        self.engine = None

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
        Base.metadata.create_all(self.engine)

    def output(self, scans: Sequence[ScanData]):
        tag_ids = {}
        with self.out_fd.begin():
            for scan in scans:
                location_ids = {}
                indicators = {}
                all_tags = set()

                if not (ref_id:=scan.metadata.get("reference")):
                    ref_id = str(uuid.uuid4())

                scan_data = scan.to_json()
                scan_metadata = scan_data.pop("metadata", {})

                scan_obj = ScanModel(
                    input=scan_metadata["name"],
                    reference=ref_id,
                    scan_data=scan_data,#sanitize_json(scan_data),
                    metadata_col=scan_metadata, #sanitize_json(scan_metadata),
                    scan_score=scan_data.get("score", 0),
                    created=datetime.datetime.utcnow(),
                    package=scan_metadata.get("package_name"),
                    package_release=scan_metadata.get("package_release"),
                    pkg_filename=scan_metadata.get("package_file")
                )
                self.out_fd.add(scan_obj)
                self.out_fd.flush()
                logger.info(f"Saved under scan id: {scan_obj.scan_id}")

                for indicator_data in scan_metadata.get("behavioral_analysis", {}).values():
                    if indicator_data["id"] not in indicators:
                        result = self.out_fd.execute("""
                        WITH ins AS (
                            INSERT INTO indicators(slug, name, description)
                            VALUES (:id, :name, :description)
                            ON CONFLICT(slug) DO UPDATE
                            SET description=NULL
                            WHERE FALSE
                            RETURNING id
                        )
                        SELECT id FROM ins
                        UNION ALL
                        SELECT id FROM indicators
                        WHERE slug=:id
                        LIMIT 1
                        """, indicator_data).first()[0]
                        indicators[indicator_data["id"]] = result

                    self.out_fd.add(ScanIndicators(
                        scan_id=scan_obj.id,
                        indicator_id=indicators[indicator_data["id"]]
                    ))

                for detection in scan.hits:
                    norm_path = detection.location

                    if norm_path in location_ids:
                        location_id = location_ids[norm_path].id
                    else:
                        location_obj = LocationModel(
                            name=norm_path,
                            scan_id=scan_obj.id,
                            metadata_col=detection._metadata,#sanitize_json(detection._metadata),
                        )
                        self.out_fd.add(location_obj)
                        self.out_fd.flush()
                        location_id = location_obj.id
                        location_ids[norm_path] = location_obj

                    detection_obj = DetectionModel(
                        signature=detection.int_signature,
                        score=detection.score,
                        slug=detection.slug,
                        data=detection.to_json(),#sanitize_json(detection),
                        scan_id = scan_obj.id,
                        location_id = location_id
                    )
                    self.out_fd.add(detection_obj)
                    self.out_fd.flush()

                    for tag in detection.tags:
                        if tag not in tag_ids:
                            result = self.out_fd.execute("""
                                WITH ins AS (
                                    INSERT INTO tags(tag)
                                    VALUES(:tag)
                                    ON CONFLICT (tag) DO UPDATE
                                    SET tag=NULL
                                    WHERE FALSE -- never executes but locks the row
                                    RETURNING id
                                )
                                SELECT id FROM ins
                                UNION ALL
                                SELECT id FROM tags
                                WHERE tag=:tag
                                LIMIT 1
                            """, {"tag": tag})
                            tag_ids[tag] = result.first()[0]

                        self.out_fd.add(DetectionTagsModel(
                            detection_id=detection_obj.id,
                            tag_id=tag_ids[tag]
                        ))
                        self.out_fd.flush()

                    all_tags |= set(detection.tags)

                for tag in all_tags:
                    self.out_fd.add(ScanTagsModel(
                        scan_id=scan_obj.id,
                        tag_id=tag_ids[tag]
                    ))


def get_engine(uri: Union[urllib.parse.ParseResult, str]) -> TypeEngine:
    if type(uri) == str:
        uri = urllib.parse.urlparse(uri)

    # TODO: change the hook name in package setup to postgresql to avoid this
    return sa.create_engine(
        urllib.parse.urlunparse(("postgresql",) + tuple(uri)[1:]),
        json_serializer=sanitize_json,
        json_deserializer=loads
    )


def get_session(engine_or_uri):
    if type(engine_or_uri) == str:
        engine = get_engine(engine_or_uri)
    else:
        engine = engine_or_uri

    return scoped_session(sessionmaker(
        autocommit=False,
        autoflush=False,
        bind=engine
    ))


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

    engine = get_engine(pg_uri)
    session = scoped_session(sessionmaker(bind=engine))

    for uri in parse_bandersnatch_log(Path(log_path)):
        logger.info(f"Inserting URI into the scan queue: `{uri}`")
        session.add(PendingScans(uri=uri))

    session.flush()
    session.commit()
    session.close()


def sanitize_json(data: Union[dict, str]) -> str:
    # TODO: add tests for this
    # This unicode character is not valid in postgres json column data
    return dumps(data).replace("\\u0000", "").replace("\u0000", "")
