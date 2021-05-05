import os
import sys
import sqlite3
import zlib

import rapidjson
import xxhash


# TODO: reqs:
# pip install xxhash

DETECTION_TYPES = {}
TAG_NAMES = {}



def initialize_schema(connection):
    cur = connection.cursor()

    cur.execute("""
        CREATE TABLE scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            package_name VARCHAR(256) UNIQUE,
            metadata JSON
        )
        """)

    cur.execute("""
    CREATE TABLE tag_names (id INTEGER PRIMARY KEY AUTOINCREMENT, name VARCHAR(128) UNIQUE)
    """)

    cur.execute("""
    CREATE TABLE detection_types (id INTEGER PRIMARY KEY AUTOINCREMENT, name text)
    """)

    cur.execute("""
    CREATE TABLE detections 
    (
        id INTEGER PRIMARY KEY AUTOINCREMENT ,
        scan INTEGER NOT NULL ,
        type INTEGER NOT NULL,
        signature TEXT UNIQUE,
        message TEXT NOT NULL,
        score INTEGER DEFAULT 0,
        extra BLOB,
        FOREIGN KEY (type) REFERENCES detection_types (id),
        FOREIGN KEY (scan) REFERENCES scans (id)
    )
    """)

    cur.execute("""
    CREATE TABLE tags (
        detection INTEGER NOT NULL,
        tag INTEGER NOT NULL,
        FOREIGN KEY (detection) REFERENCES detections (id),
        FOREIGN KEY (tag) REFERENCES tag_names (id),
        PRIMARY KEY (detection, tag)
    ) WITHOUT ROWID
    """)

    connection.commit()


def create_or_open(name: str):
    exists = os.path.exists(name)
    conn = sqlite3.connect(name)
    if not exists:
        initialize_schema(conn)
    else:
        load_existing(conn.cursor())

    return conn


def load_existing(cursor):
    cursor.execute("SELECT id, name FROM tag_names")

    for (id, name) in cursor.fetchall():
        TAG_NAMES[name] = id

    cursor.execute("SELECT id, name FROM detection_types")

    for (id, name) in cursor.fetchall():
        DETECTION_TYPES[name] = id


def get_tag_id(name, cursor) -> int:
    if name not in TAG_NAMES:
        cursor.execute("INSERT INTO tag_names (name) VALUES (?)", (name,))
        TAG_NAMES[name] = cursor.lastrowid

    return TAG_NAMES[name]


def get_detection_type_id(name, cursor) -> int:
    if name not in DETECTION_TYPES:
        cursor.execute("INSERT INTO detection_types (name) VALUES (?)", (name,))
        DETECTION_TYPES[name] = cursor.lastrowid

    return DETECTION_TYPES[name]


def add_detection(scan_id, detection, package, cursor):
    # TODO: add severity to table cols
    type_id = get_detection_type_id(detection["type"], cursor)
    signature = xxhash.xxh64(f"{package}#{detection['signature']}").hexdigest()

    extra = zlib.compress(rapidjson.dumps(detection.get("extra", {})).encode())

    try:
        cursor.execute("""
        INSERT INTO detections (scan, type, signature, message, score, extra) VALUES (?, ?, ?, ?, ?, ?)
        """, (scan_id, type_id, signature, detection["message"], detection.get("score", 0), extra))
    except sqlite3.IntegrityError:
        print(f"Warning detection already exists: {detection}")
        return

    detection_id = cursor.lastrowid

    for tag in detection.get("tags", []):
        tag_id = get_tag_id(tag, cursor)
        try:
            cursor.execute("""
            INSERT INTO tags (detection, tag) VALUES (?, ?)
            """, (detection_id, tag_id))
        except sqlite3.IntegrityError:
            pass


def add_scan(scan: dict, cursor):
    try:
        pkg_name = scan["metadata"]["uri_input"]["package"]
        print(f"Processing package: `{pkg_name}`")

        cursor.execute("""
        INSERT INTO scans (package_name, metadata) VALUES (?, ?)
        """, (pkg_name, rapidjson.dumps(scan["metadata"])))
    except sqlite3.IntegrityError:
        # Data for this package already exists:
        return

    scan_id = cursor.lastrowid
    for d in scan.get("detections", []):
        add_detection(scan_id, d, pkg_name, cursor)


def process_scans(dataset_path, cursor):
    with open(dataset_path, "r") as fd:
        for line in fd:
            if line := line.strip():
                add_scan(rapidjson.loads(line), cursor)


def main(name: str, dataset_path):
    c = create_or_open(name)
    cur = c.cursor()

    process_scans(dataset_path, cur)

    c.commit()


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
