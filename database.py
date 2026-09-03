import json
import sqlite3
from pathlib import Path
from datetime import datetime, timezone


DB_PATH = Path("data/recon.db")


SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS hosts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ip          TEXT NOT NULL UNIQUE,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    risk_score  INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id     INTEGER NOT NULL,
    started_at  TEXT NOT NULL,
    finished_at TEXT,
    status      TEXT NOT NULL,
    source      TEXT,
    FOREIGN KEY(host_id) REFERENCES hosts(id)
);

-- Primary observation: port + service + version
CREATE TABLE IF NOT EXISTS service_observations (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     INTEGER NOT NULL,
    host_id     INTEGER NOT NULL,
    port        INTEGER NOT NULL,
    protocol    TEXT NOT NULL,
    service     TEXT,
    version     TEXT,
    banner      TEXT,
    raw_json    TEXT,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    UNIQUE(host_id, port, protocol),
    FOREIGN KEY(scan_id) REFERENCES scans(id),
    FOREIGN KEY(host_id) REFERENCES hosts(id)
);

-- Domains / subdomains linked to host
CREATE TABLE IF NOT EXISTS domains (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id     INTEGER NOT NULL,
    name        TEXT NOT NULL,
    source      TEXT NOT NULL,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    UNIQUE(host_id, name, source),
    FOREIGN KEY(host_id) REFERENCES hosts(id)
);

-- Geo snapshot
CREATE TABLE IF NOT EXISTS geo (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id      INTEGER NOT NULL UNIQUE,
    country      TEXT,
    country_code TEXT,
    region       TEXT,
    city         TEXT,
    lat          REAL,
    lon          REAL,
    asn          TEXT,
    org          TEXT,
    isp          TEXT,
    source       TEXT,
    looked_up_at TEXT NOT NULL,
    FOREIGN KEY(host_id) REFERENCES hosts(id)
);

CREATE TABLE IF NOT EXISTS findings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id         INTEGER NOT NULL,
    observation_id  INTEGER,
    finding_key     TEXT NOT NULL,
    severity        INTEGER NOT NULL,
    title           TEXT NOT NULL,
    description     TEXT,
    evidence        TEXT,
    first_seen      TEXT NOT NULL,
    last_seen       TEXT NOT NULL,
    UNIQUE(host_id, observation_id, finding_key),
    FOREIGN KEY(host_id) REFERENCES hosts(id),
    FOREIGN KEY(observation_id) REFERENCES service_observations(id)
);

-- Deep analysis queue (same worker for now)
CREATE TABLE IF NOT EXISTS deep_tasks (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    observation_id  INTEGER NOT NULL,
    chain           TEXT NOT NULL,
    status          TEXT NOT NULL,
    priority        INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT NOT NULL,
    started_at      TEXT,
    finished_at     TEXT,
    error           TEXT,
    FOREIGN KEY(observation_id) REFERENCES service_observations(id)
);

CREATE TABLE IF NOT EXISTS deep_results (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id         INTEGER NOT NULL,
    observation_id  INTEGER NOT NULL,
    key             TEXT NOT NULL,
    value_json      TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    FOREIGN KEY(task_id) REFERENCES deep_tasks(id),
    FOREIGN KEY(observation_id) REFERENCES service_observations(id)
);

CREATE INDEX IF NOT EXISTS idx_hosts_ip ON hosts(ip);
CREATE INDEX IF NOT EXISTS idx_obs_host ON service_observations(host_id);
CREATE INDEX IF NOT EXISTS idx_obs_service ON service_observations(service);
CREATE INDEX IF NOT EXISTS idx_domains_host ON domains(host_id);
CREATE INDEX IF NOT EXISTS idx_findings_host ON findings(host_id);
CREATE INDEX IF NOT EXISTS idx_deep_status ON deep_tasks(status);
"""


def utcnow():
    return datetime.now(timezone.utc).isoformat()


def connect(timeout: float = 30.0):
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=timeout, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA busy_timeout = 30000")
    conn.execute("PRAGMA synchronous = NORMAL")
    return conn


def init_db():
    with connect() as conn:
        conn.executescript(SCHEMA)


# ── Hosts ──────────────────────────────────────────────

def get_or_create_host(conn, ip, timestamp=None):
    timestamp = timestamp or utcnow()
    row = conn.execute(
        "SELECT id FROM hosts WHERE ip = ?", (ip,)
    ).fetchone()

    if row:
        host_id = row["id"]
        conn.execute(
            "UPDATE hosts SET last_seen = ? WHERE id = ?",
            (timestamp, host_id),
        )
        return host_id

    cur = conn.execute(
        "INSERT INTO hosts (ip, first_seen, last_seen) VALUES (?, ?, ?)",
        (ip, timestamp, timestamp),
    )
    return cur.lastrowid


# ── Scans ──────────────────────────────────────────────

def create_scan(conn, host_id, source="worker"):
    ts = utcnow()
    cur = conn.execute(
        """
        INSERT INTO scans (host_id, started_at, status, source)
        VALUES (?, ?, 'running', ?)
        """,
        (host_id, ts, source),
    )
    return cur.lastrowid


def finish_scan(conn, scan_id, status="done"):
    conn.execute(
        "UPDATE scans SET finished_at = ?, status = ? WHERE id = ?",
        (utcnow(), status, scan_id),
    )


# ── Service observations ───────────────────────────────

def upsert_observation(conn, scan_id, host_id, data, timestamp=None):
    """
    data — dict от scanner (result()):
        service, port, protocol, observations, findings, timestamp
    """
    timestamp = timestamp or data.get("timestamp") or utcnow()
    port = data["port"]
    protocol = data["protocol"]
    service = data.get("service")
    observations = data.get("observations") or {}

    version = (
        observations.get("version")
        or observations.get("server")
        or observations.get("banner")
    )
    banner = observations.get("banner")

    raw_json = json.dumps(data, ensure_ascii=False, default=str)

    row = conn.execute(
        """
        SELECT id FROM service_observations
        WHERE host_id = ? AND port = ? AND protocol = ?
        """,
        (host_id, port, protocol),
    ).fetchone()

    if row:
        obs_id = row["id"]
        conn.execute(
            """
            UPDATE service_observations SET
                scan_id = ?,
                service = ?,
                version = ?,
                banner = ?,
                raw_json = ?,
                last_seen = ?
            WHERE id = ?
            """,
            (scan_id, service, version, banner, raw_json, timestamp, obs_id),
        )
        return obs_id

    cur = conn.execute(
        """
        INSERT INTO service_observations (
            scan_id, host_id, port, protocol,
            service, version, banner, raw_json,
            first_seen, last_seen
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            scan_id, host_id, port, protocol,
            service, version, banner, raw_json,
            timestamp, timestamp,
        ),
    )
    return cur.lastrowid


# ── Domains ────────────────────────────────────────────

def upsert_domain(conn, host_id, name, source, timestamp=None):
    if not name:
        return None
    name = name.strip().lower().rstrip(".")
    if not name:
        return None

    timestamp = timestamp or utcnow()

    row = conn.execute(
        """
        SELECT id FROM domains
        WHERE host_id = ? AND name = ? AND source = ?
        """,
        (host_id, name, source),
    ).fetchone()

    if row:
        conn.execute(
            "UPDATE domains SET last_seen = ? WHERE id = ?",
            (timestamp, row["id"]),
        )
        return row["id"]

    cur = conn.execute(
        """
        INSERT INTO domains (host_id, name, source, first_seen, last_seen)
        VALUES (?, ?, ?, ?, ?)
        """,
        (host_id, name, source, timestamp, timestamp),
    )
    return cur.lastrowid


# ── Geo ────────────────────────────────────────────────

def upsert_geo(conn, host_id, geo_data, timestamp=None):
    """
    geo_data keys: country, country_code, region, city,
                   lat, lon, asn, org, isp, source
    """
    if not geo_data:
        return None

    timestamp = timestamp or utcnow()

    row = conn.execute(
        "SELECT id FROM geo WHERE host_id = ?", (host_id,)
    ).fetchone()

    fields = (
        geo_data.get("country"),
        geo_data.get("country_code"),
        geo_data.get("region"),
        geo_data.get("city"),
        geo_data.get("lat"),
        geo_data.get("lon"),
        geo_data.get("asn"),
        geo_data.get("org"),
        geo_data.get("isp"),
        geo_data.get("source"),
        timestamp,
        host_id,
    )

    if row:
        conn.execute(
            """
            UPDATE geo SET
                country = ?, country_code = ?, region = ?, city = ?,
                lat = ?, lon = ?, asn = ?, org = ?, isp = ?,
                source = ?, looked_up_at = ?
            WHERE host_id = ?
            """,
            fields,
        )
        return row["id"]

    cur = conn.execute(
        """
        INSERT INTO geo (
            country, country_code, region, city,
            lat, lon, asn, org, isp,
            source, looked_up_at, host_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        fields,
    )
    return cur.lastrowid


# ── Findings ───────────────────────────────────────────

def upsert_finding(conn, host_id, observation_id, item, timestamp=None):
    timestamp = timestamp or utcnow()
    finding_key = item.get("id") or item.get("finding_key") or "unknown"

    row = conn.execute(
        """
        SELECT id FROM findings
        WHERE host_id = ? AND observation_id IS ?
          AND finding_key = ?
        """,
        (host_id, observation_id, finding_key),
    ).fetchone()

    if row:
        conn.execute(
            """
            UPDATE findings SET
                severity = ?, title = ?, description = ?,
                evidence = ?, last_seen = ?
            WHERE id = ?
            """,
            (
                item.get("severity", 0),
                item.get("title", ""),
                item.get("description", ""),
                item.get("evidence", ""),
                timestamp,
                row["id"],
            ),
        )
        return row["id"]

    cur = conn.execute(
        """
        INSERT INTO findings (
            host_id, observation_id, finding_key,
            severity, title, description, evidence,
            first_seen, last_seen
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            host_id,
            observation_id,
            finding_key,
            item.get("severity", 0),
            item.get("title", ""),
            item.get("description", ""),
            item.get("evidence", ""),
            timestamp,
            timestamp,
        ),
    )
    return cur.lastrowid


# ── Deep tasks ─────────────────────────────────────────

def enqueue_deep(conn, observation_id, chain, priority=0):
    # не дублируем pending/running
    existing = conn.execute(
        """
        SELECT id FROM deep_tasks
        WHERE observation_id = ? AND chain = ?
          AND status IN ('pending', 'running')
        """,
        (observation_id, chain),
    ).fetchone()
    if existing:
        return existing["id"]

    cur = conn.execute(
        """
        INSERT INTO deep_tasks (
            observation_id, chain, status, priority, created_at
        ) VALUES (?, ?, 'pending', ?, ?)
        """,
        (observation_id, chain, priority, utcnow()),
    )
    return cur.lastrowid


def fetch_pending_deep(conn, limit=20):
    return conn.execute(
        """
        SELECT * FROM deep_tasks
        WHERE status = 'pending'
        ORDER BY priority DESC, id ASC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()


def mark_deep_running(conn, task_id):
    conn.execute(
        "UPDATE deep_tasks SET status = 'running', started_at = ? WHERE id = ?",
        (utcnow(), task_id),
    )


def mark_deep_done(conn, task_id, error=None):
    status = "error" if error else "done"
    conn.execute(
        """
        UPDATE deep_tasks
        SET status = ?, finished_at = ?, error = ?
        WHERE id = ?
        """,
        (status, utcnow(), error, task_id),
    )


def save_deep_result(conn, task_id, observation_id, key, value):
    conn.execute(
        """
        INSERT INTO deep_results (
            task_id, observation_id, key, value_json, created_at
        ) VALUES (?, ?, ?, ?, ?)
        """,
        (
            task_id,
            observation_id,
            key,
            json.dumps(value, ensure_ascii=False, default=str),
            utcnow(),
        ),
    )


# ── High-level: save primary result ────────────────────

def save_primary_result(ip, data, scan_id=None, host_id=None):
    """
    Сохраняет один результат сканера порта.
    Возвращает (host_id, observation_id).
    """
    timestamp = data.get("timestamp") or utcnow()

    with connect() as conn:
        if host_id is None:
            host_id = get_or_create_host(conn, ip, timestamp)

        if scan_id is None:
            scan_id = create_scan(conn, host_id)

        obs_id = upsert_observation(conn, scan_id, host_id, data, timestamp)

        for item in data.get("findings") or []:
            upsert_finding(conn, host_id, obs_id, item, timestamp)

        return host_id, obs_id


# backward-compatible alias used by old code
def save_result(ip, data):
    host_id, _ = save_primary_result(ip, data)
    return host_id


if __name__ == "__main__":
    init_db()
    print(f"DB ready: {DB_PATH}")