import contextlib
import json
import sqlite3
from pathlib import Path
from datetime import datetime, timezone


ROOT = Path(__file__).resolve().parent
DB_PATH = ROOT / "data" / "recon.db"


class _ClosingConnection(sqlite3.Connection):
    """sqlite3.Connection, закрывающий файл при выходе из `with`.

    Стандартный контекстный менеджер sqlite3 делает commit/rollback,
    но НЕ закрывает соединение — отсюда утечки fd в worker/webapp.
    """

    def __exit__(self, exc_type, exc, tb):
        try:
            return super().__exit__(exc_type, exc, tb)
        finally:
            try:
                self.close()
            except Exception:
                pass


def connect():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(
        str(DB_PATH), timeout=30.0, check_same_thread=False, factory=_ClosingConnection
    )
    conn.row_factory = sqlite3.Row
    # Меньше SQLITE_BUSY при параллельных writer'ах (worker + deep + web).
    try:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA busy_timeout=30000;")
        conn.execute("PRAGMA foreign_keys=ON;")
    except Exception:
        pass
    return conn


@contextlib.contextmanager
def transaction():
    """Короткая транзакция с гарантированным close."""
    conn = connect()
    try:
        yield conn
        conn.commit()
    except Exception:
        try:
            conn.rollback()
        except Exception:
            pass
        raise
    finally:
        try:
            conn.close()
        except Exception:
            pass


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
    observation_id  INTEGER NOT NULL DEFAULT 0,
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
CREATE TABLE IF NOT EXISTS task_logs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id     INTEGER NOT NULL,
    stream      TEXT NOT NULL,
    line        TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    FOREIGN KEY(task_id) REFERENCES deep_tasks(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_task_logs_task ON task_logs(task_id, id);
"""


def utcnow():
    return datetime.now(timezone.utc).isoformat()


def init_db():
    with connect() as conn:
        conn.executescript(SCHEMA)
        # Миграция старых БД: observation_id мог быть NULL ( UNIQUE с NULL
        # не дедуплицирует в SQLite) — нормализуем к 0 и чистим дубли.
        try:
            cols = [r["name"] for r in conn.execute("PRAGMA table_info(findings)").fetchall()]
            if "observation_id" in cols:
                conn.execute("UPDATE findings SET observation_id = 0 WHERE observation_id IS NULL")
                conn.execute(
                    """
                    DELETE FROM findings
                    WHERE id NOT IN (
                        SELECT MIN(id) FROM findings
                        GROUP BY host_id, observation_id, finding_key
                    )
                    """
                )
        except Exception:
            pass
        # Backward-compatible migration for databases created before task leases/logs.
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(deep_tasks)").fetchall()}
        migrations = {
            "worker_id": "ALTER TABLE deep_tasks ADD COLUMN worker_id TEXT",
            "heartbeat_at": "ALTER TABLE deep_tasks ADD COLUMN heartbeat_at TEXT",
            "cancel_requested": "ALTER TABLE deep_tasks ADD COLUMN cancel_requested INTEGER NOT NULL DEFAULT 0",
            "attempt": "ALTER TABLE deep_tasks ADD COLUMN attempt INTEGER NOT NULL DEFAULT 0",
        }
        for name, sql in migrations.items():
            if name not in cols:
                conn.execute(sql)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_deep_heartbeat ON deep_tasks(status, heartbeat_at)")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS task_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id INTEGER NOT NULL,
                stream TEXT NOT NULL,
                line TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(task_id) REFERENCES deep_tasks(id) ON DELETE CASCADE
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_task_logs_task ON task_logs(task_id, id)")


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
    # Host-level findings (reverse_dns, expired_cert) приходят с observation_id=None.
    # В SQLite NULL != NULL, поэтому UNIQUE(host_id, observation_id, finding_key)
    # с NULL никогда не дедуплицируется. Нормализуем к 0.
    if observation_id is None:
        observation_id = 0
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
    # не дублируем pending/running; done/error/cancelled пересоздаём,
    # чтобы упавшая цепочка перезапустилась при повторном скане хоста.
    existing = conn.execute(
        """
        SELECT id, status FROM deep_tasks
        WHERE observation_id = ? AND chain = ?
        ORDER BY id DESC
        """,
        (observation_id, chain),
    ).fetchone()
    if existing is not None:
        status = existing["status"] if hasattr(existing, "keys") else existing[1]
        if status in ("pending", "running"):
            return existing["id"] if hasattr(existing, "keys") else existing[0]
        conn.execute(
            """
            UPDATE deep_tasks
            SET status = 'pending', priority = ?, created_at = ?,
                started_at = NULL, finished_at = NULL, error = NULL,
                worker_id = NULL, heartbeat_at = NULL, cancel_requested = 0,
                attempt = attempt + 1
            WHERE id = ?
            """,
            (priority, utcnow(), existing["id"] if hasattr(existing, "keys") else existing[0]),
        )
        return existing["id"] if hasattr(existing, "keys") else existing[0]

    cur = conn.execute(
        """
        INSERT INTO deep_tasks (
            observation_id, chain, status, priority, created_at, attempt, cancel_requested
        ) VALUES (?, ?, 'pending', ?, ?, 0, 0)
        """,
        (observation_id, chain, priority, utcnow()),
    )
    return cur.lastrowid


def fetch_pending_deep(conn, limit=20):
    return conn.execute(
        """
        SELECT * FROM deep_tasks
        WHERE status = 'pending' AND cancel_requested = 0
        ORDER BY priority DESC, id ASC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()


def mark_deep_running(conn, task_id, worker_id):
    cur = conn.execute(
        """
        UPDATE deep_tasks
        SET status = 'running', started_at = ?, finished_at = NULL, error = NULL,
            worker_id = ?, heartbeat_at = ?, cancel_requested = 0, attempt = attempt + 1
        WHERE id = ? AND status = 'pending' AND cancel_requested = 0
        """,
        (utcnow(), worker_id, utcnow(), task_id),
    )
    return cur.rowcount == 1


def heartbeat_deep(conn, task_id, worker_id):
    conn.execute(
        """
        UPDATE deep_tasks SET heartbeat_at = ?
        WHERE id = ? AND status = 'running' AND worker_id = ?
        """,
        (utcnow(), task_id, worker_id),
    )


def mark_deep_done(conn, task_id, error=None, expected_status=None):
    """Помечает deep-задачу завершённой.

    expected_status: если задан — UPDATE сработает только если задача всё ещё
    в этом статусе. Защита от гонки «timeout записал error, а зависший тред
    позже перезаписал его на done».
    Возвращает True если строка обновлена.
    """
    status = "error" if error else "done"
    if expected_status is not None:
        cur = conn.execute(
            """
            UPDATE deep_tasks
            SET status = ?, finished_at = ?, error = ?, heartbeat_at = NULL, worker_id = NULL
            WHERE id = ? AND status = ?
            """,
            (status, utcnow(), error, task_id, expected_status),
        )
        return cur.rowcount == 1
    conn.execute(
        """
        UPDATE deep_tasks
        SET status = ?, finished_at = ?, error = ?, heartbeat_at = NULL, worker_id = NULL
        WHERE id = ?
        """,
        (status, utcnow(), error, task_id),
    )
    return True


def mark_deep_cancelled(conn, task_id, reason="cancelled by user"):
    conn.execute(
        """
        UPDATE deep_tasks
        SET status = 'cancelled', finished_at = ?, error = ?,
            heartbeat_at = NULL, worker_id = NULL, cancel_requested = 0
        WHERE id = ?
        """,
        (utcnow(), reason, task_id),
    )


def deep_cancel_requested(conn, task_id):
    row = conn.execute("SELECT cancel_requested FROM deep_tasks WHERE id = ?", (task_id,)).fetchone()
    return bool(row and row["cancel_requested"])


def request_deep_cancel(conn, task_id):
    cur = conn.execute(
        """
        UPDATE deep_tasks SET cancel_requested = 1
        WHERE id = ? AND status = 'running'
        """,
        (task_id,),
    )
    if cur.rowcount:
        return True
    cur = conn.execute(
        """
        UPDATE deep_tasks
        SET status = 'cancelled', finished_at = ?, error = 'cancelled by user'
        WHERE id = ? AND status = 'pending'
        """,
        (utcnow(), task_id),
    )
    return cur.rowcount == 1


def restart_deep(conn, task_id):
    cur = conn.execute(
        """
        UPDATE deep_tasks
        SET status = 'pending', started_at = NULL, finished_at = NULL, error = NULL,
            worker_id = NULL, heartbeat_at = NULL, cancel_requested = 0
        WHERE id = ? AND status IN ('done', 'error', 'cancelled')
        """,
        (task_id,),
    )
    return cur.rowcount == 1


def recover_interrupted_deep(conn, stale_after_seconds=30):
    # Перезапускаем только действительно потерянные leases. Это не ломает живой worker.
    from datetime import timedelta
    cutoff = (datetime.now(timezone.utc) - timedelta(seconds=stale_after_seconds)).isoformat()
    rows = conn.execute(
        """
        SELECT id FROM deep_tasks
        WHERE status = 'running'
          AND COALESCE(heartbeat_at, started_at) < ?
        """,
        (cutoff,),
    ).fetchall()
    if rows:
        ids = [r["id"] for r in rows]
        conn.execute(
            f"""
            UPDATE deep_tasks
            SET status = 'pending', started_at = NULL, finished_at = NULL,
                error = 'worker interrupted; task requeued', worker_id = NULL,
                heartbeat_at = NULL, cancel_requested = 0
            WHERE id IN ({','.join('?' * len(ids))})
            """,
            ids,
        )
    return len(rows)


def save_task_log(conn, task_id, stream, line):
    conn.execute(
        "INSERT INTO task_logs (task_id, stream, line, created_at) VALUES (?, ?, ?, ?)",
        (task_id, stream, line, utcnow()),
    )


def fetch_task_logs(conn, task_id, limit=2000, after_id=0):
    rows = conn.execute(
        """
        SELECT id, task_id, stream, line, created_at
        FROM task_logs WHERE task_id = ? AND id > ?
        ORDER BY id ASC LIMIT ?
        """,
        (task_id, after_id, limit),
    ).fetchall()
    return [dict(r) for r in rows]


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

# ── Host-centric helpers (use models.HostProfile for full view) ─

def get_full_host(host_id: int = None, ip: str = None):
    """
    Convenience wrapper.
    Prefer: from models import get_host_by_id / get_host_by_ip
    """
    from models import get_host_by_id, get_host_by_ip
    if host_id is not None:
        return get_host_by_id(host_id)
    if ip is not None:
        return get_host_by_ip(ip)
    raise ValueError("host_id or ip required")
