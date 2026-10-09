"""
Local web UI — Host-centric Access Scanner.
Run from project root:
    python webapp.py
Open:
    http://127.0.0.1:8088
"""
from __future__ import annotations

import json
import sys
import os
import signal
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from flask import Flask, abort, render_template, request, jsonify, redirect, url_for

from database import connect, init_db, request_deep_cancel, restart_deep, fetch_task_logs
from models import get_host_by_id, list_host_summaries
import deep_runner

app = Flask(
    __name__,
    template_folder=str(ROOT / "templates"),
    static_folder=str(ROOT / "static"),
)


WORKER_PID_FILE = ROOT / "state" / "worker.pid"
WORKER_STATUS_FILE = ROOT / "state" / "worker.json"
WORKER_LOG_FILE = ROOT / "state" / "worker.log"


def _worker_pid():
    try:
        pid = int(WORKER_PID_FILE.read_text().strip())
        os.kill(pid, 0)
        return pid
    except (OSError, ValueError, FileNotFoundError):
        return None


def worker_status():
    pid = _worker_pid()
    status = {}
    try:
        status = json.loads(WORKER_STATUS_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        pass
    status["running"] = bool(pid)
    status["pid"] = pid
    if not pid:
        status["state"] = "stopped"
    return status


def _start_worker_process():
    pid = _worker_pid()
    if pid:
        return False, f"worker already running (pid={pid})"
    WORKER_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    log_handle = WORKER_LOG_FILE.open("a", encoding="utf-8")
    try:
        proc = subprocess.Popen(
            [sys.executable, str(ROOT / "worker.py")],
            cwd=str(ROOT), stdout=log_handle, stderr=subprocess.STDOUT,
            start_new_session=True, close_fds=True,
        )
    finally:
        log_handle.close()
    return True, f"worker started (pid={proc.pid})"


def _stop_worker_process():
    pid = _worker_pid()
    if not pid:
        return False, "worker is not running"
    try:
        os.kill(pid, signal.SIGTERM)
        return True, f"shutdown requested (pid={pid})"
    except OSError as exc:
        return False, str(exc)


def worker_log_tail(limit=100000):
    try:
        data = WORKER_LOG_FILE.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    return data[-limit:]

SEVERITY_NAMES = {0: "INFO", 1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}
SEVERITY_CLASS = {0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical"}


def risk_bucket(score: int) -> str:
    score = int(score or 0)
    if score >= 70:
        return "critical"
    if score >= 40:
        return "high"
    if score >= 20:
        return "medium"
    return "low"


@app.template_filter("severity_name")
def severity_name(value):
    return SEVERITY_NAMES.get(int(value or 0), "INFO")


@app.template_filter("severity_class")
def severity_class(value):
    return SEVERITY_CLASS.get(int(value or 0), "info")


@app.template_filter("risk_class")
def risk_class_filter(score):
    return risk_bucket(score)


@app.template_filter("pretty_json")
def pretty_json(value):
    return json.dumps(value, indent=2, ensure_ascii=False, default=str)


@app.template_filter("short_time")
def short_time(value):
    if not value:
        return "—"
    return str(value).replace("T", " ")[:19]


@app.template_filter("truncate")
def truncate_filter(value, length=120):
    if value is None:
        return ""
    s = str(value)
    if len(s) <= length:
        return s
    return s[: length - 1] + "…"


def list_host_ids(conn):
    return [
        r["id"]
        for r in conn.execute(
            "SELECT id FROM hosts ORDER BY risk_score DESC, last_seen DESC, id DESC"
        ).fetchall()
    ]



def fetch_task_queue(conn, status=None, limit=200):
    """
    Очередь deep-задач с контекстом host/service.
    status: None = pending+running (+ recent done/error),
            или конкретный статус / список
    """
    if status is None:
        where = "dt.status IN ('pending', 'running')"
        params: list = []
    elif isinstance(status, (list, tuple, set)):
        placeholders = ",".join("?" * len(status))
        where = f"dt.status IN ({placeholders})"
        params = list(status)
    else:
        where = "dt.status = ?"
        params = [status]

    sql = f"""
        SELECT
            dt.id AS task_id,
            dt.chain,
            dt.status,
            dt.priority,
            dt.created_at,
            dt.started_at,
            dt.finished_at,
            dt.error,
            dt.worker_id,
            dt.heartbeat_at,
            dt.cancel_requested,
            dt.attempt,
            so.id AS observation_id,
            so.port,
            so.protocol,
            so.service,
            so.version,
            h.id AS host_id,
            h.ip,
            h.risk_score
        FROM deep_tasks dt
        JOIN service_observations so ON so.id = dt.observation_id
        JOIN hosts h ON h.id = so.host_id
        WHERE {where}
        ORDER BY
            CASE dt.status
                WHEN 'running' THEN 0
                WHEN 'pending' THEN 1
                WHEN 'error' THEN 2
                ELSE 3
            END,
            dt.priority DESC,
            dt.id ASC
        LIMIT ?
    """
    params.append(limit)
    return [dict(r) for r in conn.execute(sql, params).fetchall()]


def task_queue_stats(conn):
    rows = conn.execute(
        """
        SELECT status, COUNT(*) AS cnt
        FROM deep_tasks
        GROUP BY status
        """
    ).fetchall()
    stats = {"pending": 0, "running": 0, "done": 0, "error": 0, "total": 0}
    for r in rows:
        st = r["status"] or "unknown"
        stats[st] = r["cnt"]
        stats["total"] += r["cnt"]
    stats["active"] = stats.get("pending", 0) + stats.get("running", 0)
    return stats


@app.route("/dashboard")
def dashboard_page():
    with connect() as conn:
        tstats = task_queue_stats(conn)
        host_count = conn.execute("SELECT COUNT(*) FROM hosts").fetchone()[0]
        scan_count = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
    status = worker_status()
    runtime = {}
    try:
        runtime = json.loads((ROOT / "state" / "deep_runtime.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        runtime = {"processes": [], "active_count": 0}
    status["runtime"] = runtime
    status["free_slots"] = max(0, int(status.get("deep", {}).get("workers", 0)) - int(tstats.get("running", 0)))
    return render_template("dashboard.html", status=status, tstats=tstats, host_count=host_count, scan_count=scan_count, worker_log=worker_log_tail(50000))


@app.post("/api/worker/start")
def api_worker_start():
    ok, message = _start_worker_process()
    return jsonify({"ok": ok, "message": message, "status": worker_status()}), (200 if ok else 409)


@app.post("/api/worker/stop")
def api_worker_stop():
    ok, message = _stop_worker_process()
    return jsonify({"ok": ok, "message": message, "status": worker_status()}), (200 if ok else 409)


@app.get("/api/worker")
def api_worker():
    status = worker_status()
    try:
        status["runtime"] = json.loads((ROOT / "state" / "deep_runtime.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        status["runtime"] = {"processes": [], "active_count": 0}
    with connect() as conn:
        stats = task_queue_stats(conn)
    status["queue"] = stats
    status["free_slots"] = max(0, int(status.get("deep", {}).get("workers", 0)) - int(stats.get("running", 0)))
    return jsonify(status)


@app.get("/api/worker/log")
def api_worker_log():
    try:
        limit = int(request.args.get("limit", 100000))
    except (TypeError, ValueError):
        limit = 100000
    return jsonify({"text": worker_log_tail(min(max(limit, 1), 300000))})


@app.route("/")
def index():
    q = request.args.get("q", "").strip()
    service = request.args.get("service", "").strip().lower()
    risk = request.args.get("risk", "").strip().lower()
    country = request.args.get("country", "").strip()
    has_domain = request.args.get("has_domain", "").strip()
    sort = request.args.get("sort", "added").strip().lower()

    with connect() as conn:
        services = [
            r["service"]
            for r in conn.execute(
                """
                SELECT DISTINCT lower(service) AS service
                FROM service_observations
                WHERE service IS NOT NULL AND service != ''
                ORDER BY 1
                """
            ).fetchall()
        ]
        countries = [
            r["country"]
            for r in conn.execute(
                """
                SELECT DISTINCT country FROM geo
                WHERE country IS NOT NULL AND country != ''
                ORDER BY 1
                """
            ).fetchall()
        ]

        sql = """
            SELECT h.*,
                   g.country, g.city, g.org, g.asn,
                   (SELECT COUNT(*) FROM service_observations so
                    WHERE so.host_id = h.id) AS service_count,
                   (SELECT COUNT(*) FROM findings f
                    WHERE f.host_id = h.id) AS finding_count,
                   (SELECT GROUP_CONCAT(d.name, ', ')
                    FROM (
                        SELECT name FROM domains
                        WHERE host_id = h.id
                        ORDER BY source, name
                        LIMIT 3
                    ) d
                   ) AS domains_preview,
                   (SELECT COUNT(*) FROM domains d WHERE d.host_id = h.id) AS domain_count,
                   (SELECT GROUP_CONCAT(DISTINCT so.service)
                    FROM service_observations so
                    WHERE so.host_id = h.id AND so.service IS NOT NULL) AS services_list
            FROM hosts h
            LEFT JOIN geo g ON g.host_id = h.id
            WHERE 1=1
        """
        params: list = []

        if q:
            sql += """
                AND (
                    h.ip LIKE ?
                    OR IFNULL(g.country,'') LIKE ?
                    OR IFNULL(g.city,'') LIKE ?
                    OR IFNULL(g.org,'') LIKE ?
                    OR EXISTS (
                        SELECT 1 FROM domains d
                        WHERE d.host_id = h.id AND d.name LIKE ?
                    )
                    OR EXISTS (
                        SELECT 1 FROM service_observations so
                        WHERE so.host_id = h.id AND (
                            IFNULL(so.service,'') LIKE ?
                            OR IFNULL(so.version,'') LIKE ?
                            OR IFNULL(so.banner,'') LIKE ?
                        )
                    )
                )
            """
            like = f"%{q}%"
            params.extend([like] * 8)

        if service:
            sql += """
                AND EXISTS (
                    SELECT 1 FROM service_observations so
                    WHERE so.host_id = h.id AND lower(so.service) = ?
                )
            """
            params.append(service)

        if country:
            sql += " AND g.country = ?"
            params.append(country)

        if has_domain == "1":
            sql += " AND EXISTS (SELECT 1 FROM domains d WHERE d.host_id = h.id)"
        elif has_domain == "0":
            sql += " AND NOT EXISTS (SELECT 1 FROM domains d WHERE d.host_id = h.id)"

        if risk == "critical":
            sql += " AND h.risk_score >= 70"
        elif risk == "high":
            sql += " AND h.risk_score >= 40 AND h.risk_score < 70"
        elif risk == "medium":
            sql += " AND h.risk_score >= 20 AND h.risk_score < 40"
        elif risk == "low":
            sql += " AND h.risk_score < 20"

        # whitelist — нельзя подставлять сырой input в ORDER BY
        SORT_MAP = {
            "risk": "h.risk_score DESC, h.last_seen DESC",
            "added": "h.first_seen DESC, h.id DESC",          # время добавления (новые сверху)
            "added_asc": "h.first_seen ASC, h.id ASC",        # старые сверху
            "seen": "h.last_seen DESC, h.id DESC",
            "seen_asc": "h.last_seen ASC, h.id ASC",
            "ip": "h.ip ASC",
            "findings": "finding_count DESC, h.risk_score DESC",
        }
        order_sql = SORT_MAP.get(sort, SORT_MAP["risk"])
        sql += f" ORDER BY {order_sql} LIMIT 500"
        hosts = [dict(r) for r in conn.execute(sql, params).fetchall()]

        for h in hosts:
            raw = h.get("services_list") or ""
            h["services"] = sorted(set(filter(None, raw.split(","))))

        stats = {
            "hosts": conn.execute("SELECT COUNT(*) FROM hosts").fetchone()[0],
            "services": conn.execute(
                "SELECT COUNT(*) FROM service_observations"
            ).fetchone()[0],
            "findings": conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0],
            "critical": conn.execute(
                "SELECT COUNT(*) FROM findings WHERE severity >= 3"
            ).fetchone()[0],
        }
        tstats = task_queue_stats(conn)
        stats["tasks_running"] = tstats.get("running", 0)
        stats["tasks_pending"] = tstats.get("pending", 0)
        stats["tasks_active"] = tstats.get("active", 0)

        nav_hosts = [
            {"id": h["id"], "ip": h["ip"], "risk_score": h["risk_score"]}
            for h in hosts[:200]
        ]

    return render_template(
        "index.html",
        hosts=hosts,
        stats=stats,
        query=q,
        service=service,
        risk=risk,
        country=country,
        has_domain=has_domain,
        sort=sort,
        services=services,
        countries=countries,
        nav_hosts=nav_hosts,
    )


@app.route("/host/<int:host_id>")
def host_detail(host_id):
    profile = get_host_by_id(host_id)
    if not profile:
        abort(404)

    with connect() as conn:
        ids = list_host_ids(conn)
        try:
            idx = ids.index(host_id)
        except ValueError:
            idx = -1
        prev_id = ids[idx - 1] if idx > 0 else None
        next_id = ids[idx + 1] if 0 <= idx < len(ids) - 1 else None

        nav_hosts = []
        if ids:
            start = max(0, idx - 40)
            end = min(len(ids), idx + 60)
            slice_ids = ids[start:end]
            if slice_ids:
                placeholders = ",".join("?" * len(slice_ids))
                rows = conn.execute(
                    f"SELECT id, ip, risk_score FROM hosts WHERE id IN ({placeholders})",
                    slice_ids,
                ).fetchall()
                by_id = {r["id"]: dict(r) for r in rows}
                nav_hosts = [by_id[i] for i in slice_ids if i in by_id]

    # Prepare data for template from HostProfile
    host_dict = profile.to_dict()
    summary = host_dict["summary"]

    return render_template(
        "host.html",
        profile=profile,
        host=host_dict,
        summary=summary,
        prev_id=prev_id,
        next_id=next_id,
        nav_hosts=nav_hosts,
    )


@app.route("/api/host/<int:host_id>")
def api_host(host_id):
    """JSON API — полный профиль хоста."""
    profile = get_host_by_id(host_id)
    if not profile:
        abort(404)
    return jsonify(profile.to_dict())


@app.route("/api/hosts")
def api_hosts():
    """JSON API — список саммари."""
    try:
        limit = int(request.args.get("limit", 100))
    except (TypeError, ValueError):
        limit = 100
    try:
        offset = int(request.args.get("offset", 0))
    except (TypeError, ValueError):
        offset = 0
    return jsonify(list_host_summaries(limit=min(max(limit, 1), 500), offset=max(offset, 0)))


@app.route("/tasks")
def tasks_page():
    """Очередь deep-задач: running + pending + недавние done/error."""
    status_filter = request.args.get("status", "").strip().lower()
    with connect() as conn:
        tstats = task_queue_stats(conn)
        if status_filter in ("pending", "running", "done", "error", "cancelled"):
            queue = fetch_task_queue(conn, status=status_filter, limit=300)
        else:
            # активные всегда + последние завершённые
            active = fetch_task_queue(conn, status=["pending", "running"], limit=200)
            recent = fetch_task_queue(conn, status=["done", "error", "cancelled"], limit=50)
            # recent already ordered; re-sort done/error by finished
            recent.sort(
                key=lambda t: t.get("finished_at") or t.get("created_at") or "",
                reverse=True,
            )
            queue = active + recent[:50]

        nav_hosts = [
            {"id": r["id"], "ip": r["ip"], "risk_score": r["risk_score"]}
            for r in conn.execute(
                """
                SELECT id, ip, risk_score FROM hosts
                ORDER BY risk_score DESC, last_seen DESC
                LIMIT 80
                """
            ).fetchall()
        ]

    return render_template(
        "tasks.html",
        tasks=queue,
        tstats=tstats,
        status_filter=status_filter,
        nav_hosts=nav_hosts,
    )


@app.route("/api/tasks")
def api_tasks():
    """JSON: очередь задач."""
    status_filter = request.args.get("status", "").strip().lower()
    try:
        limit = int(request.args.get("limit", 200))
    except (TypeError, ValueError):
        limit = 200
    limit = min(max(limit, 1), 500)
    with connect() as conn:
        tstats = task_queue_stats(conn)
        if status_filter in ("pending", "running", "done", "error", "cancelled"):
            queue = fetch_task_queue(conn, status=status_filter, limit=limit)
        else:
            queue = fetch_task_queue(
                conn, status=["pending", "running", "done", "error", "cancelled"], limit=limit
            )
    return jsonify({"stats": tstats, "tasks": queue})


@app.post("/api/tasks/<int:task_id>/stop")
def api_task_stop(task_id):
    with connect() as conn:
        row = conn.execute("SELECT id, status FROM deep_tasks WHERE id = ?", (task_id,)).fetchone()
        if not row:
            return jsonify({"ok": False, "error": "task not found"}), 404
        changed = request_deep_cancel(conn, task_id)
    if changed and row["status"] == "running":
        deep_runner.request_cancel_marker(task_id)
    return jsonify({"ok": True, "status": "cancelling" if row["status"] == "running" else "cancelled"})


@app.post("/api/tasks/<int:task_id>/start")
def api_task_start(task_id):
    with connect() as conn:
        row = conn.execute("SELECT id, status FROM deep_tasks WHERE id = ?", (task_id,)).fetchone()
        if not row:
            return jsonify({"ok": False, "error": "task not found"}), 404
        if row["status"] == "running":
            return jsonify({"ok": True, "status": "running"})
        if row["status"] == "pending":
            return jsonify({"ok": True, "status": "pending"})
        if not restart_deep(conn, task_id):
            return jsonify({"ok": False, "error": "task cannot be started from this state"}), 409
    deep_runner.clear_cancel_marker(task_id)
    return jsonify({"ok": True, "status": "pending"})


@app.get("/api/tasks/<int:task_id>")
def api_task(task_id):
    with connect() as conn:
        row = conn.execute("SELECT * FROM deep_tasks WHERE id = ?", (task_id,)).fetchone()
        if not row:
            return jsonify({"ok": False, "error": "task not found"}), 404
        task = dict(row)
        obs = conn.execute("""
            SELECT so.port, so.protocol, so.service, h.ip, h.id AS host_id
            FROM service_observations so JOIN hosts h ON h.id=so.host_id
            WHERE so.id=?
        """, (task["observation_id"],)).fetchone()
        task.update(dict(obs) if obs else {})
    task["log"] = deep_runner.task_log_tail(task_id)
    return jsonify(task)


@app.get("/api/tasks/<int:task_id>/log")
def api_task_log(task_id):
    try:
        after = int(request.args.get("after", 0) or 0)
    except (TypeError, ValueError):
        after = 0
    try:
        limit = int(request.args.get("limit", 1000) or 1000)
    except (TypeError, ValueError):
        limit = 1000
    limit = min(max(limit, 1), 5000)
    after = max(after, 0)
    with connect() as conn:
        exists = conn.execute("SELECT 1 FROM deep_tasks WHERE id=?", (task_id,)).fetchone()
        if not exists:
            return jsonify({"ok": False, "error": "task not found"}), 404
        rows = fetch_task_logs(conn, task_id, limit=limit, after_id=after)
    # File logs are live/streamed; DB fallback is intentionally lightweight.
    return jsonify({"ok": True, "task_id": task_id, "logs": rows, "text": deep_runner.task_log_tail(task_id)})


@app.route("/logs")
def logs_page():
    task_id = request.args.get("task_id", type=int)
    with connect() as conn:
        tasks = fetch_task_queue(conn, status=["running", "pending", "done", "error", "cancelled"], limit=200)
        if task_id:
            selected = conn.execute("SELECT id, chain, status FROM deep_tasks WHERE id=?", (task_id,)).fetchone()
            selected = dict(selected) if selected else None
        else:
            selected = tasks[0] if tasks else None
    log_text = deep_runner.task_log_tail(task_id or (selected["id"] if selected else 0)) if (task_id or selected) else ""
    return render_template("logs.html", tasks=tasks, selected=selected, log_text=log_text,
                           nav_hosts=[])


@app.route("/health")
def health():
    with connect() as conn:
        count = conn.execute("SELECT COUNT(*) FROM hosts").fetchone()[0]
    return {"status": "ok", "hosts": count}


def main():
    init_db()
    print("Open http://127.0.0.1:8000")
    app.run(host="127.0.0.1", port=8000, debug=False)


if __name__ == "__main__":
    main()
