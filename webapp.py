"""
Local web UI (Flask) — Access Scanner design.
Run from project root:
    python -m web.webapp
Open:
    http://127.0.0.1:8088
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from flask import Flask, abort, render_template, request, url_for

from database import connect, init_db

app = Flask(
    __name__,
    template_folder=str(Path(__file__).parent / "templates"),
    static_folder=str(Path(__file__).parent / "static"),
)

SEVERITY_NAMES = {0: "INFO", 1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}
SEVERITY_CLASS = {0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical"}


def rowdict(row):
    return dict(row) if row else None


def parse_json(value):
    if not value:
        return {}
    try:
        return json.loads(value)
    except Exception:
        return {"raw": value}


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


def list_host_ids(conn):
    """Ordered id list for prev/next navigation (risk desc)."""
    return [
        r["id"]
        for r in conn.execute(
            "SELECT id FROM hosts ORDER BY risk_score DESC, last_seen DESC, id DESC"
        ).fetchall()
    ]


def build_host_chain(conn, host_id):
    events = []

    host = conn.execute("SELECT * FROM hosts WHERE id = ?", (host_id,)).fetchone()
    if not host:
        return None, []

    events.append({
        "kind": "host",
        "timestamp": host["first_seen"],
        "title": "Host discovered",
        "subtitle": host["ip"],
        "icon": "◉",
        "severity": None,
        "data": {
            "first_seen": host["first_seen"],
            "last_seen": host["last_seen"],
            "risk_score": host["risk_score"],
        },
    })

    geo = conn.execute("SELECT * FROM geo WHERE host_id = ?", (host_id,)).fetchone()
    if geo:
        location = ", ".join(
            x for x in [geo["city"], geo["region"], geo["country"]] if x
        )
        events.append({
            "kind": "geo",
            "timestamp": geo["looked_up_at"],
            "title": "Geo / network intelligence",
            "subtitle": location or geo["org"] or geo["isp"] or "Location data",
            "icon": "◎",
            "severity": None,
            "data": {
                "country": geo["country"],
                "region": geo["region"],
                "city": geo["city"],
                "asn": geo["asn"],
                "org": geo["org"],
                "isp": geo["isp"],
                "source": geo["source"],
                "lat": geo["lat"],
                "lon": geo["lon"],
            },
        })

    domains = conn.execute(
        """
        SELECT * FROM domains WHERE host_id = ?
        ORDER BY first_seen ASC, id ASC
        """,
        (host_id,),
    ).fetchall()
    for d in domains:
        events.append({
            "kind": "domain",
            "timestamp": d["first_seen"],
            "title": "Domain identified",
            "subtitle": d["name"],
            "icon": "⌁",
            "severity": None,
            "data": {
                "source": d["source"],
                "first_seen": d["first_seen"],
                "last_seen": d["last_seen"],
            },
        })

    observations = conn.execute(
        """
        SELECT so.*, s.started_at AS scan_started, s.finished_at AS scan_finished
        FROM service_observations so
        LEFT JOIN scans s ON s.id = so.scan_id
        WHERE so.host_id = ?
        ORDER BY so.last_seen ASC, so.id ASC
        """,
        (host_id,),
    ).fetchall()

    for obs in observations:
        service_label = obs["service"] or "unknown"
        endpoint = f'{obs["port"]}/{obs["protocol"]}'
        raw = parse_json(obs["raw_json"])

        events.append({
            "kind": "service",
            "timestamp": obs["last_seen"],
            "title": f"{service_label.upper()} service observed",
            "subtitle": endpoint,
            "icon": "◌",
            "severity": None,
            "data": {
                "port": obs["port"],
                "protocol": obs["protocol"],
                "service": obs["service"],
                "version": obs["version"],
                "banner": obs["banner"],
                "first_seen": obs["first_seen"],
                "last_seen": obs["last_seen"],
                "observations": raw.get("observations", {}),
            },
        })

        findings = conn.execute(
            """
            SELECT * FROM findings
            WHERE observation_id = ?
            ORDER BY severity DESC, id ASC
            """,
            (obs["id"],),
        ).fetchall()

        for f in findings:
            sev = int(f["severity"] or 0)
            events.append({
                "kind": "finding",
                "timestamp": f["last_seen"],
                "title": f["title"],
                "subtitle": f["finding_key"],
                "icon": "!",
                "severity": sev,
                "data": {
                    "description": f["description"],
                    "evidence": f["evidence"],
                    "first_seen": f["first_seen"],
                    "last_seen": f["last_seen"],
                    "port": obs["port"],
                    "protocol": obs["protocol"],
                    "service": obs["service"],
                },
            })

        tasks = conn.execute(
            """
            SELECT * FROM deep_tasks
            WHERE observation_id = ?
            ORDER BY created_at ASC, id ASC
            """,
            (obs["id"],),
        ).fetchall()

        for task in tasks:
            events.append({
                "kind": "deep_task",
                "timestamp": task["finished_at"] or task["created_at"],
                "title": f"Deep chain: {task['chain']}",
                "subtitle": task["status"],
                "icon": "↳",
                "severity": None,
                "data": {
                    "status": task["status"],
                    "priority": task["priority"],
                    "created_at": task["created_at"],
                    "started_at": task["started_at"],
                    "finished_at": task["finished_at"],
                    "error": task["error"],
                },
            })

            results = conn.execute(
                """
                SELECT * FROM deep_results
                WHERE task_id = ?
                ORDER BY created_at ASC, id ASC
                """,
                (task["id"],),
            ).fetchall()

            for r in results:
                value = parse_json(r["value_json"])
                events.append({
                    "kind": "deep_result",
                    "timestamp": r["created_at"],
                    "title": f"Deep result: {r['key']}",
                    "subtitle": task["chain"],
                    "icon": "↳",
                    "severity": None,
                    "data": {
                        "observation_id": r["observation_id"],
                        "task_id": r["task_id"],
                        "value": value,
                    },
                })

    events.sort(key=lambda e: (e["timestamp"] or "", e["kind"]))
    return rowdict(host), events


@app.route("/")
def index():
    q = request.args.get("q", "").strip()
    service = request.args.get("service", "").strip().lower()
    risk = request.args.get("risk", "").strip().lower()
    country = request.args.get("country", "").strip()
    has_domain = request.args.get("has_domain", "").strip()

    with connect() as conn:
        # filter options
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
                   (SELECT COUNT(*) FROM domains d WHERE d.host_id = h.id) AS domain_count
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
            sql += """
                AND EXISTS (SELECT 1 FROM domains d WHERE d.host_id = h.id)
            """
        elif has_domain == "0":
            sql += """
                AND NOT EXISTS (SELECT 1 FROM domains d WHERE d.host_id = h.id)
            """

        if risk == "critical":
            sql += " AND h.risk_score >= 70"
        elif risk == "high":
            sql += " AND h.risk_score >= 40 AND h.risk_score < 70"
        elif risk == "medium":
            sql += " AND h.risk_score >= 20 AND h.risk_score < 40"
        elif risk == "low":
            sql += " AND h.risk_score < 20"

        sql += " ORDER BY h.risk_score DESC, h.last_seen DESC LIMIT 500"

        hosts = conn.execute(sql, params).fetchall()

        stats = {
            "hosts": conn.execute("SELECT COUNT(*) FROM hosts").fetchone()[0],
            "services": conn.execute(
                "SELECT COUNT(*) FROM service_observations"
            ).fetchone()[0],
            "findings": conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0],
            "critical": conn.execute(
                "SELECT COUNT(*) FROM findings WHERE severity >= 4"
            ).fetchone()[0],
        }

        # compact sidebar list (same filters, lighter fields)
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
        services=services,
        countries=countries,
        nav_hosts=nav_hosts,
    )


@app.route("/host/<int:host_id>")
def host_detail(host_id):
    with connect() as conn:
        host, events = build_host_chain(conn, host_id)
        if not host:
            abort(404)

        geo = rowdict(
            conn.execute("SELECT * FROM geo WHERE host_id = ?", (host_id,)).fetchone()
        )

        domains = conn.execute(
            """
            SELECT * FROM domains WHERE host_id = ?
            ORDER BY source, name
            """,
            (host_id,),
        ).fetchall()

        services = conn.execute(
            """
            SELECT * FROM service_observations
            WHERE host_id = ?
            ORDER BY port ASC, protocol ASC
            """,
            (host_id,),
        ).fetchall()

        findings = conn.execute(
            """
            SELECT f.*, so.port, so.protocol, so.service
            FROM findings f
            LEFT JOIN service_observations so ON so.id = f.observation_id
            WHERE f.host_id = ?
            ORDER BY f.severity DESC, f.last_seen DESC
            """,
            (host_id,),
        ).fetchall()

        ids = list_host_ids(conn)
        try:
            idx = ids.index(host_id)
        except ValueError:
            idx = -1
        prev_id = ids[idx - 1] if idx > 0 else None
        next_id = ids[idx + 1] if 0 <= idx < len(ids) - 1 else None

        # sidebar: nearby hosts in list order
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
                by_id = {r["id"]: r for r in rows}
                nav_hosts = [by_id[i] for i in slice_ids if i in by_id]

    return render_template(
        "host.html",
        host=host,
        geo=geo,
        domains=domains,
        events=events,
        services=services,
        findings=findings,
        prev_id=prev_id,
        next_id=next_id,
        nav_hosts=nav_hosts,
    )


@app.route("/health")
def health():
    with connect() as conn:
        count = conn.execute("SELECT COUNT(*) FROM hosts").fetchone()[0]
    return {"status": "ok", "hosts": count}


def main():
    init_db()
    print("Open http://127.0.0.1:8088")
    app.run(host="127.0.0.1", port=8088, debug=False)


if __name__ == "__main__":
    main()