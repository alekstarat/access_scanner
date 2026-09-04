"""
Host-centric domain model

Единая точка, через которую можно получить ПОЛНУЮ картину по хосту
и каждому сервису (primary scan + deep chains + findings + geo + domains)

Использование:
    from models import HostProfile, get_host_by_ip, get_host_by_id

    host = get_host_by_ip("1.2.3.4")
    print(host.to_dict())          # полный JSON-ready снимок
    for svc in host.services:
        print(svc.port, svc.service, svc.deep)
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from typing import Any, Optional

from database import connect


# ──────────────────────────────────────────────────────────────
# Dataclasses
# ──────────────────────────────────────────────────────────────

@dataclass
class Finding:
    id: Optional[int]
    key: str
    severity: int
    title: str
    description: str = ""
    evidence: str = ""
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    observation_id: Optional[int] = None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class DeepResult:
    key: str
    value: Any
    task_id: Optional[int] = None
    created_at: Optional[str] = None
    chain: Optional[str] = None  # имя цепочки, если известно

    def to_dict(self) -> dict:
        return {
            "key": self.key,
            "value": self.value,
            "task_id": self.task_id,
            "created_at": self.created_at,
            "chain": self.chain,
        }


@dataclass
class DeepTask:
    id: int
    chain: str
    status: str
    priority: int = 0
    created_at: Optional[str] = None
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    error: Optional[str] = None
    results: list[DeepResult] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["results"] = [r.to_dict() for r in self.results]
        return d


@dataclass
class Service:
    observation_id: int
    port: int
    protocol: str
    service: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    raw: dict = field(default_factory=dict)          # полный raw_json от сканера
    observations: dict = field(default_factory=dict) # удобный доступ к obs
    findings: list[Finding] = field(default_factory=list)
    deep_tasks: list[DeepTask] = field(default_factory=list)
    deep: dict = field(default_factory=dict)         # aggregated deep results by key/chain

    @property
    def key(self) -> str:
        return f"{self.port}/{self.protocol}"

    def to_dict(self) -> dict:
        return {
            "observation_id": self.observation_id,
            "port": self.port,
            "protocol": self.protocol,
            "service": self.service,
            "version": self.version,
            "banner": self.banner,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "observations": self.observations,
            "findings": [f.to_dict() for f in self.findings],
            "deep_tasks": [t.to_dict() for t in self.deep_tasks],
            "deep": self.deep,
            # raw оставляем опционально — может быть большим
            "raw": self.raw,
        }


@dataclass
class Domain:
    name: str
    source: str
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Geo:
    country: Optional[str] = None
    country_code: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    lat: Optional[float] = None
    lon: Optional[float] = None
    asn: Optional[str] = None
    org: Optional[str] = None
    isp: Optional[str] = None
    source: Optional[str] = None
    looked_up_at: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class HostProfile:
    id: int
    ip: str
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    risk_score: int = 0
    domains: list[Domain] = field(default_factory=list)
    geo: Optional[Geo] = None
    services: list[Service] = field(default_factory=list)
    # findings, которые не привязаны к конкретному observation (если такие появятся)
    host_findings: list[Finding] = field(default_factory=list)

    def service_by_port(self, port: int, protocol: str = "tcp") -> Optional[Service]:
        for s in self.services:
            if s.port == port and s.protocol == protocol:
                return s
        return None

    def services_by_name(self, name: str) -> list[Service]:
        name = (name or "").lower()
        return [s for s in self.services if (s.service or "").lower() == name]

    def all_findings(self) -> list[Finding]:
        out = list(self.host_findings)
        for s in self.services:
            out.extend(s.findings)
        return out

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "ip": self.ip,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "risk_score": self.risk_score,
            "domains": [d.to_dict() for d in self.domains],
            "geo": self.geo.to_dict() if self.geo else None,
            "services": [s.to_dict() for s in self.services],
            "host_findings": [f.to_dict() for f in self.host_findings],
            "summary": {
                "ports_open": len(self.services),
                "services": sorted({(s.service or "unknown") for s in self.services}),
                "findings_count": len(self.all_findings()),
                "max_severity": max((f.severity for f in self.all_findings()), default=0),
            },
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False, default=str)


# ──────────────────────────────────────────────────────────────
# Loaders
# ──────────────────────────────────────────────────────────────

def _parse_raw(raw_json: Optional[str]) -> dict:
    if not raw_json:
        return {}
    try:
        return json.loads(raw_json)
    except Exception:
        return {"_parse_error": True, "raw": raw_json}


def _load_services(conn, host_id: int) -> list[Service]:
    rows = conn.execute(
        """
        SELECT * FROM service_observations
        WHERE host_id = ?
        ORDER BY port, protocol
        """,
        (host_id,),
    ).fetchall()

    services: list[Service] = []
    for row in rows:
        obs_id = row["id"]
        raw = _parse_raw(row["raw_json"])
        observations = raw.get("observations") or {}

        # findings для этого observation
        finding_rows = conn.execute(
            """
            SELECT * FROM findings
            WHERE observation_id = ?
            ORDER BY severity DESC, id
            """,
            (obs_id,),
        ).fetchall()
        findings = [
            Finding(
                id=f["id"],
                key=f["finding_key"],
                severity=f["severity"],
                title=f["title"] or "",
                description=f["description"] or "",
                evidence=f["evidence"] or "",
                first_seen=f["first_seen"],
                last_seen=f["last_seen"],
                observation_id=obs_id,
            )
            for f in finding_rows
        ]

        # deep tasks + results
        task_rows = conn.execute(
            """
            SELECT * FROM deep_tasks
            WHERE observation_id = ?
            ORDER BY id
            """,
            (obs_id,),
        ).fetchall()

        deep_tasks: list[DeepTask] = []
        deep_agg: dict[str, Any] = {}

        for t in task_rows:
            res_rows = conn.execute(
                """
                SELECT * FROM deep_results
                WHERE task_id = ?
                ORDER BY id
                """,
                (t["id"],),
            ).fetchall()
            results = []
            for r in res_rows:
                try:
                    value = json.loads(r["value_json"])
                except Exception:
                    value = r["value_json"]
                dr = DeepResult(
                    key=r["key"],
                    value=value,
                    task_id=r["task_id"],
                    created_at=r["created_at"],
                    chain=t["chain"],
                )
                results.append(dr)
                # агрегируем удобный доступ: deep[chain][key] = value
                # и deep[key] = value (последний побеждает)
                chain_bucket = deep_agg.setdefault(t["chain"], {})
                if isinstance(chain_bucket, dict):
                    chain_bucket[r["key"]] = value
                deep_agg[r["key"]] = value

            deep_tasks.append(
                DeepTask(
                    id=t["id"],
                    chain=t["chain"],
                    status=t["status"],
                    priority=t["priority"] or 0,
                    created_at=t["created_at"],
                    started_at=t["started_at"],
                    finished_at=t["finished_at"],
                    error=t["error"],
                    results=results,
                )
            )

        services.append(
            Service(
                observation_id=obs_id,
                port=row["port"],
                protocol=row["protocol"],
                service=row["service"],
                version=row["version"],
                banner=row["banner"],
                first_seen=row["first_seen"],
                last_seen=row["last_seen"],
                raw=raw,
                observations=observations,
                findings=findings,
                deep_tasks=deep_tasks,
                deep=deep_agg,
            )
        )
    return services


def get_host_by_id(host_id: int, conn=None) -> Optional[HostProfile]:
    """Полный профиль хоста по id."""
    own_conn = conn is None
    if own_conn:
        conn = connect()
    try:
        row = conn.execute("SELECT * FROM hosts WHERE id = ?", (host_id,)).fetchone()
        if not row:
            return None

        # domains
        domain_rows = conn.execute(
            "SELECT * FROM domains WHERE host_id = ? ORDER BY name",
            (host_id,),
        ).fetchall()
        domains = [
            Domain(
                name=d["name"],
                source=d["source"],
                first_seen=d["first_seen"],
                last_seen=d["last_seen"],
            )
            for d in domain_rows
        ]

        # geo
        geo_row = conn.execute(
            "SELECT * FROM geo WHERE host_id = ?", (host_id,)
        ).fetchone()
        geo = None
        if geo_row:
            geo = Geo(
                country=geo_row["country"],
                country_code=geo_row["country_code"],
                region=geo_row["region"],
                city=geo_row["city"],
                lat=geo_row["lat"],
                lon=geo_row["lon"],
                asn=geo_row["asn"],
                org=geo_row["org"],
                isp=geo_row["isp"],
                source=geo_row["source"],
                looked_up_at=geo_row["looked_up_at"],
            )

        # host-level findings (observation_id IS NULL) — на будущее
        host_finding_rows = conn.execute(
            """
            SELECT * FROM findings
            WHERE host_id = ? AND observation_id IS NULL
            ORDER BY severity DESC, id
            """,
            (host_id,),
        ).fetchall()
        host_findings = [
            Finding(
                id=f["id"],
                key=f["finding_key"],
                severity=f["severity"],
                title=f["title"] or "",
                description=f["description"] or "",
                evidence=f["evidence"] or "",
                first_seen=f["first_seen"],
                last_seen=f["last_seen"],
                observation_id=None,
            )
            for f in host_finding_rows
        ]

        services = _load_services(conn, host_id)

        return HostProfile(
            id=row["id"],
            ip=row["ip"],
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
            risk_score=row["risk_score"] or 0,
            domains=domains,
            geo=geo,
            services=services,
            host_findings=host_findings,
        )
    finally:
        if own_conn:
            conn.close()


def get_host_by_ip(ip: str, conn=None) -> Optional[HostProfile]:
    """Полный профиль хоста по IP."""
    own_conn = conn is None
    if own_conn:
        conn = connect()
    try:
        row = conn.execute("SELECT id FROM hosts WHERE ip = ?", (ip,)).fetchone()
        if not row:
            return None
        return get_host_by_id(row["id"], conn=conn)
    finally:
        if own_conn:
            conn.close()


def list_hosts(
    limit: int = 100,
    offset: int = 0,
    order_by: str = "risk_score DESC, last_seen DESC",
    conn=None,
) -> list[HostProfile]:
    """Список хостов (полные профили). Для больших БД лучше использовать list_host_summaries."""
    own_conn = conn is None
    if own_conn:
        conn = connect()
    try:
        # безопасный whitelist сортировки
        allowed = {
            "risk_score DESC, last_seen DESC",
            "risk_score ASC",
            "last_seen DESC",
            "ip ASC",
            "id DESC",
        }
        if order_by not in allowed:
            order_by = "risk_score DESC, last_seen DESC"

        rows = conn.execute(
            f"SELECT id FROM hosts ORDER BY {order_by} LIMIT ? OFFSET ?",
            (limit, offset),
        ).fetchall()
        return [get_host_by_id(r["id"], conn=conn) for r in rows]
    finally:
        if own_conn:
            conn.close()


def list_host_summaries(
    limit: int = 200,
    offset: int = 0,
    conn=None,
) -> list[dict]:
    own_conn = conn is None
    if own_conn:
        conn = connect()
    try:
        rows = conn.execute(
            """
            SELECT
                h.id,
                h.ip,
                h.first_seen,
                h.last_seen,
                h.risk_score,
                (SELECT COUNT(*) FROM service_observations so WHERE so.host_id = h.id) AS ports,
                (SELECT COUNT(*) FROM findings f WHERE f.host_id = h.id) AS findings,
                (SELECT GROUP_CONCAT(so.service) FROM service_observations so
                 WHERE so.host_id = h.id AND so.service IS NOT NULL) AS services
            FROM hosts h
            ORDER BY h.risk_score DESC, h.last_seen DESC
            LIMIT ? OFFSET ?
            """,
            (limit, offset),
        ).fetchall()
        result = []
        for r in rows:
            result.append({
                "id": r["id"],
                "ip": r["ip"],
                "first_seen": r["first_seen"],
                "last_seen": r["last_seen"],
                "risk_score": r["risk_score"] or 0,
                "ports": r["ports"] or 0,
                "findings": r["findings"] or 0,
                "services": sorted(set(filter(None, (r["services"] or "").split(",")))),
            })
        return result
    finally:
        if own_conn:
            conn.close()
