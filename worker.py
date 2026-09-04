import argparse
import concurrent.futures
import json
import os
import time
from pathlib import Path
import ipaddress

from main import run_module, format_result
from database import (
    init_db,
    connect,
    get_or_create_host,
    create_scan,
    finish_scan,
    upsert_observation,
    upsert_domain,
    upsert_geo,
    upsert_finding,
    enqueue_deep,
    fetch_pending_deep,
    mark_deep_running,
    mark_deep_done,
    save_deep_result,
    utcnow,
)
from risk_engine import update_host_score, risk_level
from intelligence.geo import lookup as geo_lookup
from intelligence.dns import reverse_dns
from intelligence.tls_info import probe as tls_probe
from chains.registry import get_chains_for_service, run_chain
import deep_runner


QUEUE_FILE = Path("active_hosts.txt")
OFFSET_FILE = Path("state/worker.offset")
POLL_INTERVAL = 1.0


def log(message: str):
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {message}", flush=True)


def valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def load_offset() -> int:
    try:
        return int(OFFSET_FILE.read_text().strip())
    except (FileNotFoundError, ValueError):
        return 0


def save_offset(offset: int):
    OFFSET_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = OFFSET_FILE.with_suffix(".tmp")
    tmp.write_text(str(offset))
    os.replace(tmp, OFFSET_FILE)


def parse_line(line: str):
    """
    Формат: IP 22/tcp 80/tcp 443/tcp
    """
    parts = line.replace(",", " ").strip().split()
    if not parts:
        return None

    ip = parts[0]
    if not valid_ip(ip):
        return None

    ports = []
    for item in parts[1:]:
        if "/" not in item:
            continue
        try:
            port_s, proto = item.lower().split("/", 1)
            port = int(port_s)
            if not 1 <= port <= 65535:
                continue
            if proto not in ("tcp", "udp"):
                continue
            ports.append((port, proto))
        except ValueError:
            continue

    if not ports:
        return None

    return ip, sorted(set(ports))


# ── Network enrichment (no DB lock held) ───────────────

def fetch_ptr(ip: str) -> str | None:
    try:
        return reverse_dns(ip)
    except Exception:
        return None


def fetch_geo(ip: str) -> dict | None:
    try:
        return geo_lookup(ip)
    except Exception:
        return None


def fetch_tls(ip: str, port: int) -> tuple[dict, list]:
    """Returns (tls_info, extra_findings)."""
    try:
        info = tls_probe(ip, port)
    except Exception as exc:
        return {"ok": False, "error": str(exc), "domains": [], "cert": {}}, []

    cert = info.get("cert") or {}
    findings_extra = []

    if cert.get("expired"):
        findings_extra.append({
            "id": "cert_expired",
            "severity": 3,
            "title": "TLS certificate expired",
            "evidence": cert.get("not_after"),
        })
    elif cert.get("days_left") is not None and cert["days_left"] < 14:
        findings_extra.append({
            "id": "cert_expiring_soon",
            "severity": 2,
            "title": "TLS certificate expiring soon",
            "evidence": f"{cert['days_left']} days left",
        })

    if info.get("tls_version") in ("TLSv1", "TLSv1.1"):
        findings_extra.append({
            "id": "legacy_tls",
            "severity": 3,
            "title": "Legacy TLS version",
            "evidence": info["tls_version"],
        })

    return info, findings_extra


# ── Process one host ───────────────────────────────────

def process_host(ip: str, ports: list):
    log(f"[*] Processing {ip} ({len(ports)} ports)")

    # Network I/O first — no DB connection held
    ptr = fetch_ptr(ip)
    if ptr:
        log(f"    domain (ptr): {ptr}")

    geo = fetch_geo(ip)
    if geo:
        loc = ", ".join(
            filter(None, [geo.get("city"), geo.get("region"), geo.get("country")])
        )
        log(f"    geo: {loc} | {geo.get('asn')} {geo.get('org') or ''}")
    else:
        log("    geo: lookup failed")

    # Port scans (network) — collect results, then write DB in one short transaction
    scan_results = []  # list of (port, proto, data, tls_info, tls_findings)

    for port, proto in ports:
        try:
            data = run_module(ip, port, proto)
            print(format_result(ip, data), flush=True)

            tls_info, tls_findings = {}, []
            service = (data.get("service") or "").lower()
            if service == "https" or (proto == "tcp" and port in (443, 8443, 9443)):
                tls_info, tls_findings = fetch_tls(ip, port)
                for name in tls_info.get("domains") or []:
                    log(f"    domain (cert): {name}")

            scan_results.append((port, proto, data, tls_info, tls_findings))
        except Exception as exc:
            log(f"[!] {ip}:{port}/{proto}: {type(exc).__name__}: {exc}")

    # Short DB transaction
    host_id = None
    with connect() as conn:
        host_id = get_or_create_host(conn, ip)
        scan_id = create_scan(conn, host_id, source="worker")

        if ptr:
            upsert_domain(conn, host_id, ptr, source="ptr")
        if geo:
            upsert_geo(conn, host_id, geo)

        for port, proto, data, tls_info, tls_findings in scan_results:
            obs_id = upsert_observation(conn, scan_id, host_id, data)

            for item in data.get("findings") or []:
                upsert_finding(conn, host_id, obs_id, item)

            for name in (tls_info or {}).get("domains") or []:
                upsert_domain(conn, host_id, name, source="cert")

            for item in tls_findings or []:
                upsert_finding(conn, host_id, obs_id, item)

            service = (data.get("service") or "").lower()
            for chain in get_chains_for_service(service):
                # heavy chains — ниже priority, чтобы лёгкие не ждали
                priority = 0 if deep_runner.is_heavy(chain) else 10
                enqueue_deep(conn, obs_id, chain, priority=priority)
                log(f"    queued deep: {chain} (obs={obs_id}, prio={priority})")

        finish_scan(conn, scan_id, status="done")

        try:
            score = update_host_score(host_id, conn=conn)
            level = risk_level(score)
            log(f"[RISK] {ip}: {score}/100 [{level}]")
        except Exception as exc:
            log(f"[!] Risk calculation failed for {ip}: {exc}")

    # Deep tasks after connection is closed
    run_pending_deep()

    log(f"[*] Finished {ip}")


def _build_ctx(conn, obs_id: int) -> dict | None:
    """Собирает ctx для deep-цепочки. Вызывается под DB-локом"""
    row = conn.execute(
        """
        SELECT so.*, h.ip
        FROM service_observations so
        JOIN hosts h ON h.id = so.host_id
        WHERE so.id = ?
        """,
        (obs_id,),
    ).fetchone()

    if not row:
        return None

    row = dict(row)

    domains = [
        r["name"]
        for r in conn.execute(
            "SELECT name FROM domains WHERE host_id = ?",
            (row["host_id"],),
        ).fetchall()
    ]

    geo_row = conn.execute(
        "SELECT * FROM geo WHERE host_id = ?",
        (row["host_id"],),
    ).fetchone()
    geo = dict(geo_row) if geo_row else None

    raw = {}
    if row.get("raw_json"):
        try:
            raw = json.loads(row["raw_json"])
        except Exception:
            pass

    return {
        "ip": row["ip"],
        "port": row["port"],
        "protocol": row["protocol"],
        "service": row["service"],
        "version": row["version"],
        "banner": row["banner"],
        "observation_id": obs_id,
        "host_id": row["host_id"],
        "domains": domains,
        "geo": geo,
        "raw": raw,
    }


def _run_one_deep(task: dict) -> tuple[int, int, str, dict | None, str | None]:
    """
    Выполняется в пуле потоков.
    Возвращает: (task_id, obs_id, chain, result, error)

    Тяжёлые bash-цепочки внутри run_chain должны звать deep_runner.run_bash()
    — тогда timeout реально убивает process group.
    """
    task_id = task["id"]
    obs_id = task["observation_id"]
    chain = task["chain"]
    ctx = task.get("_ctx")

    if ctx is None:
        return task_id, obs_id, chain, None, "observation not found / no ctx"

    heavy = deep_runner.is_heavy(chain)
    tag = "heavy" if heavy else "light"
    log(f"    deep start: {chain} [{tag}] (obs={obs_id}, ip={ctx.get('ip')}:{ctx.get('port')})")
    t0 = time.monotonic()
    try:
        result = run_chain(chain, ctx)
        dt = time.monotonic() - t0
        log(f"    deep finish: {chain} ({dt:.1f}s)")
        return task_id, obs_id, chain, result, None
    except Exception as exc:
        log(f"    deep exception: {chain} (obs={obs_id}): {exc}")
        return task_id, obs_id, chain, None, str(exc)


def run_pending_deep(limit: int | None = None):
    """
    Забирает pending deep-задачи, готовит ctx под DB-локом,
    запускает в deep_runner pool (лимит workers + bash_limit),
    сохраняет результаты.
    """
    if limit is None:
        limit = deep_runner.DEEP_BATCH

    deep_runner.start()

    with connect() as conn:
        tasks = [dict(t) for t in fetch_pending_deep(conn, limit=limit)]

        if not tasks:
            return

        prepared = []
        for task in tasks:
            task_id = task["id"]
            obs_id = task["observation_id"]
            chain = task["chain"]

            try:
                mark_deep_running(conn, task_id)
                ctx = _build_ctx(conn, obs_id)
                if ctx is None:
                    mark_deep_done(conn, task_id, error="observation not found")
                    continue
                task["_ctx"] = ctx
                prepared.append(task)
            except Exception as exc:
                try:
                    mark_deep_done(conn, task_id, error=str(exc))
                except Exception:
                    pass
                log(f"    deep prepare fail: {chain}: {exc}")

    if not prepared:
        return

    cfg = deep_runner.stats()
    log(
        f"[*] Running {len(prepared)} deep task(s) "
        f"(workers={cfg['workers']}, bash_limit={cfg['bash_limit']}, "
        f"timeout={cfg['timeout']}s)"
    )

    futures = {
        deep_runner.submit(_run_one_deep, task): task
        for task in prepared
    }

    for future in concurrent.futures.as_completed(futures):
        task = futures[future]
        task_id = task["id"]
        obs_id = task["observation_id"]
        chain = task["chain"]
        # Страховка: если handler завис без run_bash — future timeout.
        # Для run_bash kill сработает раньше, внутри.
        timeout = deep_runner.DEEP_TIMEOUT + 15

        try:
            task_id, obs_id, chain, result, error = future.result(timeout=timeout)

            with connect() as conn:
                if error:
                    mark_deep_done(conn, task_id, error=error)
                    log(f"    deep fail: {chain} (obs={obs_id}): {error}")
                else:
                    save_deep_result(conn, task_id, obs_id, chain, result)
                    if isinstance(result, dict):
                        for k, v in result.items():
                            if k == chain:
                                continue
                            try:
                                save_deep_result(conn, task_id, obs_id, str(k), v)
                            except Exception:
                                pass
                    mark_deep_done(conn, task_id)
                    log(f"    deep ok: {chain} (obs={obs_id})")

        except concurrent.futures.TimeoutError:
            try:
                with connect() as conn:
                    mark_deep_done(
                        conn, task_id,
                        error=f"timeout after {deep_runner.DEEP_TIMEOUT}s",
                    )
            except Exception:
                pass
            log(f"    deep timeout: {chain} (obs={obs_id})")

        except Exception as exc:
            try:
                with connect() as conn:
                    mark_deep_done(conn, task_id, error=str(exc))
            except Exception:
                pass
            log(f"    deep fail: {chain} (obs={obs_id}): {exc}")


def process_line(line: str):
    line = line.strip()
    if not line:
        return

    log(f"[*] Queue item: {line}")
    parsed = parse_line(line)
    if parsed is None:
        log(f"[!] Skipping invalid queue item: {line}")
        return

    ip, ports = parsed
    log(f"[*] Parsed: {ip} -> {', '.join(f'{p}/{pr}' for p, pr in ports)}")
    process_host(ip, ports)


def worker():
    OFFSET_FILE.parent.mkdir(parents=True, exist_ok=True)
    offset = load_offset()

    cfg = deep_runner.stats()
    log("[*] Worker started")
    log(f"[*] Queue: {QUEUE_FILE}")
    log(f"[*] Offset: {offset}")
    log(
        f"[*] Deep pool: workers={cfg['workers']}, "
        f"bash_limit={cfg['bash_limit']}, timeout={cfg['timeout']}s, "
        f"batch={cfg['batch']}"
    )

    while True:
        if not QUEUE_FILE.exists():
            run_pending_deep()
            time.sleep(POLL_INTERVAL)
            continue

        try:
            with QUEUE_FILE.open("r", encoding="utf-8") as queue:
                queue.seek(0, os.SEEK_END)
                file_size = queue.tell()

                if offset > file_size:
                    log("[!] Queue file truncated; resetting offset")
                    offset = 0

                queue.seek(offset)

                while True:
                    line = queue.readline()
                    if not line:
                        break

                    new_offset = queue.tell()
                    if not line.endswith("\n"):
                        break

                    try:
                        process_line(line)
                        offset = new_offset
                        save_offset(offset)
                    except Exception as exc:
                        log(f"[!] Failed to process line: {exc}")
                        time.sleep(POLL_INTERVAL)
                        break

        except OSError as exc:
            log(f"[!] Queue read error: {exc}")

        run_pending_deep()
        time.sleep(POLL_INTERVAL)


def main():
    parser = argparse.ArgumentParser(description="Active Host Recon worker")
    parser.add_argument("--reset", action="store_true", help="Reset worker offset")
    parser.add_argument(
        "--deep-workers", type=int, default=None,
        help="Python thread pool size for deep tasks (env DEEP_WORKERS, default 4)",
    )
    parser.add_argument(
        "--bash-limit", type=int, default=None,
        help="Max concurrent bash/subprocess chains (env DEEP_BASH_LIMIT, default 2)",
    )
    parser.add_argument(
        "--deep-timeout", type=int, default=None,
        help="Timeout per deep task in seconds (env DEEP_TIMEOUT, default 300)",
    )
    parser.add_argument(
        "--deep-batch", type=int, default=None,
        help="How many pending deep tasks to claim per cycle (env DEEP_BATCH, default 20)",
    )
    args = parser.parse_args()

    deep_runner.configure(
        workers=args.deep_workers,
        bash_limit=args.bash_limit,
        timeout=args.deep_timeout,
        batch=args.deep_batch,
    )

    if args.reset:
        save_offset(0)
        log("[*] Worker offset reset")

    init_db()
    deep_runner.start()
    try:
        worker()
    finally:
        deep_runner.shutdown(wait=True)


if __name__ == "__main__":
    main()
