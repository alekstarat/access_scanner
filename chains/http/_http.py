"""
HTTP deep helpers.

Долгие bash-скрипты (ffuf) — только через deep_runner.run_bash.
stdout скрипта = один JSON-объект с полем results[].
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from deep_runner import run_bash, DEEP_TIMEOUT

log = logging.getLogger(__name__)

SCRIPT = Path(__file__).resolve().parent / "search_dirs.sh"
FFUF_TIMEOUT = min(180, DEEP_TIMEOUT)

# сколько доменов максимум фузить за одну https_dirs задачу
MAX_DOMAINS_PER_TASK = 3


def _parse_ffuf_stdout(stdout: str) -> dict[str, Any]:
    """Достаёт JSON из stdout (скрипт печатает один объект)."""
    text = (stdout or "").strip()
    if not text:
        return {"ok": False, "error": "empty stdout", "results": [], "count": 0}

    # на всякий случай — если вдруг мусор до/после JSON
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    start = text.find("{")
    end = text.rfind("}")
    if start >= 0 and end > start:
        try:
            return json.loads(text[start : end + 1])
        except json.JSONDecodeError as e:
            return {
                "ok": False,
                "error": f"json parse: {e}",
                "results": [],
                "count": 0,
                "raw": text[:2000],
            }
    return {
        "ok": False,
        "error": "no json in stdout",
        "results": [],
        "count": 0,
        "raw": text[:2000],
    }


def _interesting_paths(results: list[dict]) -> list[dict]:
    """Короткая выжимка для UI / findings."""
    out = []
    for r in results[:100]:
        out.append({
            "path": r.get("path"),
            "status": r.get("status"),
            "length": r.get("length"),
            "url": r.get("url"),
            "redirect": r.get("redirectlocation") or None,
        })
    return out


def search_dirs(
    ip: str,
    port: int,
    tls: bool = False,
    host_header: str | None = None,
    target_host: str | None = None,
) -> dict:
    """
    Запуск search_dirs.sh (ffuf) по IP или hostname.

    target_host — что подставлять в URL (IP или домен).
    host_header — опциональный Host: для виртуальных хостов на IP.
    """
    if not SCRIPT.is_file():
        return {"ok": False, "error": f"script not found: {SCRIPT}", "results": [], "count": 0}

    host = target_host or ip
    cmd = [str(SCRIPT), "-i", str(host), "-p", str(port)]
    if tls:
        cmd.append("--tls")
    if host_header:
        cmd.extend(["-H", str(host_header)])

    log.info("search_dirs: %s", " ".join(cmd))
    result = run_bash(cmd, timeout=FFUF_TIMEOUT)

    parsed = _parse_ffuf_stdout(result.get("stdout") or "")

    # если скрипт упал до JSON — отразим
    if result.get("error") and not parsed.get("results"):
        parsed.setdefault("ok", False)
        parsed["error"] = result["error"]
        parsed.setdefault("results", [])
        parsed.setdefault("count", 0)

    parsed["duration"] = result.get("duration")
    parsed["runner_returncode"] = result.get("returncode")
    parsed["target"] = host
    parsed["port"] = port
    parsed["tls"] = tls
    if host_header:
        parsed["host_header"] = host_header

    # удобная выжимка
    results = parsed.get("results") or []
    parsed["interesting"] = _interesting_paths(results)
    parsed["count"] = parsed.get("count") if parsed.get("count") is not None else len(results)

    # не тащим огромный raw stderr progress в БД
    if "stderr" in parsed and len(str(parsed["stderr"])) > 500:
        parsed["stderr"] = str(parsed["stderr"])[:500]

    return parsed


def _looks_like_domain(name: str) -> bool:
    if not name or not isinstance(name, str):
        return False
    name = name.strip().lower().rstrip(".")
    if not name or " " in name:
        return False
    # отсекаем IP
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", name):
        return False
    if ":" in name and not name.startswith("["):  # грубо
        return False
    return "." in name or name in ("localhost",)


def pick_domains(ctx: dict, limit: int = MAX_DOMAINS_PER_TASK) -> list[str]:
    """Домены из ctx.domains + raw/cert, уникальные, без IP."""
    found: list[str] = []
    seen: set[str] = set()

    def add(name: str | None):
        if not name:
            return
        name = name.strip().lower().rstrip(".")
        if not _looks_like_domain(name):
            return
        if name in seen:
            return
        seen.add(name)
        found.append(name)

    for d in ctx.get("domains") or []:
        if isinstance(d, dict):
            add(d.get("name"))
        else:
            add(str(d))

    raw = ctx.get("raw") or {}
    obs = raw.get("observations") or {}
    for key in ("host", "hostname", "server_name", "cn"):
        add(obs.get(key) if isinstance(obs, dict) else None)

    # tls domains иногда лежат в geo? нет — в deep tls или raw
    for key in ("domains", "sans"):
        val = obs.get(key) if isinstance(obs, dict) else None
        if isinstance(val, list):
            for x in val:
                add(str(x))

    return found[:limit]


def search_dirs_by_domain(ctx: dict) -> dict:
    """
    https_dirs / domain-aware fuzz:
    для каждого известного домена — ffuf по https://domain:port/FUZZ
    (или http, если сервис http).
    """
    ip = ctx.get("ip")
    port = int(ctx.get("port") or (443 if (ctx.get("service") or "").lower() == "https" else 80))
    service = (ctx.get("service") or "").lower()
    tls = service == "https" or port in (443, 8443, 9443)

    domains = pick_domains(ctx)
    if not domains:
        return {
            "ok": False,
            "skipped": True,
            "reason": "no domains known for host",
            "results": [],
            "count": 0,
            "by_domain": {},
        }

    by_domain: dict[str, Any] = {}
    all_interesting: list[dict] = []

    for domain in domains:
        # бьём по имени хоста в URL (SNI + Host для TLS)
        one = search_dirs(
            ip=ip,
            port=port,
            tls=tls,
            target_host=domain,
            host_header=None,
        )
        by_domain[domain] = {
            "ok": one.get("ok"),
            "count": one.get("count", 0),
            "interesting": one.get("interesting") or [],
            "error": one.get("error"),
            "url": one.get("url"),
            "duration": one.get("duration"),
        }
        for item in one.get("interesting") or []:
            item = dict(item)
            item["domain"] = domain
            all_interesting.append(item)

    total = sum(v.get("count") or 0 for v in by_domain.values())
    return {
        "ok": any(v.get("ok") for v in by_domain.values()),
        "tls": tls,
        "port": port,
        "domains": domains,
        "count": total,
        "interesting": all_interesting[:200],
        "by_domain": by_domain,
    }
