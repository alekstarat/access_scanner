"""
Реестр deep-цепочек по сервису.

Цепочки запускаются после primary-скана порта.
Результат сохраняется в deep_results и автоматически
попадает в Service.deep / Service.deep_tasks через models.HostProfile.

Как добавить новую цепочку:
  1. Реализовать handler(ctx) -> dict в соответствующем модуле (или здесь).
  2. Добавить имя в SERVICE_CHAINS[service].
  3. Зарегистрировать handler в _HANDLERS.

ctx всегда содержит:
  ip, port, protocol, service, version, banner,
  observation_id, host_id, domains, geo, raw
"""

from __future__ import annotations

from typing import Callable

# ── imports of concrete chain modules ─────────────────────────
try:
    from .ssh import ssh as ssh_mod
except Exception:
    ssh_mod = None

try:
    from .http import _http as http_mod
except Exception:
    http_mod = None

try:
    from .html import _html as html_mod
except Exception:
    html_mod = None


SERVICE_CHAINS: dict[str, list[str]] = {
    "ssh":      ["ssh_info", "ssh_bruteforce"],
    "http":     ["http_info", "http_headers", "html_info", "http_dirs"],
    "https":    ["tls_security", "http_info", "http_headers", "html_info", "https_dirs"],
    "html":     ["html_info"],
    "ftp":      ["ftp_info"],
    "smtp":     ["smtp_info"],
    "smb":      ["smb_info"],
    "rdp":      ["rdp_info"],
    "vnc":      ["vnc_info"],
    "telnet":   ["telnet_info"],
    "dns":      ["dns_info"],
    "pop3":     ["pop3_info"],
}


def get_chains_for_service(service: str) -> list[str]:
    if not service:
        return []
    return list(SERVICE_CHAINS.get(service.lower(), []))


# ── Handlers ──────────────────────────────────────────────────

def _generic_info(ctx: dict) -> dict:
    return {
        "service": ctx.get("service"),
        "version": ctx.get("version"),
        "banner": ctx.get("banner"),
        "note": "generic chain — no deep logic yet",
    }


def _ssh_info(ctx: dict) -> dict:
    banner = ctx.get("banner") or ""
    result = {
        "banner": banner,
        "version_hint": None,
        "known_vulns": {},
    }
    if banner.startswith("SSH-"):
        result["version_hint"] = banner.split()[0] if banner.split() else None
    return result


def _rdp_info(ctx: dict) -> dict:
    from pathlib import Path
    from deep_runner import run_bash

    script = Path(__file__).resolve().parent / "rdp" / "rdp.sh"
    ip = ctx.get("ip")

    result = run_bash([str(script), str(ip)])
    return {
        "ok": result["ok"],
        "returncode": result["returncode"],
        "duration": result["duration"],
        "stdout": (result["stdout"] or "")[:50_000],
        "stderr": (result["stderr"] or "")[:10_000],
        "error": result.get("error"),
    }

def _ssh_bruteforce(ctx: dict) -> dict:
    """
    Пример тяжёлой цепочки: bash + deep_runner.run_bash.
    """
    from pathlib import Path
    from deep_runner import run_bash

    script = Path(__file__).resolve().parent / "ssh" / "ssh_bruteforcer.sh"
    ip = ctx.get("ip")
    if not script.is_file():
        return {
            "status": "stub",
            "note": f"script missing: {script}",
            "ip": ip,
            "port": ctx.get("port"),
            "suggested_users": ["root", "admin", "ubuntu", "debian"],
        }

    # timeout берётся из DEEP_TIMEOUT
    result = run_bash([str(script), str(ip), 'root, admin, ubuntu, debian'])
    return {
        "ok": result["ok"],
        "returncode": result["returncode"],
        "duration": result["duration"],
        "stdout": (result["stdout"] or "")[:50_000],
        "stderr": (result["stderr"] or "")[:10_000],
        "error": result.get("error"),
    }


def _http_info(ctx: dict) -> dict:
    raw = ctx.get("raw") or {}
    obs = raw.get("observations") or {}
    result = {
        "status": obs.get("status"),
        "server": obs.get("server"),
        "powered_by": obs.get("powered_by"),
        "title": obs.get("title"),
    }
    return result


def _http_dirs(ctx: dict) -> dict:
    """ffuf / search_dirs.sh через deep_runner.run_bash (лимит + kill)"""
    if http_mod is not None and hasattr(http_mod, "search_dirs"):
        return http_mod.search_dirs(
            ip=ctx.get("ip"),
            port=ctx.get("port"),
            tls=(ctx.get("service") or "").lower() == "https",
        )
    return {
        "status": "stub",
        "note": "http module / search_dirs not available",
        "ip": ctx.get("ip"),
        "port": ctx.get("port"),
    }

def _https_dirs(ctx: dict) -> dict:
    if http_mod is not None and hasattr(http_mod, "search_dirs_by_domain"):
        return http_mod.search_dirs(
            ip=ctx.get("ip"),
            port=ctx.get("port"),
            service=ctx.get("service")
        )
    return {
        "status": "stub",
        "note": "http module / search_dirs not available",
        "ip": ctx.get("ip"),
        "port": ctx.get("port"),
    }


def _http_headers(ctx: dict) -> dict:
    raw = ctx.get("raw") or {}
    obs = raw.get("observations") or {}
    headers = obs.get("headers") or {}
    return {
        "status": "stub",
        "headers_seen": list(headers.keys()) if isinstance(headers, dict) else [],
        "note": "http_headers analysis not implemented yet",
        # TODO: check HSTS, CSP, X-Frame-Options, etc.
    }


def _html_info(ctx: dict) -> dict:
    if html_mod is not None and hasattr(html_mod, "run"):
        try:
            return html_mod.run(ctx)
        except Exception as exc:
            return {"error": str(exc)}
    return {
        "status": "stub",
        "note": "html analysis module not ready",
    }


def _tls_security(ctx: dict) -> dict:
    """Уже частично собирается в primary через intelligence.tls_info."""
    from intelligence.tls_info import probe

    ip = ctx["ip"]
    port = ctx.get("port") or 443
    try:
        info = probe(ip, port)
        return {
            "tls_version": info.get("tls_version"),
            "cipher": info.get("cipher"),
            "cert": info.get("cert"),
            "domains": info.get("domains"),
            "error": info.get("error"),
        }
    except Exception as exc:
        return {"error": str(exc)}


def _ftp_info(ctx: dict) -> dict:
    return _generic_info(ctx) | {"note": "ftp deep chain stub"}


def _smtp_info(ctx: dict) -> dict:
    return _generic_info(ctx) | {"note": "smtp deep chain stub — VRFY/EXPN/etc"}


def _smb_info(ctx: dict) -> dict:
    return _generic_info(ctx) | {"note": "smb deep chain stub — enum shares"}


def _vnc_info(ctx: dict) -> dict:
    return _generic_info(ctx) | {"note": "vnc deep chain stub"}


def _telnet_info(ctx: dict) -> dict:
    return _generic_info(ctx) | {"note": "telnet deep chain stub — banner + auth"}


def _dns_info(ctx: dict) -> dict:
    return _generic_info(ctx) | {"note": "dns deep chain stub — version.bind, zone transfer"}


def _pop3_info(ctx: dict) -> dict:
    return _generic_info(ctx) | {"note": "pop3 deep chain stub"}


# ── Registry ──────────────────────────────────────────────────

_HANDLERS: dict[str, Callable[[dict], dict]] = {
    "ssh_info":       _ssh_info,
    "ssh_bruteforce": _ssh_bruteforce,
    "http_info":      _http_info,
    "http_dirs":      _http_dirs,
    "http_headers":   _http_headers,
    "https_dirs":     _http_dirs,
    "html_info":      _html_info,
    "tls_security":   _tls_security,
    "ftp_info":       _ftp_info,
    "smtp_info":      _smtp_info,
    "smb_info":       _smb_info,
    "rdp_info":       _rdp_info,
    "vnc_info":       _vnc_info,
    "telnet_info":    _telnet_info,
    "dns_info":       _dns_info,
    "pop3_info":      _pop3_info,
}


def run_chain(chain: str, ctx: dict) -> dict:
    """
    Выполняет цепочку и возвращает dict результатов.
    Результаты сохраняются в deep_results (по одному ключу или целиком).
    """
    handler = _HANDLERS.get(chain, _generic_info)
    result = handler(ctx)
    if not isinstance(result, dict):
        result = {"value": result}
    return result


def list_available_chains() -> dict[str, list[str]]:
    """Для отладки / UI."""
    return dict(SERVICE_CHAINS)
