"""
Реестр deep-цепочек по сервису.
Пока заглушки — будут наполняться.
"""
from .ssh import ssh
from .http import _http
# service → list of chain names
SERVICE_CHAINS = {
    "ssh": ["ssh_info"],
    "http": ["http_info"],
    "html": ["_html_info"],
    "https": ["tls_security", "http_info"],
    "ftp": ["ftp_info"],
    "smtp": ["smtp_info"],
    "smb": ["smb_info"],
    "rdp": ["rdp_info"],
    "vnc": ["vnc_info"],
    "telnet": ["telnet_info"],
    "dns": ["dns_info"],
    "pop3": ["pop3_info"],
}


def get_chains_for_service(service: str) -> list[str]:
    if not service:
        return []
    return list(SERVICE_CHAINS.get(service.lower(), []))


def run_chain(chain: str, ctx: dict) -> dict:
    """
    ctx: {
        ip, port, protocol, service, version, banner,
        observation_id, host_id, domains, geo, raw
    }
    Возвращает dict результатов (сохраняется в deep_results).
    """
    handlers = {
        "ssh_info": _ssh_info,
        "html_info": _html_info,
        "http_info": _http_info,
        "tls_security": _tls_security,
        "ftp_info": _generic_info,
        "smtp_info": _generic_info,
        "smb_info": _generic_info,
        "rdp_info": _generic_info,
        "vnc_info": _generic_info,
        "telnet_info": _generic_info,
        "dns_info": _generic_info,
        "pop3_info": _generic_info,
    }
    handler = handlers.get(chain, _generic_info)
    return handler(ctx)



def _generic_info(ctx: dict) -> dict:
    return {
        "service": ctx.get("service"),
        "version": ctx.get("version"),
        "banner": ctx.get("banner"),
        "note": "generic chain — no deep logic yet",
    }


def _html_info(ctx: dict):
    with open("example_ctx.txt", "w") as c:
        c.write(f"HTML ctx\n")
        for item in ctx.items():
            c.write(f"{item}\n")
    c.close()


def _ssh_info(ctx: dict) -> dict:
    banner = ctx.get("banner") or ""

    # with open("example_ctx.txt", "w") as c:
    #     c.write(f"SSH ctx\n")
    #     for item in ctx.items():
    #         c.write(f"{item}\n")
    # c.close()

    return {
        "banner": banner,
        "version_hint": banner.split()[0] if banner.startswith("SSH-") else None,
        "note": {
            k: ssh.KNOWN_VULNERABILITIES[k]["handler"](ctx.get("ip")) for k in ssh.known_vulnerabilities(banner)
        },
    }


def _http_info(ctx: dict) -> dict:
    raw = ctx.get("raw") or {}
    obs = raw.get("observations") or {}

    # with open("example_ctx.txt", "w") as c:
    #     c.write(f"HTTP ctx\n")
    #     for item in ctx.items():
    #         c.write(f"{item}\n")
    # c.close()

    return {
        "status": obs.get("status"),
        "server": obs.get("server"),
        "powered_by": obs.get("powered_by"),
        "note": _http.search_dirs(ip=ctx.get('ip'), port=ctx.get('port'), tls=ctx.get("service")=='https'),
    }


def _tls_security(ctx: dict) -> dict:
    """Уже частично собрано в primary через intelligence.tls_info."""
    from intelligence.tls_info import probe

    ip = ctx["ip"]
    port = ctx.get("port") or 443
    info = probe(ip, port)
    return {
        "tls_version": info.get("tls_version"),
        "cipher": info.get("cipher"),
        "cert": info.get("cert"),
        "domains": info.get("domains"),
        "error": info.get("error"),
    }
