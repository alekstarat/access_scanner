import socket
from .common import result, finding


def run(ip, port, proto):
    if proto != "tcp":
        return result(
            service="pop3",
            port=port,
            protocol=proto,
            findings=[
                finding("unsupported_protocol", 0, "POP3 module expects TCP")
            ],
        )

    try:
        with socket.create_connection((ip, port), timeout=3) as sock:
            sock.settimeout(3)
            banner = sock.recv(512).decode(errors="replace").strip()

        observations = {}
        findings = []

        if banner:
            observations["banner"] = banner
            observations["version"] = banner
        else:
            findings.append(
                finding(
                    "pop3_no_banner",
                    1,
                    "POP3 port open but no banner received",
                )
            )

        return result(
            service="pop3",
            port=port,
            protocol=proto,
            observations=observations,
            findings=findings,
        )

    except Exception as exc:
        return result(
            service="pop3",
            port=port,
            protocol=proto,
            findings=[
                finding(
                    "pop3_error",
                    0,
                    "POP3 probe failed",
                    evidence=str(exc),
                )
            ],
        )
