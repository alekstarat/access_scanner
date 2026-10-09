import socket
from .common import result, finding


def run(ip, port, proto):
    if proto != "tcp":
        return result(
            service="ftp",
            port=port,
            protocol=proto,
            findings=[
                finding("unsupported_protocol", 0, "FTP module expects TCP")
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
                    "ftp_no_banner",
                    1,
                    "FTP port open but no banner received",
                )
            )

        return result(
            service="ftp",
            port=port,
            protocol=proto,
            observations=observations,
            findings=findings,
        )

    except Exception as exc:
        return result(
            service="ftp",
            port=port,
            protocol=proto,
            findings=[
                finding(
                    "ftp_error",
                    0,
                    "FTP probe failed",
                    evidence=str(exc),
                )
            ],
        )
