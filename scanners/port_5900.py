import socket
from .common import result, finding


def run(ip, port, proto):
    if proto != "tcp":
        return result(
            service="vnc",
            port=port,
            protocol=proto,
            findings=[
                finding("unsupported_protocol", 0, "VNC module expects TCP")
            ],
        )

    try:
        with socket.create_connection((ip, port), timeout=3) as sock:
            sock.settimeout(3)
            banner = sock.recv(64).decode(errors="replace").strip()

        observations = {}
        findings = []

        if banner.startswith("RFB"):
            observations["banner"] = banner
            observations["version"] = banner
            findings.append(
                finding(
                    "vnc_responding",
                    2,
                    "VNC service detected",
                    evidence=banner,
                )
            )
        elif banner:
            observations["banner"] = banner[:100]
            findings.append(
                finding(
                    "vnc_unexpected_response",
                    1,
                    "Unexpected response on VNC port",
                    evidence=banner[:100],
                )
            )
        else:
            findings.append(
                finding(
                    "vnc_open_no_banner",
                    2,
                    "VNC port open, no banner",
                )
            )

        findings.append(
            finding(
                "vnc_exposed",
                3,
                "VNC service is exposed",
                evidence="Port 5900/tcp",
            )
        )

        return result(
            service="vnc",
            port=port,
            protocol=proto,
            observations=observations,
            findings=findings,
        )

    except Exception as exc:
        return result(
            service="vnc",
            port=port,
            protocol=proto,
            findings=[
                finding(
                    "vnc_error",
                    0,
                    "VNC probe failed",
                    evidence=str(exc),
                )
            ],
        )
