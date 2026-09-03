import socket
from .common import result, finding


def run(ip, port, proto):
    if proto != "tcp":
        return result(
            service="telnet",
            port=port,
            protocol=proto,
            findings=[
                finding("unsupported_protocol", 0, "Telnet module expects TCP")
            ],
        )

    try:
        with socket.create_connection((ip, port), timeout=3) as sock:
            sock.settimeout(2)
            try:
                data = sock.recv(512)
            except socket.timeout:
                data = b""

        observations = {}
        findings = []

        if data:
            banner = (
                data.decode(errors="replace")
                .replace("\r", " ")
                .replace("\n", " ")
                .strip()
            )
            observations["banner"] = banner[:200]
        else:
            findings.append(
                finding(
                    "telnet_open",
                    2,
                    "Telnet service reachable (no banner)",
                )
            )

        findings.append(
            finding(
                "telnet_exposed",
                3,
                "Telnet service is exposed",
                evidence="Cleartext remote access protocol",
            )
        )

        return result(
            service="telnet",
            port=port,
            protocol=proto,
            observations=observations,
            findings=findings,
        )

    except Exception as exc:
        return result(
            service="telnet",
            port=port,
            protocol=proto,
            findings=[
                finding(
                    "telnet_error",
                    0,
                    "Telnet probe failed",
                    evidence=str(exc),
                )
            ],
        )
