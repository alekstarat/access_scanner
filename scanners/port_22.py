import socket
from .common import result, finding


def run(ip, port, proto):
    if proto != "tcp":
        return result(
            service="ssh",
            port=port,
            protocol=proto,
            findings=[
                finding("unsupported_protocol", 0, "SSH module expects TCP")
            ],
        )

    try:
        with socket.create_connection((ip, port), timeout=3) as sock:
            sock.sendall(b"SSH-2.0-port-hub\r\n")
            raw = sock.recv(256)

        banner = raw.decode(errors="replace").strip()

        observations = {}
        findings = []

        if banner:
            observations["banner"] = banner
            # Extract version-ish part if present
            if banner.startswith("SSH-"):
                observations["version"] = banner.split()[0] if banner.split() else banner

        else:
            findings.append(
                finding(
                    "ssh_no_banner",
                    1,
                    "SSH port open but no banner received",
                )
            )

        return result(
            service="ssh",
            port=port,
            protocol=proto,
            observations=observations,
            findings=findings,
        )

    except socket.timeout:
        return result(
            service="ssh",
            port=port,
            protocol=proto,
            findings=[
                finding("connection_timeout", 0, "Connection timeout")
            ],
        )
    except OSError as exc:
        return result(
            service="ssh",
            port=port,
            protocol=proto,
            findings=[
                finding(
                    "connection_error",
                    0,
                    "Connection error",
                    evidence=str(exc),
                )
            ],
        )
