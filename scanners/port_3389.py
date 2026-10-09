import socket
from .common import result, finding


def run(ip, port, proto):
    if proto != "tcp":
        return result(
            service="rdp",
            port=port,
            protocol=proto,
            findings=[
                finding("unsupported_protocol", 0, "RDP module expects TCP")
            ],
        )

    try:
        with socket.create_connection((ip, port), timeout=3) as sock:
            sock.settimeout(3)

            # Minimal RDP Negotiation Request
            request = bytes.fromhex(
                "030000130ee000000000000100080003000000"
            )
            sock.sendall(request)
            response = sock.recv(1024)

        observations = {}
        findings = []

        if response:
            observations["response_size"] = len(response)
            findings.append(
                finding(
                    "rdp_responding",
                    2,
                    "RDP negotiation response received",
                    evidence=f"{len(response)} bytes",
                )
            )
        else:
            findings.append(
                finding(
                    "rdp_open_no_response",
                    2,
                    "RDP port reachable, no response",
                )
            )

        findings.append(
            finding(
                "rdp_exposed",
                3,
                "RDP service is exposed",
                evidence="Port 3389/tcp",
            )
        )

        return result(
            service="rdp",
            port=port,
            protocol=proto,
            observations=observations,
            findings=findings,
        )

    except Exception as exc:
        return result(
            service="rdp",
            port=port,
            protocol=proto,
            findings=[
                finding(
                    "rdp_error",
                    0,
                    "RDP probe failed",
                    evidence=str(exc),
                )
            ],
        )
