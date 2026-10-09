import socket
from .common import result, finding


def run(ip, port, proto):
    if proto != "tcp":
        return result(
            service="smb",
            port=port,
            protocol=proto,
            findings=[
                finding("unsupported_protocol", 0, "SMB module expects TCP")
            ],
        )

    try:
        with socket.create_connection((ip, port), timeout=3) as sock:
            sock.settimeout(2)

            # Minimal SMB negotiate probe
            probe = bytes.fromhex(
                "00000054"
                "ff534d4272000000001801"
                "280000000000000000000000000000000000000000000000"
                "000000000000000000000000000000000000000000000000"
                "000000000000000000000000000000000000000000000000"
            )

            sock.sendall(probe)
            data = sock.recv(1024)

        observations = {}
        findings = []

        if data:
            observations["response_size"] = len(data)
            findings.append(
                finding(
                    "smb_responding",
                    2,
                    "SMB service is responding",
                    evidence=f"{len(data)} bytes",
                )
            )
        else:
            findings.append(
                finding(
                    "smb_open_no_response",
                    2,
                    "SMB port reachable, no response",
                )
            )

        findings.append(
            finding(
                "smb_exposed",
                3,
                "SMB/CIFS service is exposed",
                evidence="Port 445/tcp",
            )
        )

        return result(
            service="smb",
            port=port,
            protocol=proto,
            observations=observations,
            findings=findings,
        )

    except Exception as exc:
        return result(
            service="smb",
            port=port,
            protocol=proto,
            findings=[
                finding(
                    "smb_error",
                    0,
                    "SMB probe failed",
                    evidence=str(exc),
                )
            ],
        )
