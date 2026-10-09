import socket
from .common import result, finding


def run(ip, port, proto):
    if proto != "tcp":
        return result(
            service="rtsp",
            port=port,
            protocol=proto,
            findings=[
                finding("unsupported_protocol", 0, "RTSP module expects TCP")
            ],
        )

    try:
        with socket.create_connection((ip, port), timeout=3) as sock:
            sock.settimeout(3)
            # RTSP DESCRIBE — сервер должен ответить 200/401/454.
            request = (
                f"DESCRIBE rtsp://{ip}:{port}/ RTSP/1.0\r\n"
                "CSeq: 1\r\n"
                "Accept: application/sdp\r\n"
                "\r\n"
            )
            sock.sendall(request.encode())
            try:
                data = sock.recv(2048)
            except socket.timeout:
                data = b""

        observations = {}
        findings = []

        if data:
            banner = data.decode(errors="replace").strip()
            observations["banner"] = banner[:500]
            first_line = banner.splitlines()[0] if banner.splitlines() else ""
            if first_line.startswith("RTSP/"):
                observations["version"] = first_line[:100]
                findings.append(
                    finding(
                        "rtsp_responding",
                        2,
                        "RTSP service is responding",
                        evidence=first_line[:100],
                    )
                )
            else:
                findings.append(
                    finding(
                        "rtsp_unexpected_response",
                        1,
                        "Unexpected response on RTSP port",
                        evidence=first_line[:100],
                    )
                )
        else:
            findings.append(
                finding(
                    "rtsp_open_no_response",
                    2,
                    "RTSP port open, no response",
                )
            )

        return result(
            service="rtsp",
            port=port,
            protocol=proto,
            observations=observations,
            findings=findings,
        )

    except Exception as exc:
        return result(
            service="rtsp",
            port=port,
            protocol=proto,
            findings=[
                finding(
                    "rtsp_error",
                    0,
                    "RTSP probe failed",
                    evidence=str(exc),
                )
            ],
        )
