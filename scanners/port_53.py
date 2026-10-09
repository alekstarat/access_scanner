import socket
import struct
from .common import result, finding


def _dns_query_packet() -> bytes:
    # Minimal DNS query for example.com A
    return (
        b"\xaa\xbb"          # transaction ID
        b"\x01\x00"          # standard query
        b"\x00\x01"          # one question
        b"\x00\x00\x00\x00"
        b"\x00\x00"
        b"\x07example\x03com\x00"
        b"\x00\x01"          # A
        b"\x00\x01"          # IN
    )


def _parse_dns_response(data: bytes) -> tuple[dict, list]:
    observations = {}
    findings = []

    if len(data) < 12:
        findings.append(
            finding(
                "dns_short_response",
                1,
                "DNS response too short",
                evidence=f"{len(data)} bytes",
            )
        )
        return observations, findings

    flags = int.from_bytes(data[2:4], "big")
    rcode = flags & 0x0F
    answers = int.from_bytes(data[6:8], "big")

    observations["rcode"] = rcode
    observations["answers"] = answers
    observations["response_size"] = len(data)

    if rcode == 0:
        findings.append(
            finding(
                "dns_responding",
                1,
                "DNS server is responding",
                evidence=f"rcode={rcode}, answers={answers}",
            )
        )

    return observations, findings


def _probe_dns_udp(ip, port, query: bytes) -> bytes | None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(3)
        sock.sendto(query, (ip, port))
        data, _ = sock.recvfrom(4096)
        return data
    finally:
        try:
            sock.close()
        except Exception:
            pass


def _probe_dns_tcp(ip, port, query: bytes) -> bytes | None:
    # DNS over TCP: 2-байтовый length-prefix.
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(3)
        sock.connect((ip, port))
        sock.sendall(struct.pack(">H", len(query)) + query)
        header = b""
        while len(header) < 2:
            chunk = sock.recv(2 - len(header))
            if not chunk:
                return None
            header += chunk
        (length,) = struct.unpack(">H", header)
        data = b""
        while len(data) < length:
            chunk = sock.recv(min(length - len(data), 4096))
            if not chunk:
                break
            data += chunk
        return data or None
    finally:
        try:
            sock.close()
        except Exception:
            pass


def run(ip, port, proto):
    if proto not in ("udp", "tcp"):
        return result(
            service="dns",
            port=port,
            protocol=proto,
            findings=[
                finding("unsupported_protocol", 0, "DNS module expects UDP or TCP")
            ],
        )

    query = _dns_query_packet()

    try:
        if proto == "udp":
            data = _probe_dns_udp(ip, port, query)
            if data is None:
                return result(
                    service="dns",
                    port=port,
                    protocol=proto,
                    findings=[finding("dns_timeout", 0, "DNS timeout")],
                )
        else:
            # nmap -F пишет только port/tcp — DNS на 53/tcp тоже проверяем.
            data = _probe_dns_tcp(ip, port, query)
            if data is None:
                return result(
                    service="dns",
                    port=port,
                    protocol=proto,
                    findings=[finding("dns_no_response", 1, "No DNS response over TCP")],
                )

        observations, findings = _parse_dns_response(data)

        return result(
            service="dns",
            port=port,
            protocol=proto,
            observations=observations,
            findings=findings,
        )

    except socket.timeout:
        return result(
            service="dns",
            port=port,
            protocol=proto,
            findings=[
                finding("dns_timeout", 0, "DNS timeout")
            ],
        )
    except Exception as exc:
        return result(
            service="dns",
            port=port,
            protocol=proto,
            findings=[
                finding(
                    "dns_error",
                    0,
                    "DNS probe failed",
                    evidence=str(exc),
                )
            ],
        )
