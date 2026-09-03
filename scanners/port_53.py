import socket
from .common import result, finding


def run(ip, port, proto):
    if proto != "udp":
        return result(
            service="dns",
            port=port,
            protocol=proto,
            findings=[
                finding("unsupported_protocol", 0, "DNS module expects UDP")
            ],
        )

    # Minimal DNS query for example.com A
    query = (
        b"\xaa\xbb"          # transaction ID
        b"\x01\x00"          # standard query
        b"\x00\x01"          # one question
        b"\x00\x00\x00\x00"
        b"\x00\x00"
        b"\x07example\x03com\x00"
        b"\x00\x01"          # A
        b"\x00\x01"          # IN
    )

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3)
        sock.sendto(query, (ip, port))
        data, _ = sock.recvfrom(4096)
        sock.close()

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
        else:
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
