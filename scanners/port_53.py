import socket


def run(ip, port, proto):
    if proto != "udp":
        return "DNS module expects 53/udp"

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

        if len(data) < 12:
            return "DNS response too short"

        flags = int.from_bytes(data[2:4], "big")
        rcode = flags & 0x0F
        answers = int.from_bytes(data[6:8], "big")

        return f"DNS responding, rcode={rcode}, answers={answers}"

    except socket.timeout:
        return "DNS timeout"

    except Exception as exc:
        return f"DNS error: {exc}"
