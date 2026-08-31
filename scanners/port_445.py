import socket


def run(ip, port, proto):
    if proto != "tcp":
        return "unsupported protocol"

    try:
        with socket.create_connection((ip, port), timeout=3) as sock:
            sock.settimeout(2)

            # NetBIOS Session Service / SMB negotiation probe
            probe = bytes.fromhex(
                "00000054"
                "ff534d4272000000001801"
                "280000000000000000000000000000000000000000000000"
                "000000000000000000000000000000000000000000000000"
                "000000000000000000000000000000000000000000000000"
            )

            sock.sendall(probe)
            data = sock.recv(1024)

        if not data:
            return "SMB port reachable, no response"

        return f"SMB response received ({len(data)} bytes)"

    except Exception as exc:
        return f"SMB error: {exc}"
