import socket


def run(ip, port, proto):
    if proto != "tcp":
        return "unsupported protocol"

    try:
        with socket.create_connection((ip, port), timeout=3) as sock:
            sock.settimeout(3)

            # Minimal RDP Negotiation Request
            request = bytes.fromhex(
                "030000130ee000000000000100080003000000"
            )

            sock.sendall(request)
            response = sock.recv(1024)

        if not response:
            return "RDP port reachable, no response"

        return f"RDP negotiation response ({len(response)} bytes)"

    except Exception as exc:
        return f"RDP error: {exc}"
