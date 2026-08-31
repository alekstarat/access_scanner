import socket


def run(ip, port, proto):
    if proto != "tcp":
        return "unsupported protocol"

    try:
        with socket.create_connection((ip, port), timeout=3) as sock:
            sock.settimeout(2)

            try:
                data = sock.recv(512)
            except socket.timeout:
                data = b""

        if data:
            banner = data.decode(errors="replace").replace("\r", " ").replace("\n", " ")
            return f"Telnet banner: {banner[:200]}"

        return "Telnet service reachable"

    except Exception as exc:
        return f"Telnet error: {exc}"
