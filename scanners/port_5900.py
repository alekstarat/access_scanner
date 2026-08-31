import socket


def run(ip, port, proto):
    if proto != "tcp":
        return "unsupported protocol"

    try:
        with socket.create_connection((ip, port), timeout=3) as sock:
            sock.settimeout(3)
            banner = sock.recv(64).decode(errors="replace").strip()

        if banner.startswith("RFB"):
            return f"VNC: {banner}"

        if banner:
            return f"Unexpected response: {banner[:100]}"

        return "VNC port open, no banner"

    except Exception as exc:
        return f"VNC error: {exc}"
