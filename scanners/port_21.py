import socket


def run(ip, port, proto):
    if proto != "tcp":
        return "unsupported protocol"

    try:
        with socket.create_connection((ip, port), timeout=3) as sock:
            sock.settimeout(3)
            banner = sock.recv(512).decode(errors="replace").strip()

        if not banner:
            return "FTP open, no banner"

        return f"FTP: {banner}"

    except Exception as exc:
        return f"FTP error: {exc}"