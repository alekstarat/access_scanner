import socket


def run(ip, port, proto):
    if proto != "tcp":
        return "unsupported protocol"

    try:
        with socket.create_connection((ip, port), timeout=3) as sock:
            sock.sendall(b"SSH-2.0-port-hub\r\n")
            banner = sock.recv(256)

        banner = banner.decode(errors="replace").strip()

        if banner:
            return f"SSH banner: {banner}"

        return "SSH port is open, no banner received"

    except socket.timeout:
        return "connection timeout"

    except OSError as exc:
        return f"connection error: {exc}"
