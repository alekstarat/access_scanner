"""
Reverse DNS (PTR) и базовая проверка доменов.
"""
import socket


def reverse_dns(ip: str) -> str | None:
    """PTR-запись или None."""
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return host.rstrip(".").lower() if host else None
    except (socket.herror, socket.gaierror, OSError):
        return None


def resolve_a(name: str) -> list[str]:
    """A-записи домена."""
    try:
        infos = socket.getaddrinfo(name, None, socket.AF_INET)
        return sorted({info[4][0] for info in infos})
    except (socket.gaierror, OSError):
        return []


if __name__ == "__main__":
    print(reverse_dns("46.39.224.205"))