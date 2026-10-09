import socket
import base64


def b64encode(s: str) -> str:
    text_bytes = s.encode("utf-8")
    b64bytes = base64.b64encode(text_bytes)

    b64text = b64bytes.decode("ascii")

    return b64text


def check_rtsp_authentication(
    ip: str, port: int = 554, login: str | None = None,
    password: str | None = None, timeout: float = 5.0,
) -> dict:
    """DESCRIBE-запрос: anonymous + проверка 401."""
    if login and password:
        encrypted_credentials = b64encode(f"{login}:{password}")
        auth_header = f"Authorization: Basic {encrypted_credentials}\r\n"
    else:
        auth_header = ""

    request = (
        f"DESCRIBE rtsp://{ip}:{port}/ RTSP/1.0\r\n"
        f"CSeq: 2\r\n"
        f"{auth_header}"
        f"Accept: application/sdp\r\n"
        f"\r\n"
    )

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.connect((ip, port))
        sock.sendall(request.encode())
        data = sock.recv(4096)
    finally:
        try:
            sock.close()
        except Exception:
            pass

    try:
        decoded_data = data.decode(errors="replace")
    except Exception:
        decoded_data = ""

    return {
        "success": bool(decoded_data) and "Unauthorized" not in decoded_data,
        "banner": decoded_data[:2000],
        "request": request,
    }


def run(ctx: dict) -> dict:
    """Deep-handler для registry: анонимный DESCRIBE."""
    ip = ctx.get("ip")
    try:
        port = int(ctx.get("port") or 554)
    except (TypeError, ValueError):
        port = 554
    result = check_rtsp_authentication(ip, port)
    result["ok"] = bool(result.get("banner"))
    return result


if __name__ == "__main__":
    print(check_rtsp_authentication(ip="78.38.152.173"))