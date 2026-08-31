import http.client
import ssl


def run(ip, port, proto):
    if proto != "tcp":
        return "unsupported protocol"

    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        conn = http.client.HTTPSConnection(
            ip,
            port,
            timeout=3,
            context=context,
        )

        conn.request("HEAD", "/")
        response = conn.getresponse()

        server = response.getheader("Server", "")

        conn.close()

        info = f"HTTPS {response.status} {response.reason}"

        if server:
            info += f", Server: {server}"

        return info

    except Exception as exc:
        return f"HTTPS error: {exc}"
