import http.client


def run(ip, port, proto):
    if proto != "tcp":
        return "unsupported protocol"

    try:
        conn = http.client.HTTPConnection(
            ip,
            port,
            timeout=3,
        )

        conn.request("HEAD", "/")
        response = conn.getresponse()

        server = response.getheader("Server", "")
        powered_by = response.getheader("X-Powered-By", "")

        conn.close()

        info = f"HTTP {response.status} {response.reason}"

        if server:
            info += f", Server: {server}"

        if powered_by:
            info += f", X-Powered-By: {powered_by}"

        return info

    except Exception as exc:
        return f"HTTP error: {exc}"
