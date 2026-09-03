"""
Legacy/simple HTTP probe for port 80.
Note: load_module prioritises scanners.http for ports in HTTP_PORTS,
so this module is only used if 80 is removed from HTTP_PORTS.
"""
import http.client
from .common import result, finding


def run(ip, port, proto):
    if proto != "tcp":
        return result(
            service="http",
            port=port,
            protocol=proto,
            findings=[
                finding("unsupported_protocol", 0, "HTTP module expects TCP")
            ],
        )

    try:
        conn = http.client.HTTPConnection(ip, port, timeout=3)
        conn.request("HEAD", "/")
        response = conn.getresponse()

        server = response.getheader("Server", "")
        powered_by = response.getheader("X-Powered-By", "")
        conn.close()

        observations = {
            "status": response.status,
            "reason": response.reason,
        }
        if server:
            observations["server"] = server
        if powered_by:
            observations["powered_by"] = powered_by

        return result(
            service="http",
            port=port,
            protocol=proto,
            observations=observations,
        )

    except Exception as exc:
        return result(
            service="http",
            port=port,
            protocol=proto,
            findings=[
                finding(
                    "http_error",
                    0,
                    "HTTP probe failed",
                    evidence=str(exc),
                )
            ],
        )
