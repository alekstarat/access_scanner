"""
Legacy/simple HTTPS probe for port 443.
Note: load_module prioritises scanners.https for ports in HTTPS_PORTS,
so this module is only used if 443 is removed from HTTPS_PORTS.
"""
import http.client
import ssl
from .common import result, finding


def run(ip, port, proto):
    if proto != "tcp":
        return result(
            service="https",
            port=port,
            protocol=proto,
            findings=[
                finding("unsupported_protocol", 0, "HTTPS module expects TCP")
            ],
        )

    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        conn = http.client.HTTPSConnection(
            ip, port, timeout=3, context=context
        )
        conn.request("HEAD", "/")
        response = conn.getresponse()

        server = response.getheader("Server", "")
        conn.close()

        observations = {
            "status": response.status,
            "reason": response.reason,
        }
        if server:
            observations["server"] = server

        return result(
            service="https",
            port=port,
            protocol=proto,
            observations=observations,
        )

    except Exception as exc:
        return result(
            service="https",
            port=port,
            protocol=proto,
            findings=[
                finding(
                    "https_error",
                    0,
                    "HTTPS probe failed",
                    evidence=str(exc),
                )
            ],
        )
