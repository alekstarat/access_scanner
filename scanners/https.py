import http.client
import ssl

from .common import finding, result


def run(ip, port, proto):
    if proto != "tcp":
        return result(
            "https",
            port,
            proto,
            findings=[
                finding(
                    "unsupported_protocol",
                    0,
                    "HTTPS module expects TCP",
                )
            ],
        )

    context = ssl.create_default_context()

    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        conn = http.client.HTTPSConnection(
            ip,
            port,
            timeout=5,
            context=context,
        )

        conn.request(
            "GET",
            "/",
            headers={
                "User-Agent": "ActiveHostRecon/1.0",
                "Accept": "*/*",
                "Connection": "close",
            },
        )

        response = conn.getresponse()

        body = response.read(64 * 1024)

        sock = conn.sock

        tls_version = None
        cipher = None

        if sock:
            tls_version = sock.version()
            cipher_info = sock.cipher()

            if cipher_info:
                cipher = cipher_info[0]

        headers = {
            key.lower(): value
            for key, value in response.getheaders()
        }

        observations = {
            "status": response.status,
            "reason": response.reason,
            "server": headers.get("server"),
            "content_type": headers.get("content-type"),
            "location": headers.get("location"),
            "powered_by": headers.get("x-powered-by"),
            "body_size": len(body),
            "tls_version": tls_version,
            "tls_cipher": cipher,
        }

        findings = []

        if response.status >= 500:
            findings.append(
                finding(
                    "https_server_error",
                    2,
                    "HTTPS server returned 5xx",
                    evidence=f"HTTP {response.status}",
                )
            )

        if headers.get("x-powered-by"):
            findings.append(
                finding(
                    "powered_by_disclosure",
                    1,
                    "X-Powered-By header exposes technology",
                    evidence=headers["x-powered-by"],
                )
            )

        # HSTS особенно важен для HTTPS.
        if "strict-transport-security" not in headers:
            findings.append(
                finding(
                    "missing_hsts",
                    2,
                    "HSTS header is missing",
                    evidence="Strict-Transport-Security not present",
                )
            )

        if tls_version in ("TLSv1", "TLSv1.1"):
            findings.append(
                finding(
                    "legacy_tls",
                    3,
                    "Legacy TLS version negotiated",
                    evidence=tls_version,
                )
            )

        cookies = response.headers.get_all("Set-Cookie") or []

        insecure_cookies = []

        for cookie in cookies:
            lower = cookie.lower()

            if "secure" not in lower:
                insecure_cookies.append("missing Secure")

            if "httponly" not in lower:
                insecure_cookies.append("missing HttpOnly")

            if "samesite" not in lower:
                insecure_cookies.append("missing SameSite")

        if insecure_cookies:
            findings.append(
                finding(
                    "weak_cookie_flags",
                    2,
                    "Cookie security attributes are incomplete",
                    evidence=", ".join(
                        sorted(set(insecure_cookies))
                    ),
                )
            )

        conn.close()

        return result(
            "https",
            port,
            proto,
            observations=observations,
            findings=findings,
        )

    except ssl.SSLError as exc:
        return result(
            "https",
            port,
            proto,
            findings=[
                finding(
                    "tls_error",
                    2,
                    "TLS negotiation failed",
                    evidence=str(exc),
                )
            ],
        )

    except Exception as exc:
        return result(
            "https",
            port,
            proto,
            findings=[
                finding(
                    "https_connection_error",
                    0,
                    "HTTPS connection failed",
                    evidence=str(exc),
                )
            ],
        )
