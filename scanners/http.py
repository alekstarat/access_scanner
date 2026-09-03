import http.client
from urllib.parse import urljoin

from .common import finding, result


SECURITY_HEADERS = {
    "strict-transport-security": (
        2,
        "missing_hsts",
        "HSTS header is missing",
    ),
    "content-security-policy": (
        2,
        "missing_csp",
        "Content-Security-Policy header is missing",
    ),
    "x-content-type-options": (
        1,
        "missing_x_content_type_options",
        "X-Content-Type-Options header is missing",
    ),
    "x-frame-options": (
        1,
        "missing_x_frame_options",
        "X-Frame-Options header is missing",
    ),
    "referrer-policy": (
        1,
        "missing_referrer_policy",
        "Referrer-Policy header is missing",
    ),
}


def run(ip, port, proto):
    if proto != "tcp":
        return result(
            "http",
            port,
            proto,
            findings=[
                finding(
                    "unsupported_protocol",
                    0,
                    "HTTP module expects TCP",
                )
            ],
        )

    try:
        conn = http.client.HTTPConnection(
            ip,
            port,
            timeout=5,
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

        headers = {
            key.lower(): value
            for key, value in response.getheaders()
        }

        observations = {
            "status": response.status,
            "reason": response.reason,
            "server": headers.get("server"),
            "content_type": headers.get("content-type"),
            "content_length": headers.get("content-length"),
            "location": headers.get("location"),
            "powered_by": headers.get("x-powered-by"),
            "body_size": len(body),
        }

        findings = []

        # Interesting HTTP status codes.
        if response.status >= 500:
            findings.append(
                finding(
                    "http_server_error",
                    2,
                    "HTTP server returned 5xx",
                    evidence=f"HTTP {response.status}",
                )
            )

        elif response.status in (401, 403):
            findings.append(
                finding(
                    "http_restricted",
                    1,
                    "HTTP resource requires access or is forbidden",
                    evidence=f"HTTP {response.status}",
                )
            )

        elif response.status == 200:
            pass

        # Security headers.
        for header, (
            severity,
            finding_id,
            title,
        ) in SECURITY_HEADERS.items():

            if header not in headers:
                findings.append(
                    finding(
                        finding_id,
                        severity,
                        title,
                        evidence=f"Missing header: {header}",
                    )
                )

        # Information disclosure.
        if headers.get("x-powered-by"):
            findings.append(
                finding(
                    "powered_by_disclosure",
                    1,
                    "X-Powered-By header exposes technology",
                    evidence=headers["x-powered-by"],
                )
            )

        if headers.get("server"):
            findings.append(
                finding(
                    "server_header_present",
                    0,
                    "Server header disclosed",
                    evidence=headers["server"],
                )
            )

        # Cookies.
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
            "http",
            port,
            proto,
            observations=observations,
            findings=findings,
        )

    except Exception as exc:
        return result(
            "http",
            port,
            proto,
            findings=[
                finding(
                    "http_connection_error",
                    0,
                    "HTTP connection failed",
                    evidence=str(exc),
                )
            ],
        )
