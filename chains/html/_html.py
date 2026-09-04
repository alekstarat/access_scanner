"""
HTML deep analysis chain.

Запускается после http/https primary + http_info.
Срабатывает только если content-type text/html (или xhtml)
и body_size > MIN_HTML_SIZE.

Ищет:
  - интересные / API / admin / debug URL и редиректы
  - потенциальные XSS sinks
  - POST-формы без CSRF-токена
  - утечки API-токенов, JWT, ключей, секретов в HTML/JS
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

try:
    import requests
except ImportError:  # pragma: no cover
    requests = None

# Минимальный размер ответа (байт), ниже которого парсить нет смысла.
MIN_HTML_SIZE = 512

# Таймаут на загрузку HTML.
FETCH_TIMEOUT = 12

# Сколько URL максимум класть в результат.
MAX_URLS = 200
MAX_INTERESTING = 80
MAX_XSS = 50
MAX_CSRF = 30
MAX_SECRETS = 40

# Пути/слова, которые часто интересны при аудите приложения.
INTERESTING_PATTERNS = [
    r"/api(?:/|$|\?)",
    r"/graphql(?:/|$|\?)",
    r"/swagger(?:/|\.json|$)",
    r"/openapi(?:/|\.json|$)",
    r"/docs?(?:/|$)",
    r"/admin(?:/|$|\?)",
    r"/debug(?:/|$|\?)",
    r"/internal(?:/|$|\?)",
    r"/private(?:/|$|\?)",
    r"/actuator(?:/|$|\?)",
    r"/\.git(?:/|$)",
    r"/\.env(?:/|$)",
    r"/config(?:/|$|\.)",
    r"/backup(?:/|$|\.)",
    r"/wp-admin(?:/|$)",
    r"/wp-json(?:/|$)",
    r"/phpmyadmin(?:/|$)",
    r"/manager(?:/|$)",
    r"/console(?:/|$)",
    r"/v1(?:/|$|\?)",
    r"/v2(?:/|$|\?)",
    r"/oauth(?:/|$|\?)",
    r"/auth(?:/|$|\?)",
    r"/login(?:/|$|\?)",
    r"/logout(?:/|$|\?)",
    r"/token(?:/|$|\?)",
    r"/callback(?:/|$|\?)",
]

# Признаки потенциальных XSS sinks/sources в HTML/JS.
XSS_PATTERNS = [
    r"innerHTML\s*=",
    r"outerHTML\s*=",
    r"insertAdjacentHTML\s*\(",
    r"document\.write\s*\(",
    r"document\.writeln\s*\(",
    r"\beval\s*\(",
    r"setTimeout\s*\(\s*[\"'`]",
    r"setInterval\s*\(\s*[\"'`]",
    r"location(?:\.href)?\s*=",
    r"\.html\s*\(\s*[^)]*\)",  # jQuery .html(...)
    r"dangerouslySetInnerHTML",
]

# Признаки CSRF-токена в формах.
CSRF_PATTERNS = [
    r"csrf",
    r"xsrf",
    r"__requestverificationtoken",
    r"authenticity_token",
    r"_token",
    r"csrfmiddlewaretoken",
    r"anti-forgery",
]

# Утечки секретов / токенов, которых не должно быть в HTML/JS.
SECRET_PATTERNS = [
    # JWT
    (
        "jwt",
        re.compile(
            r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"
        ),
    ),
    # Generic API keys / tokens in assignments
    (
        "api_key_assignment",
        re.compile(
            r"""(?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token|secret[_-]?key|client[_-]?secret)\s*[=:]\s*['"]([^'"]{8,})['"]""",
            re.IGNORECASE,
        ),
    ),
    # Bearer tokens
    (
        "bearer_token",
        re.compile(r"""Bearer\s+([A-Za-z0-9\-._~+/]+=*)""", re.IGNORECASE),
    ),
    # AWS-ish
    (
        "aws_access_key",
        re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    ),
    # Private key block
    (
        "private_key",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    ),
    # Google API key
    (
        "google_api_key",
        re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    ),
    # Slack token
    (
        "slack_token",
        re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"),
    ),
    # Generic long hex/base64 secrets in JS config
    (
        "long_secret_literal",
        re.compile(
            r"""(?:secret|token|password|passwd|pwd|key)\s*[=:]\s*['"]([A-Za-z0-9+/=_\-.]{20,})['"]""",
            re.IGNORECASE,
        ),
    ),
]


def extract_urls(html: str) -> list[str]:
    """Извлекает URL из href/src/action и некоторых текстовых мест"""
    soup = BeautifulSoup(html, "html.parser")

    urls: set[str] = set()

    for tag in soup.find_all(True):
        for attr in ("href", "src", "action", "data-url", "data-href", "data-src"):
            value = tag.get(attr)
            if value:
                urls.add(value.strip())

    # URL прямо в JavaScript/тексте
    urls.update(
        re.findall(
            r"""https?://[^\s"'<>\\]+""",
            html,
            flags=re.IGNORECASE,
        )
    )
    # Relative API-like paths in JS strings
    urls.update(
        re.findall(
            r"""['"](/(?:api|graphql|v[0-9]|admin|auth|oauth|token)[^'"]*)['"]""",
            html,
            flags=re.IGNORECASE,
        )
    )

    cleaned = []
    for u in urls:
        u = u.strip().rstrip("\\").rstrip(",;")
        if not u or u.startswith(("javascript:", "mailto:", "tel:", "data:", "#")):
            continue
        cleaned.append(u)

    return sorted(set(cleaned))[:MAX_URLS]


def find_interesting_urls(urls: list[str], base_url: str | None = None) -> list[dict]:
    result = []
    for url in urls:
        decoded = url.lower()
        for pattern in INTERESTING_PATTERNS:
            if re.search(pattern, decoded):
                abs_url = url
                if base_url and not urlparse(url).scheme:
                    abs_url = urljoin(base_url, url)
                result.append({
                    "url": url,
                    "absolute": abs_url,
                    "reason": pattern,
                })
                break
        if len(result) >= MAX_INTERESTING:
            break
    return result


def find_redirects(html: str, base_url: str | None = None) -> list[dict]:
    """meta refresh, JS location redirects, form actions that look like API"""
    soup = BeautifulSoup(html, "html.parser")
    out: list[dict] = []

    for meta in soup.find_all("meta", attrs={"http-equiv": re.compile(r"refresh", re.I)}):
        content = meta.get("content") or ""
        m = re.search(r"url\s*=\s*([^\s;]+)", content, re.I)
        if m:
            target = m.group(1).strip("'\"")
            abs_t = urljoin(base_url, target) if base_url else target
            out.append({"type": "meta_refresh", "target": target, "absolute": abs_t})

    for match in re.finditer(
        r"""(?:window\.)?location(?:\.href)?\s*=\s*['"]([^'"]+)['"]""",
        html,
        re.I,
    ):
        target = match.group(1)
        abs_t = urljoin(base_url, target) if base_url else target
        out.append({"type": "js_location", "target": target, "absolute": abs_t})

    for form in soup.find_all("form"):
        action = form.get("action") or ""
        method = (form.get("method") or "get").lower()
        if action and re.search(r"/api|/auth|/oauth|/token|/login", action, re.I):
            abs_t = urljoin(base_url, action) if base_url else action
            out.append({
                "type": "form_action",
                "method": method,
                "target": action,
                "absolute": abs_t,
            })

    seen = set()
    uniq = []
    for item in out:
        key = item.get("absolute") or item.get("target")
        if key in seen:
            continue
        seen.add(key)
        uniq.append(item)
    return uniq[:40]


def find_xss_candidates(html: str) -> list[dict]:
    """Ищет потенциальные XSS"""
    result = []
    for match in re.finditer(
        "|".join(XSS_PATTERNS),
        html,
        flags=re.IGNORECASE,
    ):
        line = html.count("\n", 0, match.start()) + 1
        snippet = html[max(0, match.start() - 40) : match.end() + 40]
        snippet = re.sub(r"\s+", " ", snippet).strip()
        result.append({
            "line": line,
            "match": match.group(0),
            "snippet": snippet[:120],
        })
        if len(result) >= MAX_XSS:
            break
    return result


def find_csrf_candidates(html: str) -> list[dict]:
    """
    Ищет POST-формы без очевидного CSRF-токена
    """
    soup = BeautifulSoup(html, "html.parser")
    result = []

    for form in soup.find_all("form"):
        method = (form.get("method") or "get").lower()
        action = form.get("action") or ""

        if method != "post":
            continue

        form_text = str(form)
        has_csrf = any(
            re.search(pattern, form_text, re.IGNORECASE)
            for pattern in CSRF_PATTERNS
        )

        if not has_csrf:
            result.append({
                "action": action,
                "method": method,
                "issue": "POST form without obvious CSRF token",
            })
        if len(result) >= MAX_CSRF:
            break

    return result


def find_secrets(html: str) -> list[dict]:
    """Ищет токены и секреты, которые не должны светиться в HTML/JS."""
    result = []
    seen = set()

    for kind, pattern in SECRET_PATTERNS:
        for match in pattern.finditer(html):
            raw = match.group(0)
            # маскируем значение
            if match.lastindex:
                secret_val = match.group(1)
                masked = secret_val[:4] + "…" + secret_val[-4:] if len(secret_val) > 10 else "***"
                display = raw.replace(secret_val, masked)
            else:
                display = raw[:12] + "…" if len(raw) > 16 else raw

            key = (kind, display)
            if key in seen:
                continue
            seen.add(key)

            line = html.count("\n", 0, match.start()) + 1
            result.append({
                "type": kind,
                "line": line,
                "match": display,
            })
            if len(result) >= MAX_SECRETS:
                return result
    return result


def analyze_html(html: str, base_url: str | None = None) -> dict:
    urls = extract_urls(html)
    return {
        "interesting_urls": find_interesting_urls(urls, base_url),
        "redirects": find_redirects(html, base_url),
        "xss_candidates": find_xss_candidates(html),
        "csrf_candidates": find_csrf_candidates(html),
        "secrets": find_secrets(html),
        "all_urls_count": len(urls),
        "all_urls": urls[:MAX_URLS],
    }


def _obs(ctx: dict) -> dict:
    raw = ctx.get("raw") or {}
    obs = raw.get("observations") or {}
    if not isinstance(obs, dict):
        return {}
    return obs


def _should_parse(ctx: dict) -> tuple[bool, str]:
    """
    Цепочка срабатывает только если primary/http_info видит text/html
    и размер тела больше MIN_HTML_SIZE.
    """
    obs = _obs(ctx)
    ctype = (obs.get("content_type") or "").lower()
    size = obs.get("body_size")
    try:
        size = int(size) if size is not None else None
    except (TypeError, ValueError):
        size = None

    if not ctype:
        # нет данных — всё равно пробуем (primary мог не записать)
        return True, "no content_type in observations, will probe"

    if "html" not in ctype and "xhtml" not in ctype:
        return False, f"content_type is not html: {ctype}"

    if size is not None and size < MIN_HTML_SIZE:
        return False, f"body_size {size} < MIN_HTML_SIZE {MIN_HTML_SIZE}"

    return True, f"content_type={ctype}, body_size={size}"


def _build_url(ctx: dict) -> str:
    ip = ctx.get("ip") or "127.0.0.1"
    port = int(ctx.get("port") or 80)
    service = (ctx.get("service") or "").lower()
    tls = service == "https" or port in (443, 8443, 9443)

    # предпочитаем известный домен
    host = ip
    domains = ctx.get("domains") or []
    for d in domains:
        name = d.get("name") if isinstance(d, dict) else str(d)
        if name and name not in ("", ".", "localhost"):
            host = name
            break

    scheme = "https" if tls else "http"
    default_port = 443 if tls else 80
    if port == default_port:
        return f"{scheme}://{host}/"
    return f"{scheme}://{host}:{port}/"


def get_html(url: str, verify_tls: bool = False) -> tuple[str | None, dict]:
    """
    Загружает HTML. Возвращает (text, meta).
    """
    if requests is None:
        return None, {"error": "requests not installed"}

    try:
        response = requests.get(
            url,
            timeout=FETCH_TIMEOUT,
            verify=verify_tls,
            headers={
                "User-Agent": "ActiveHostRecon/1.0",
                "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
                "Connection": "close",
            },
            allow_redirects=True,
        )
        text = response.text or ""
        meta = {
            "final_url": str(response.url),
            "status": response.status_code,
            "content_type": response.headers.get("Content-Type"),
            "body_size": len(response.content or b""),
            "redirect_history": [str(r.url) for r in response.history],
        }
        return text, meta
    except Exception as exc:
        return None, {"error": str(exc)}


def run(ctx: dict) -> dict:
    """
    Точка входа для registry.html_info

    Условие: text/html + size > MIN_HTML_SIZE (из primary observations)
    """
    ok, reason = _should_parse(ctx)
    if not ok:
        return {
            "ok": False,
            "skipped": True,
            "reason": reason,
        }

    url = _build_url(ctx)
    html, meta = get_html(url)

    if html is None:
        return {
            "ok": False,
            "error": meta.get("error", "fetch failed"),
            "url": url,
            "meta": meta,
            "gate": reason,
        }

    # повторная проверка после реального fetch
    ctype = (meta.get("content_type") or "").lower()
    size = meta.get("body_size") or 0
    if ctype and "html" not in ctype and "xhtml" not in ctype:
        return {
            "ok": False,
            "skipped": True,
            "reason": f"fetched content_type is not html: {ctype}",
            "url": url,
            "meta": meta,
            "gate": reason,
        }
    if size < MIN_HTML_SIZE:
        return {
            "ok": False,
            "skipped": True,
            "reason": f"fetched body_size {size} < {MIN_HTML_SIZE}",
            "url": url,
            "meta": meta,
            "gate": reason,
        }

    base = meta.get("final_url") or url
    analysis = analyze_html(html, base_url=base)

    summary = {
        "interesting": len(analysis["interesting_urls"]),
        "redirects": len(analysis["redirects"]),
        "xss": len(analysis["xss_candidates"]),
        "csrf": len(analysis["csrf_candidates"]),
        "secrets": len(analysis["secrets"]),
        "urls_total": analysis["all_urls_count"],
    }

    return {
        "ok": True,
        "url": url,
        "meta": meta,
        "gate": reason,
        "summary": summary,
        "interesting_urls": analysis["interesting_urls"],
        "redirects": analysis["redirects"],
        "xss_candidates": analysis["xss_candidates"],
        "csrf_candidates": analysis["csrf_candidates"],
        "secrets": analysis["secrets"],
        # all_urls может быть большим — оставляем count + sample
        "all_urls_sample": analysis["all_urls"][:40],
        "all_urls_count": analysis["all_urls_count"],
    }

def get_html_legacy(url: str) -> str:
    text, _ = get_html(url)
    return text or ""

