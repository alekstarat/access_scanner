import re
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import requests

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
]

# Признаки потенциальных XSS sinks/sources в HTML/JS.
XSS_PATTERNS = [
    r"innerHTML\s*=",
    r"outerHTML\s*=",
    r"insertAdjacentHTML\s*\(",
    r"document\.write\s*\(",
    r"\beval\s*\(",
    r"setTimeout\s*\(\s*[\"'`]",
    r"setInterval\s*\(\s*[\"'`]",
    r"location(?:\.href)?\s*=",
]

# Признаки отсутствия/подозрительного использования CSRF-защиты.
CSRF_PATTERNS = [
    r"csrf",
    r"xsrf",
    r"__requestverificationtoken",
    r"authenticity_token",
]


def extract_urls(html: str):
    """Извлекает URL из href/src/action и некоторых текстовых мест."""
    soup = BeautifulSoup(html, "html.parser")

    urls = set()

    for tag in soup.find_all(True):
        for attr in ("href", "src", "action"):
            value = tag.get(attr)

            if value:
                urls.add(value.strip())

    # Дополнительно ищем URL прямо в JavaScript/тексте.
    urls.update(
        re.findall(
            r"""https?://[^\s"'<>]+""",
            html,
            flags=re.IGNORECASE,
        )
    )

    return sorted(urls)

def get_html(url: str):
    """
    TODO: проверять есть ли смысл парсить html
    """
    response = requests.get(
        url
    )

    data = response.text

    return data

def find_interesting_urls(urls):
    result = []

    for url in urls:
        decoded = url.lower()

        for pattern in INTERESTING_PATTERNS:
            if re.search(pattern, decoded):
                result.append({
                    "url": url,
                    "reason": pattern,
                })
                break

    return result


def find_xss_candidates(html: str):
    """Ищет потенциальные XSS sinks."""
    result = []

    for match in re.finditer(
        "|".join(XSS_PATTERNS),
        html,
        flags=re.IGNORECASE,
    ):
        line = html.count("\n", 0, match.start()) + 1

        result.append({
            "line": line,
            "match": match.group(0),
        })

    return result


def find_csrf_candidates(html: str):
    """
    Ищет формы и проверяет наличие признаков CSRF-токена.
    Это эвристика, а не доказательство CSRF.
    """
    soup = BeautifulSoup(html, "html.parser")
    result = []

    for form in soup.find_all("form"):
        method = (form.get("method") or "get").lower()
        action = form.get("action") or ""

        if method == "post":
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

    return result


def analyze_html(html: str):
    urls = extract_urls(html)

    return {
        "interesting_urls": find_interesting_urls(urls),
        "xss_candidates": find_xss_candidates(html),
        "csrf_candidates": find_csrf_candidates(html),
        "all_urls": urls,
    }


if __name__ == "__main__":
    data = get_html("https://google.com/")

    print(find_interesting_urls(data))
    print()
    print(find_xss_candidates(data))
    # В реальном использовании сюда можно передать
    # HTML, полученный любым другим способом.
    # html = """
    # <html>
    #     <body>
    #         <form action="/api/profile" method="POST">
    #             <input name="name">
    #         </form>
    #
    #         <a href="/api/users">Users API</a>
    #         <a href="/.git/config">Git</a>
    #
    #         <script>
    #             element.innerHTML = userInput;
    #         </script>
    #     </body>
    # </html>
    # """

    # result = analyze_html(html)
    #
    # print("\n[+] Interesting URLs")
    # for item in result["interesting_urls"]:
    #     print(f"  {item['url']}")
    #
    # print("\n[+] XSS candidates")
    # for item in result["xss_candidates"]:
    #     print(f"  line {item['line']}: {item['match']}")
    #
    # print("\n[+] CSRF candidates")
    # for item in result["csrf_candidates"]:
    #     print(f"  {item['method']} {item['action']}")


