"""
Shared helpers for bounded agentic web exploration tools.
"""

import asyncio
import json
import re
from html import unescape
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import parse_qsl, urljoin, urlparse, urlunparse

import aiohttp


DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0 Safari/537.36 xASM-AgenticExplorer/1.0"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}

SITE_METADATA_PATHS = (
    "/main.json",
    "/resources.json",
    "/routes.json",
    "/sitemap.json",
    "/sitemap.xml",
    "/robots.txt",
)

RISKY_CLICK_WORDS = {
    "delete",
    "remove",
    "logout",
    "sign out",
    "purchase",
    "buy",
    "pay",
    "submit",
    "send",
    "save",
    "update",
    "confirm",
    "cancel subscription",
}


def normalize_url(value: str) -> str:
    value = str(value or "").strip()
    if not value:
        return value
    parsed = urlparse(value)
    if parsed.scheme:
        return value
    return f"https://{value}"


def same_origin(base: str, candidate: str) -> bool:
    try:
        b = urlparse(base)
        c = urlparse(candidate)
        if b.scheme not in ("http", "https") or c.scheme not in ("http", "https"):
            return False
        if b.scheme != c.scheme:
            return False

        def effective_port(parsed: Any) -> int:
            if parsed.port:
                return int(parsed.port)
            return 443 if parsed.scheme == "https" else 80

        return (b.hostname or "").lower() == (c.hostname or "").lower() and effective_port(b) == effective_port(c)
    except Exception:
        return False


def dedupe_keep_order(values: Iterable[str], limit: Optional[int] = None) -> List[str]:
    seen = set()
    output: List[str] = []
    for value in values:
        if not value or value in seen:
            continue
        seen.add(value)
        output.append(value)
        if limit and len(output) >= limit:
            break
    return output


def redact_headers(headers: Dict[str, str]) -> Dict[str, str]:
    redacted = {}
    for key, value in (headers or {}).items():
        lower = key.lower()
        if lower in {"authorization", "cookie", "set-cookie", "x-api-key"}:
            redacted[key] = "***REDACTED***"
        else:
            redacted[key] = value
    return redacted


def parse_headers(parameters: Dict[str, Any]) -> Dict[str, str]:
    headers: Dict[str, str] = dict(DEFAULT_HEADERS)
    provided = parameters.get("headers") or parameters.get("authHeaders")
    if isinstance(provided, dict):
        headers.update({str(k): str(v) for k, v in provided.items()})
    cookie = parameters.get("cookie") or parameters.get("authCookies")
    if cookie:
        headers["Cookie"] = str(cookie)
    return headers


async def fetch_text(
    session: aiohttp.ClientSession,
    url: str,
    *,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    data: Optional[str] = None,
    max_bytes: int = 2_000_000,
) -> Dict[str, Any]:
    async with session.request(method, url, headers=headers, data=data, allow_redirects=True) as response:
        body = await read_limited(response.content, max_bytes + 1)
        truncated = len(body) > max_bytes
        if truncated:
            body = body[:max_bytes]
        text = body.decode("utf-8", errors="replace").replace("\0", "")
        return {
            "url": str(response.url),
            "status": response.status,
            "headers": dict(response.headers),
            "text": text,
            "truncated": truncated,
        }


async def read_limited(stream: aiohttp.StreamReader, max_bytes: int, chunk_size: int = 64 * 1024) -> bytes:
    """Read up to max_bytes from an aiohttp stream.

    aiohttp's StreamReader.read(n) may return the currently available chunk
    before EOF. Agentic recon needs full JS/API bodies, so loop until EOF or
    the configured cap.
    """
    chunks = []
    total = 0
    while total < max_bytes:
        chunk = await stream.read(min(chunk_size, max_bytes - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    return b"".join(chunks)


def extract_attr(tag: str, attr: str) -> Optional[str]:
    match = re.search(rf'\b{re.escape(attr)}\s*=\s*([\'"])(.*?)\1', tag, re.I | re.S)
    if match:
        return unescape(match.group(2).strip())
    match = re.search(rf"\b{re.escape(attr)}\s*=\s*([^\s>]+)", tag, re.I | re.S)
    if match:
        return unescape(match.group(1).strip())
    return None


def extract_html_map(html: str, base_url: str, max_items: int = 200) -> Dict[str, Any]:
    title_match = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
    title = re.sub(r"\s+", " ", unescape(title_match.group(1))).strip() if title_match else ""

    links = []
    scripts = []
    stylesheets = []
    forms = []
    buttons = []
    inputs = []

    for tag in re.findall(r"<a\b[^>]*>", html, re.I | re.S):
        href = extract_attr(tag, "href")
        if href and not href.startswith(("javascript:", "mailto:", "tel:")):
            links.append(urljoin(base_url, href))

    for tag in re.findall(r"<script\b[^>]*>", html, re.I | re.S):
        src = extract_attr(tag, "src")
        if src:
            scripts.append(urljoin(base_url, src))

    for tag in re.findall(r"<link\b[^>]*>", html, re.I | re.S):
        href = extract_attr(tag, "href")
        rel = (extract_attr(tag, "rel") or "").lower()
        if href and "stylesheet" in rel:
            stylesheets.append(urljoin(base_url, href))

    for form_html in re.findall(r"<form\b[^>]*>.*?</form>", html, re.I | re.S):
        open_tag = re.match(r"<form\b[^>]*>", form_html, re.I | re.S)
        action = extract_attr(open_tag.group(0), "action") if open_tag else None
        method = (extract_attr(open_tag.group(0), "method") if open_tag else None) or "GET"
        field_names = []
        for input_tag in re.findall(r"<(?:input|textarea|select)\b[^>]*>", form_html, re.I | re.S):
            name = extract_attr(input_tag, "name")
            field_type = extract_attr(input_tag, "type") or input_tag.split()[0].lstrip("<")
            if name:
                field_names.append({"name": name, "type": field_type.lower()})
        forms.append(
            {
                "action": urljoin(base_url, action or base_url),
                "method": method.upper(),
                "fields": field_names,
                "fieldCount": len(field_names),
            }
        )

    for tag, body in re.findall(r"(<button\b[^>]*>)(.*?)</button>", html, re.I | re.S):
        label = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", body)).strip()
        buttons.append({"label": unescape(label), "type": extract_attr(tag, "type") or "button"})

    for tag in re.findall(r"<input\b[^>]*>", html, re.I | re.S):
        name = extract_attr(tag, "name") or extract_attr(tag, "id") or ""
        field_type = (extract_attr(tag, "type") or "text").lower()
        if name or field_type in {"email", "password", "search", "file"}:
            inputs.append({"name": name, "type": field_type})

    return {
        "title": title,
        "links": dedupe_keep_order(links, max_items),
        "scripts": dedupe_keep_order(scripts, max_items),
        "stylesheets": dedupe_keep_order(stylesheets, max_items),
        "forms": forms[:max_items],
        "buttons": buttons[:max_items],
        "inputs": inputs[:max_items],
    }


def extract_js_intel(text: str, base_url: str, max_items: int = 300) -> Dict[str, Any]:
    urls = []
    routes = []
    api_paths = []
    api_endpoints = []
    graphql_hints = []
    potential_secrets = []

    string_url_pattern = r"([`'\"])((?:https?:)?//[^`'\"\s<>]+|/[A-Za-z0-9_./{}:$?&=%~+@${}-]{2,})\1"
    for match in re.finditer(string_url_pattern, text):
        value = match.group(2)
        if value.startswith("//"):
            value = f"{urlparse(base_url).scheme}:{value}"
        absolute = urljoin(base_url, value)
        if value.startswith("http"):
            urls.append(absolute)
        elif value.startswith("/"):
            routes.append(absolute)
            if re.search(r"/(?:api|graphql|v\d+|rest|rpc)(?:/|$)", value, re.I):
                api_paths.append(absolute)
                api_endpoints.append({"url": absolute, "method": "UNKNOWN", "source": "string-literal"})

    for endpoint in extract_js_http_calls(text, base_url, max_items):
        api_endpoints.append(endpoint)
        endpoint_url = endpoint.get("url")
        if endpoint_url:
            api_paths.append(endpoint_url)
            routes.append(endpoint_url)

    if re.search(r"\b(graphql|gql|apollo|urql)\b", text, re.I):
        graphql_hints.extend([urljoin(base_url, "/graphql"), urljoin(base_url, "/api/graphql")])

    secret_patterns = {
        "google_api_key": r"AIza[0-9A-Za-z_-]{20,}",
        "aws_access_key": r"AKIA[0-9A-Z]{16}",
        "generic_bearer": r"Bearer\s+[A-Za-z0-9._~+/=-]{20,}",
        "jwt": r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
    }
    for kind, pattern in secret_patterns.items():
        for found in re.findall(pattern, text):
            value = found if isinstance(found, str) else found[0]
            potential_secrets.append({"type": kind, "sample": f"{value[:8]}...{value[-4:]}"})

    api_endpoints = dedupe_objects_by_key(api_endpoints, "url", max_items)
    hypotheses = build_js_hypotheses(
        text,
        base_url,
        routes=dedupe_keep_order(routes, max_items),
        api_paths=dedupe_keep_order(api_paths, max_items),
        api_endpoints=api_endpoints,
        potential_secrets=potential_secrets,
        max_items=max_items,
    )

    return {
        "urls": dedupe_keep_order(urls, max_items),
        "routes": dedupe_keep_order(routes, max_items),
        "apiPaths": dedupe_keep_order(api_paths, max_items),
        "apiEndpoints": api_endpoints,
        "graphqlHints": dedupe_keep_order(graphql_hints, 20),
        "potentialSecrets": potential_secrets[:50],
        "hypotheses": hypotheses,
        "interestingParameters": extract_js_interesting_parameters(routes, api_paths, max_items),
    }


def dedupe_objects_by_key(values: Iterable[Dict[str, Any]], key: str, limit: Optional[int] = None) -> List[Dict[str, Any]]:
    seen = set()
    output: List[Dict[str, Any]] = []
    for value in values:
        if not isinstance(value, dict):
            continue
        marker = str(value.get(key) or "").strip()
        if not marker or marker in seen:
            continue
        seen.add(marker)
        output.append(value)
        if limit and len(output) >= limit:
            break
    return output


def extract_js_http_calls(text: str, base_url: str, max_items: int = 300) -> List[Dict[str, Any]]:
    endpoints: List[Dict[str, Any]] = []

    def add(raw_url: str, method: str, source: str, pos: int) -> None:
        if len(endpoints) >= max_items:
            return
        if not raw_url or raw_url.startswith(("data:", "javascript:", "mailto:", "tel:")):
            return
        url = urljoin(base_url, raw_url)
        endpoints.append(
            {
                "url": url,
                "method": method.upper() if method else "UNKNOWN",
                "source": source,
                "evidence": redact_js_excerpt(text[max(0, pos - 120): pos + 220]),
            }
        )

    for match in re.finditer(r"\bfetch\s*\(\s*([`'\"])(.*?)\1(?P<opts>.{0,450})", text, re.I | re.S):
        raw_url = match.group(2)
        opts = match.group("opts") or ""
        method_match = re.search(r"\bmethod\s*:\s*([`'\"])(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\1", opts, re.I)
        add(raw_url, method_match.group(2) if method_match else "GET", "fetch", match.start())

    for match in re.finditer(
        r"\b(?:axios|client|api|http)\s*\.\s*(get|post|put|patch|delete|head)\s*\(\s*([`'\"])(.*?)\2",
        text,
        re.I | re.S,
    ):
        add(match.group(3), match.group(1), "axios-like", match.start())

    for match in re.finditer(r"\b(?:url|endpoint|path|route)\s*:\s*([`'\"])(/[A-Za-z0-9_./{}:$?&=%~+@${}-]{2,})\1", text, re.I):
        add(match.group(2), "UNKNOWN", "object-property", match.start())

    return dedupe_objects_by_key(endpoints, "url", max_items)


def extract_js_interesting_parameters(routes: Iterable[str], api_paths: Iterable[str], max_items: int = 300) -> List[Dict[str, Any]]:
    interesting: List[Dict[str, Any]] = []
    category_by_name = {
        "url": "redirect_or_ssrf",
        "next": "redirect_or_ssrf",
        "redirect": "redirect_or_ssrf",
        "return": "redirect_or_ssrf",
        "continue": "redirect_or_ssrf",
        "dest": "redirect_or_ssrf",
        "destination": "redirect_or_ssrf",
        "file": "file_path_candidate",
        "path": "file_path_candidate",
        "content": "file_path_candidate",
        "template": "file_path_candidate",
        "page": "file_path_candidate",
        "include": "file_path_candidate",
        "doc": "file_path_candidate",
        "document": "file_path_candidate",
        "id": "idor_candidate",
        "uid": "idor_candidate",
        "user": "idor_candidate",
        "account": "idor_candidate",
        "tenant": "idor_candidate",
        "order": "idor_candidate",
    }
    for url in dedupe_keep_order([*routes, *api_paths], max_items):
        parsed = urlparse(str(url))
        for name, value in parse_qsl(parsed.query, keep_blank_values=True):
            lower = name.lower()
            category = category_by_name.get(lower)
            if not category and lower.endswith("_id"):
                category = "idor_candidate"
            if category:
                interesting.append({"name": name, "url": url, "categories": [category], "sample": value[:80]})
                if len(interesting) >= max_items:
                    return interesting
    return interesting


def build_js_hypotheses(
    text: str,
    base_url: str,
    *,
    routes: List[str],
    api_paths: List[str],
    api_endpoints: List[Dict[str, Any]],
    potential_secrets: List[Dict[str, Any]],
    max_items: int = 300,
) -> List[Dict[str, Any]]:
    hypotheses: List[Dict[str, Any]] = []

    def add(category: str, risk: str, confidence: float, reason: str, *, endpoint: Optional[str] = None, evidence: Optional[str] = None, tools: Optional[List[str]] = None) -> None:
        if len(hypotheses) >= max_items:
            return
        hypotheses.append(
            {
                "category": category,
                "risk": risk,
                "confidence": round(max(0.0, min(float(confidence), 1.0)), 2),
                "source": "client_js",
                "script": base_url,
                "endpoint": endpoint,
                "reason": reason,
                "evidence": redact_js_excerpt(evidence or ""),
                "recommendedTools": tools or ["param:exploit_probe", "api:access_control_probe"],
            }
        )

    sensitive_words = re.compile(
        r"/(?:admin|internal|debug|config|settings|merchant|account|accounts|user|users|order|orders|transaction|transactions|transfer|payment|billing|reservation|reservations|token|session|secret|keys?)(?:/|$|[?#])",
        re.I,
    )
    idor_words = re.compile(r"(?:[/_-](?:id|uid|user|account|tenant|order|transaction|reservation)(?:[/_=-]|$)|\$\{\s*(?:id|userId|accountId|orderId|tenantId)[^}]*\}|[?&](?:id|uid|user|account|tenant|order)=[^&]*)", re.I)
    file_words = re.compile(r"[?&](?:file|path|content|template|page|include|doc|document|view|full_path)=", re.I)
    redirect_words = re.compile(r"[?&](?:url|next|redirect|return|continue|dest|destination|redir|callback)=", re.I)

    for endpoint in dedupe_keep_order([*routes, *api_paths], max_items):
        if sensitive_words.search(endpoint):
            add(
                "sensitive_client_route",
                "MEDIUM",
                0.72,
                "Client-side JavaScript references a sensitive-looking route that should be access-control tested.",
                endpoint=endpoint,
                evidence=endpoint,
                tools=["curl:request", "api:access_control_probe"],
            )
        if idor_words.search(endpoint):
            add(
                "idor_candidate",
                "HIGH",
                0.78,
                "Client-side JavaScript exposes an object-identifier route or parameter suitable for IDOR/BOLA mutation tests.",
                endpoint=endpoint,
                evidence=endpoint,
                tools=["api:access_control_probe", "exploit:chain"],
            )
        if file_words.search(endpoint):
            add(
                "file_path_candidate",
                "HIGH",
                0.82,
                "Client-side JavaScript exposes file/path-style parameters that should be validated for path traversal or LFI.",
                endpoint=endpoint,
                evidence=endpoint,
                tools=["lfi:file_exposure_probe", "param:exploit_probe"],
            )
        if redirect_words.search(endpoint):
            add(
                "open_redirect_candidate",
                "MEDIUM",
                0.8,
                "Client-side JavaScript exposes redirect/URL parameters that should be validated for open redirect or SSRF-like behavior.",
                endpoint=endpoint,
                evidence=endpoint,
                tools=["param:exploit_probe", "curl:request"],
            )

    for endpoint in api_endpoints[:max_items]:
        url = str(endpoint.get("url") or "")
        method = str(endpoint.get("method") or "UNKNOWN").upper()
        evidence = endpoint.get("evidence") or url
        if method in {"POST", "PUT", "PATCH", "DELETE"} or sensitive_words.search(url):
            add(
                "state_changing_api_candidate",
                "HIGH" if method in {"PUT", "PATCH", "DELETE"} else "MEDIUM",
                0.76,
                f"Client-side JavaScript references a {method} API call; test authorization and object ownership with bounded probes.",
                endpoint=url,
                evidence=evidence,
                tools=["api:access_control_probe", "vuln:chain_probe"],
            )

    auth_storage_match = re.search(
        r"\b(localStorage|sessionStorage)\s*\.\s*(?:getItem|setItem)\s*\(\s*([`'\"])(token|jwt|auth|role|isAdmin|user|merchant|session)[^`'\"]*\2",
        text,
        re.I,
    )
    if auth_storage_match:
        add(
            "client_side_auth_state",
            "MEDIUM",
            0.66,
            "Client-side JavaScript stores or reads auth/role/session state in browser storage; compare authenticated and anonymous behavior.",
            evidence=text[max(0, auth_storage_match.start() - 120): auth_storage_match.end() + 120],
            tools=["browser:traffic_capture", "api:access_control_probe"],
        )

    dangerous_sink_match = re.search(r"\b(innerHTML|outerHTML|document\.write|eval|new\s+Function|location\.(?:href|assign|replace))\b", text, re.I)
    if dangerous_sink_match:
        add(
            "client_side_dangerous_sink",
            "MEDIUM",
            0.62,
            "Client-side JavaScript uses a sink that may become exploitable when fed attacker-controlled route/query data.",
            evidence=text[max(0, dangerous_sink_match.start() - 140): dangerous_sink_match.end() + 180],
            tools=["param:exploit_probe", "dalfox:xss_scan"],
        )

    default_cred_match = re.search(
        r"([`'\"](?:admin|test|demo|merchant|user)[`'\"]\s*[,=:]\s*[`'\"](?:admin|password|123456|test|demo|merchant|user)[`'\"]|password\s*[:=]\s*[`'\"](?:admin|password|123456|test|demo)[`'\"])",
        text,
        re.I,
    )
    if default_cred_match:
        add(
            "default_credential_hint",
            "HIGH",
            0.7,
            "Client-side JavaScript contains default/demo credential-looking literals; attempt bounded default credential validation only in authorized aggressive/lab mode.",
            evidence=text[max(0, default_cred_match.start() - 120): default_cred_match.end() + 120],
            tools=["exploit:chain", "authentication:ai_browser_login"],
        )

    if potential_secrets:
        add(
            "client_side_secret_signal",
            "HIGH",
            0.74,
            "Client-side JavaScript contains secret-like tokens or API keys; capture minimal redacted evidence and verify exposure context.",
            evidence=json.dumps(potential_secrets[:5]),
            tools=["curl:request", "web:security_controls_probe"],
        )

    return dedupe_js_hypotheses(hypotheses, max_items)


def dedupe_js_hypotheses(hypotheses: List[Dict[str, Any]], max_items: int = 300) -> List[Dict[str, Any]]:
    seen = set()
    output = []
    for item in hypotheses:
        key = (item.get("category"), item.get("endpoint"), item.get("evidence"))
        if key in seen:
            continue
        seen.add(key)
        output.append(item)
        if len(output) >= max_items:
            break
    return output


def redact_js_excerpt(value: str) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    text = re.sub(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "[REDACTED_JWT]", text)
    text = re.sub(r"Bearer\s+[A-Za-z0-9._~+/=-]{20,}", "Bearer [REDACTED]", text, flags=re.I)
    text = re.sub(r"AIza[0-9A-Za-z_-]{20,}", "AIza[REDACTED]", text)
    text = re.sub(r"AKIA[0-9A-Z]{16}", "AKIA[REDACTED]", text)
    return text[:500]


def extract_json_urls(text: str, base_url: str, max_items: int = 500) -> List[str]:
    urls: List[str] = []

    def add_candidate(value: Any) -> None:
        if len(urls) >= max_items or not isinstance(value, str):
            return
        candidate = value.strip()
        if not candidate or candidate.startswith(("#", "javascript:", "mailto:", "tel:")):
            return
        if candidate.startswith(("http://", "https://", "/")):
            absolute = urljoin(base_url, candidate)
            if same_origin(base_url, absolute):
                urls.append(absolute)

    try:
        parsed = json.loads(text)
    except Exception:
        parsed = None

    def walk(value: Any, key_hint: str = "") -> None:
        if len(urls) >= max_items:
            return
        if isinstance(value, dict):
            for key, child in value.items():
                key_lower = str(key).lower()
                if key_lower in {"url", "href", "path", "route", "link", "endpoint", "action"}:
                    add_candidate(child)
                walk(child, key_lower)
        elif isinstance(value, list):
            for child in value:
                walk(child, key_hint)
        elif key_hint in {"url", "href", "path", "route", "link", "endpoint", "action"}:
            add_candidate(value)

    if parsed is not None:
        walk(parsed)

    # Also handle JavaScript-ish or malformed JSON blobs that expose route strings.
    for match in re.finditer(r'["\']((?:https?://|/)[A-Za-z0-9_./{}:$?&=%~+@-]{2,})["\']', text):
        add_candidate(match.group(1))

    return dedupe_keep_order(urls, max_items)


async def discover_site_metadata_urls(
    session: aiohttp.ClientSession,
    target: str,
    *,
    headers: Optional[Dict[str, str]] = None,
    max_urls: int = 500,
) -> List[str]:
    discovered: List[str] = []
    for path in SITE_METADATA_PATHS:
        if len(discovered) >= max_urls:
            break
        url = urljoin(target, path)
        try:
            fetched = await fetch_text(session, url, headers=headers, max_bytes=1_200_000)
        except Exception:
            continue
        if int(fetched.get("status") or 0) >= 400:
            continue
        text = fetched.get("text", "")
        content_type = str((fetched.get("headers") or {}).get("Content-Type") or "").lower()
        if "json" in content_type or path.endswith(".json"):
            discovered.extend(extract_json_urls(text, fetched.get("url") or url, max_urls))
        elif "xml" in content_type or path.endswith(".xml"):
            discovered.extend(urljoin(target, value) for value in re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", text, re.I))
        elif path.endswith("robots.txt"):
            for line in text.splitlines():
                if ":" not in line:
                    continue
                key, value = line.split(":", 1)
                if key.strip().lower() in {"allow", "disallow", "sitemap"}:
                    discovered.append(urljoin(target, value.strip()))
        else:
            mapped = extract_html_map(text, fetched.get("url") or url)
            discovered.extend(mapped.get("links", []))
            discovered.extend(extract_js_intel(text, fetched.get("url") or url).get("routes", []))

    return [
        url
        for url in dedupe_keep_order(discovered, max_urls)
        if same_origin(target, url) and urlparse(url).path not in {"", "/"}
    ]


def classify_parameters(urls: Iterable[str], forms: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    params = {}
    enriched_urls = []
    interesting = []

    for url in urls:
        parsed = urlparse(str(url))
        query = parse_qsl(parsed.query, keep_blank_values=True)
        if not query:
            continue
        for name, value in query:
            categories = []
            lower = name.lower()
            if lower in {"url", "next", "redirect", "return", "continue", "callback", "dest", "destination", "redir"}:
                categories.append("redirect_or_ssrf")
            if lower in {"id", "uid", "user", "account", "tenant", "org", "order"} or lower.endswith("_id"):
                categories.append("idor_candidate")
            if lower in {"q", "s", "search", "query", "keyword"}:
                categories.append("search_xss_candidate")
            if lower in {"file", "path", "template", "page", "include", "content", "doc", "document", "view"}:
                categories.append("file_path_candidate")
            if lower in {"token", "key", "code", "state", "nonce"}:
                categories.append("token_like")
            params.setdefault(name, {"count": 0, "samples": [], "categories": set()})
            params[name]["count"] += 1
            if len(params[name]["samples"]) < 5:
                params[name]["samples"].append({"url": url, "value": value[:80]})
            params[name]["categories"].update(categories)
            if categories:
                interesting.append({"name": name, "url": url, "categories": categories})
        enriched_urls.append(url)

    form_fields = []
    for form in forms or []:
        # W.37 — defensive isinstance guard; upstream may pass non-dict.
        if not isinstance(form, dict):
            continue
        for field in form.get("fields", []) or []:
            if not isinstance(field, dict):
                continue
            name = field.get("name")
            if name:
                form_fields.append(
                    {
                        "name": name,
                        "type": field.get("type"),
                        "action": form.get("action"),
                        "method": form.get("method"),
                    }
                )

    normalized = {
        name: {
            "count": value["count"],
            "samples": value["samples"],
            "categories": sorted(value["categories"]),
        }
        for name, value in sorted(params.items())
    }
    return {
        "parameters": normalized,
        "parameterCount": len(normalized),
        "interestingParameters": interesting[:100],
        "formFields": form_fields[:200],
        "urlsWithParams": dedupe_keep_order(enriched_urls, 300),
    }


async def run_process(cmd: List[str], timeout: int = 120) -> Dict[str, Any]:
    process = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        process.kill()
        await process.wait()
        return {"returnCode": -1, "stdout": "", "stderr": f"timeout after {timeout}s", "timedOut": True}
    return {
        "returnCode": process.returncode,
        "stdout": stdout.decode("utf-8", errors="replace").replace("\0", ""),
        "stderr": stderr.decode("utf-8", errors="replace").replace("\0", ""),
        "timedOut": False,
    }
