"""Fail-closed authentication confirmation primitives.

The first mode is intentionally narrow: prove that a session which completed
only the password step can force-browse a protected resource without completing
MFA.  It performs exactly three same-origin requests and never requests or
submits the MFA form.  Runtime credentials and session material are used only
on the wire; the returned evidence is bounded and redacted.
"""

from __future__ import annotations

import hashlib
import re
from html import unescape
from typing import Any, Dict, Iterable, Optional, Tuple
from urllib.parse import urlencode, urljoin, urlsplit

import aiohttp
from yarl import URL

from plugin_interface import ToolPlugin
from tools._agentic_exploration_common import read_limited


ALLOWED_ENGAGEMENTS = {"aggressive", "lab", "ctf"}
ALLOWED_MODES = {"mfa-simple-bypass"}
MAX_RESPONSE_BYTES = 64_000
MAX_EVIDENCE_CHARS = 10_000
MAX_CREDENTIAL_CHARS = 512
REDACTED_RUNTIME_SECRET = "<redacted-runtime-secret>"

_FIELD_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,80}$")
_SENSITIVE_HEADER_LINE = re.compile(
    r"(?im)^(?:authorization|cookie|set-cookie|proxy-authorization|x-csrf-token)\s*:.*$"
)
_SENSITIVE_FORM_VALUE = re.compile(
    r"(?i)(?P<prefix>(?:password|pass|passwd|csrf|token|session|cookie|authorization|secret|api[_-]?key)"
    r"[A-Za-z0-9_.-]*=)(?P<value>[^&\s]*)"
)
_SENSITIVE_JSON_VALUE = re.compile(
    r'(?P<prefix>"[^"\r\n]*(?:csrf|token|session|cookie|authorization|password|secret|api[_-]?key)'
    r'[^"\r\n]*"\s*:\s*)(?P<value>"(?:\\.|[^"\\])*"|[^,}\]\r\n]+)',
    re.I,
)


def _http_target(value: Any) -> Optional[str]:
    raw = str(value or "").strip()
    try:
        parsed = urlsplit(raw)
    except Exception:
        return None
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or len(raw) > 4_096
    ):
        return None
    path = parsed.path or "/"
    if not path.endswith("/"):
        path += "/"
    return f"{parsed.scheme}://{parsed.netloc}{path}"


def _relative_path(value: Any) -> Optional[str]:
    raw = str(value or "").strip()
    if not raw or len(raw) > 2_048 or not raw.startswith("/") or raw.startswith("//"):
        return None
    try:
        parsed = urlsplit(raw)
    except Exception:
        return None
    if parsed.scheme or parsed.netloc or parsed.fragment or "\r" in raw or "\n" in raw:
        return None
    return raw


def _field_name(value: Any) -> Optional[str]:
    raw = str(value or "").strip()
    return raw if _FIELD_NAME.fullmatch(raw) else None


def _same_origin(left: str, right: str) -> bool:
    a, b = urlsplit(left), urlsplit(right)

    def origin(parsed) -> Tuple[str, str, int]:
        return (
            parsed.scheme.lower(),
            (parsed.hostname or "").lower(),
            parsed.port or (443 if parsed.scheme == "https" else 80),
        )

    return origin(a) == origin(b)


def _path_and_query(url: str) -> str:
    parsed = urlsplit(url)
    return (parsed.path or "/") + (f"?{parsed.query}" if parsed.query else "")


def validate_probe_parameters(parameters: Dict[str, Any]) -> Tuple[bool, str]:
    target = _http_target(parameters.get("target") or parameters.get("url"))
    if not target:
        return False, "target must be a credential-free HTTP(S) base URL without query or fragment"

    if str(parameters.get("mode") or "").lower() not in ALLOWED_MODES:
        return False, "mode must be mfa-simple-bypass"
    if str(parameters.get("engagement") or "").lower() not in ALLOWED_ENGAGEMENTS:
        return False, "engagement must be aggressive, lab, or ctf"
    if parameters.get("allowUnsafeMethods") is not True:
        return False, "allowUnsafeMethods=true is required"

    for key in ("loginPath", "protectedPath", "mfaPath"):
        if not _relative_path(parameters.get(key)):
            return False, f"{key} must be a bounded same-origin relative path"
    for key in ("usernameField", "passwordField"):
        if not _field_name(parameters.get(key)):
            return False, f"{key} must be a valid form-field name"
    csrf_field = parameters.get("csrfField")
    if csrf_field is not None and not _field_name(csrf_field):
        return False, "csrfField must be a valid form-field name"

    username = str(parameters.get("username") or "")
    password = str(parameters.get("password") or "")
    account_marker = str(parameters.get("accountMarker") or "")
    if not username or len(username) > MAX_CREDENTIAL_CHARS:
        return False, "username is required and must be bounded"
    if not password or len(password) > MAX_CREDENTIAL_CHARS:
        return False, "password is required and must be bounded"
    if len(account_marker) < 3 or len(account_marker) > 512:
        return False, "accountMarker must contain 3 to 512 characters"

    try:
        timeout = int(parameters.get("timeoutSeconds") or 15)
    except (TypeError, ValueError):
        return False, "timeoutSeconds must be an integer"
    if timeout < 3 or timeout > 30:
        return False, "timeoutSeconds must be between 3 and 30"
    return True, ""


def extract_form_token(text: str, field_name: str) -> Optional[str]:
    for tag in re.findall(r"<input\b[^>]*>", text or "", re.I | re.S):
        name_match = re.search(r"\bname\s*=\s*(['\"])(.*?)\1", tag, re.I | re.S)
        if not name_match or unescape(name_match.group(2)) != field_name:
            continue
        value_match = re.search(r"\bvalue\s*=\s*(['\"])(.*?)\1", tag, re.I | re.S)
        if value_match:
            return unescape(value_match.group(2))[:1_024]
    return None


def _redact_sensitive_inputs(text: str) -> str:
    def redact_tag(match: re.Match[str]) -> str:
        tag = match.group(0)
        name_match = re.search(r"\bname\s*=\s*(['\"])(.*?)\1", tag, re.I | re.S)
        if not name_match or not re.search(
            r"csrf|token|session|cookie|authorization|password|secret|api[_-]?key",
            unescape(name_match.group(2)),
            re.I,
        ):
            return tag
        return re.sub(
            r"(\bvalue\s*=\s*)(['\"])(.*?)\2",
            lambda value_match: (
                f"{value_match.group(1)}{value_match.group(2)}"
                f"{REDACTED_RUNTIME_SECRET}{value_match.group(2)}"
            ),
            tag,
            flags=re.I | re.S,
        )

    return re.sub(r"<input\b[^>]*>", redact_tag, text, flags=re.I | re.S)


def sanitize_evidence_text(
    text: Any,
    secret_values: Iterable[Any] = (),
    max_chars: int = MAX_EVIDENCE_CHARS,
) -> str:
    sanitized = str(text or "").replace("\0", "")
    secrets = sorted(
        {str(value) for value in secret_values if value is not None and len(str(value)) >= 3},
        key=len,
        reverse=True,
    )
    for secret in secrets:
        sanitized = sanitized.replace(secret, REDACTED_RUNTIME_SECRET)

    def redact_header(match: re.Match[str]) -> str:
        # With CRLF input, ``.*`` includes the trailing CR before ``$``. Keep it
        # so redaction cannot turn a valid HTTP header/body delimiter into the
        # mixed ``\n\r\n`` form.
        line_ending_prefix = "\r" if match.group(0).endswith("\r") else ""
        return (
            f"{match.group(0).split(':', 1)[0]}: {REDACTED_RUNTIME_SECRET}"
            f"{line_ending_prefix}"
        )

    sanitized = _SENSITIVE_HEADER_LINE.sub(
        redact_header,
        sanitized,
    )
    sanitized = _SENSITIVE_FORM_VALUE.sub(
        lambda match: f"{match.group('prefix')}{REDACTED_RUNTIME_SECRET}",
        sanitized,
    )
    sanitized = _SENSITIVE_JSON_VALUE.sub(
        lambda match: f'{match.group("prefix")}"{REDACTED_RUNTIME_SECRET}"',
        sanitized,
    )
    sanitized = _redact_sensitive_inputs(sanitized)
    if len(sanitized) > max_chars:
        return sanitized[:max_chars] + "\n...[evidence excerpt truncated]"
    return sanitized


def _cookie_header(session: aiohttp.ClientSession, url: str) -> str:
    filtered = session.cookie_jar.filter_cookies(URL(url))
    return "; ".join(f"{key}={morsel.value}" for key, morsel in filtered.items())


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
        "User-Agent: xASM-Agentic-Authentication-Probe/1.0",
        "Accept: text/html,application/xhtml+xml",
    ]
    if body:
        lines.extend(
            [
                "Content-Type: application/x-www-form-urlencoded",
                f"Content-Length: {len(body.encode('utf-8'))}",
            ]
        )
    if cookie:
        lines.append(f"Cookie: {cookie}")
    return sanitize_evidence_text(
        "\r\n".join(lines) + "\r\n\r\n" + body,
        secret_values,
        MAX_EVIDENCE_CHARS,
    )


def _response_transcript(response: Dict[str, Any], secret_values: Iterable[Any]) -> str:
    lines = [f"HTTP/1.1 {response['status']} {response['reason']}"]
    for name in ("Content-Type", "Location", "Set-Cookie"):
        for value in response["headers"].getall(name, []):
            lines.append(f"{name}: {value}")
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


def build_nuclei_finding(target: str, verification: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "template-id": "xasm-mfa-simple-bypass-verified",
        "matcher-name": "mfa-forced-browsing",
        "type": "http",
        "host": target,
        "matched-at": str(verification.get("protectedUrl") or target),
        "info": {
            "name": "Verified Multi-Factor Authentication Bypass",
            "severity": "high",
            "description": (
                "A session that completed only the password step reached the configured "
                "protected account resource without submitting the MFA challenge."
            ),
            "remediation": (
                "Keep the session unauthenticated until every required factor succeeds and "
                "enforce the fully-verified MFA state on every protected resource."
            ),
            "classification": {"cwe-id": ["CWE-287"]},
        },
        "evidence": verification,
    }


class AuthenticationProbeTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "web:authentication_probe"

    @property
    def description(self) -> str:
        return (
            "Confirms a same-origin simple MFA forced-browsing bypass with exactly three "
            "requests: fetch login, submit the approved first-factor credentials, then "
            "request one protected resource without requesting or submitting an MFA code."
        )

    @property
    def schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Authorized application base URL"},
                "url": {"type": "string", "description": "Alias for target"},
                "mode": {"type": "string", "enum": sorted(ALLOWED_MODES)},
                "loginPath": {"type": "string"},
                "protectedPath": {"type": "string"},
                "mfaPath": {"type": "string"},
                "usernameField": {"type": "string"},
                "passwordField": {"type": "string"},
                "csrfField": {"type": "string"},
                "username": {"type": "string", "x-hidden": True},
                "password": {"type": "string", "x-hidden": True},
                "accountMarker": {"type": "string"},
                "engagement": {
                    "type": "string",
                    "enum": ["standard", *sorted(ALLOWED_ENGAGEMENTS)],
                },
                "allowUnsafeMethods": {"type": "boolean", "default": False},
                "timeoutSeconds": {"type": "integer", "minimum": 3, "maximum": 30},
            },
            "required": [
                "mode",
                "loginPath",
                "protectedPath",
                "mfaPath",
                "usernameField",
                "passwordField",
                "username",
                "password",
                "accountMarker",
                "engagement",
                "allowUnsafeMethods",
            ],
            "oneOf": [{"required": ["target"]}, {"required": ["url"]}],
        }

    @property
    def metadata(self) -> Dict[str, Any]:
        return {
            "category": "auth",
            "phase": 4,
            "domain": ["web"],
            "input_type": ["url", "credentials"],
            "output_type": ["findings", "authentication_proof"],
            "taxonomy_domain": ["web"],
            "lifecycle_phase": "exploit-test",
            "purpose_count": "single",
            "primary_purpose": "Confirm an MFA forced-browsing authentication bypass",
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
            "User-Agent": "xASM-Agentic-Authentication-Probe/1.0",
            "Accept": "text/html,application/xhtml+xml",
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

    async def execute(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        valid, reason = validate_probe_parameters(parameters)
        if not valid:
            return {"success": False, "fallback": False, "error": reason, "findings": []}

        target = _http_target(parameters.get("target") or parameters.get("url"))
        assert target is not None
        mode = str(parameters["mode"]).lower()
        engagement = str(parameters["engagement"]).lower()
        login_path = str(parameters["loginPath"])
        protected_path = str(parameters["protectedPath"])
        mfa_path = str(parameters["mfaPath"])
        login_url = urljoin(target, login_path)
        protected_url = urljoin(target, protected_path)
        username = str(parameters["username"])
        password = str(parameters["password"])
        account_marker = str(parameters["accountMarker"])
        csrf_field = str(parameters.get("csrfField") or "").strip()
        timeout = int(parameters.get("timeoutSeconds") or 15)

        request_count = 0
        csrf_token: Optional[str] = None
        evidence_steps = []
        timeout_config = aiohttp.ClientTimeout(total=timeout, connect=min(timeout, 8))
        try:
            cookie_jar = aiohttp.CookieJar(unsafe=True)
            async with aiohttp.ClientSession(timeout=timeout_config, cookie_jar=cookie_jar) as session:
                cookie_before_login = _cookie_header(session, login_url)
                login_response = await self._request(session, "GET", login_url)
                request_count += 1
                if login_response["truncated"] or login_response["status"] != 200:
                    raise ValueError("login page did not return a bounded HTTP 200 response")
                if account_marker in login_response["body"]:
                    raise ValueError("account marker is already present on the clean login page")
                if csrf_field:
                    csrf_token = extract_form_token(login_response["body"], csrf_field)
                    if not csrf_token:
                        raise ValueError("configured CSRF field was not found on the login page")
                evidence_steps.append(
                    build_http_evidence_step(
                        "login-page",
                        "GET",
                        login_url,
                        "",
                        cookie_before_login,
                        login_response,
                        (password, csrf_token),
                    )
                )

                form = {
                    str(parameters["usernameField"]): username,
                    str(parameters["passwordField"]): password,
                }
                if csrf_field and csrf_token:
                    form[csrf_field] = csrf_token
                login_body = urlencode(form)
                cookie_before_first_factor = _cookie_header(session, login_url)
                first_factor_response = await self._request(session, "POST", login_url, login_body)
                request_count += 1
                location = str(first_factor_response["headers"].get("Location") or "")
                mfa_url = urljoin(login_url, location)
                if (
                    first_factor_response["truncated"]
                    or first_factor_response["status"] not in {302, 303}
                    or not location
                    or not _same_origin(target, mfa_url)
                    or _path_and_query(mfa_url) != mfa_path
                ):
                    raise ValueError("first-factor response did not redirect to the configured MFA path")
                evidence_steps.append(
                    build_http_evidence_step(
                        "first-factor",
                        "POST",
                        login_url,
                        login_body,
                        cookie_before_first_factor,
                        first_factor_response,
                        (password, csrf_token),
                    )
                )

                cookie_before_bypass = _cookie_header(session, protected_url)
                protected_response = await self._request(session, "GET", protected_url)
                request_count += 1
                if (
                    protected_response["truncated"]
                    or protected_response["status"] != 200
                    or account_marker not in protected_response["body"]
                ):
                    raise ValueError("protected resource did not expose the configured account marker")
                evidence_steps.append(
                    build_http_evidence_step(
                        "protected-resource-bypass",
                        "GET",
                        protected_url,
                        "",
                        cookie_before_bypass,
                        protected_response,
                        (password, csrf_token),
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

        verification = {
            "verified": True,
            "fallback": False,
            "mode": mode,
            "target": target,
            "engagement": engagement,
            "loginPath": login_path,
            "protectedPath": protected_path,
            "mfaPath": mfa_path,
            "usernameField": str(parameters["usernameField"]),
            "passwordField": str(parameters["passwordField"]),
            "csrfField": csrf_field or None,
            "username": username,
            "accountMarker": account_marker,
            "firstFactorStatus": 302 if evidence_steps[1]["responseStatus"] == 302 else 303,
            "protectedStatus": 200,
            "mfaSubmitted": False,
            "requestCount": request_count,
            "protectedUrl": protected_url,
            "httpEvidence": {"version": 1, "steps": evidence_steps},
        }
        return {
            "success": True,
            "fallback": False,
            "target": target,
            "verification": verification,
            "findings": [build_nuclei_finding(target, verification)],
            "summary": {
                "verified": True,
                "mode": mode,
                "requestCount": request_count,
                "findingCount": 1,
            },
        }


def get_tool() -> AuthenticationProbeTool:
    return AuthenticationProbeTool()
