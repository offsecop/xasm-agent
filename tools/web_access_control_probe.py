"""Fail-closed access-control confirmation primitives.

The first mode proves one narrow IDOR variant: a foreign object is present in
the body of a denial redirect. It performs exactly five same-origin requests,
links the leaked value to a successful confirmation by SHA-256, and returns
only bounded, sanitized HTTP evidence.
"""

from __future__ import annotations

import hashlib
import re
from html import unescape
from typing import Any, Dict, Iterable, Optional, Tuple
from urllib.parse import urlencode, urljoin, urlsplit

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


ALLOWED_MODES = {"idor-redirect-leak"}
MAX_MARKER_CHARS = 512
MAX_SECRET_CHARS = 256
_SECRET_TOKEN = re.compile(r"[A-Za-z0-9._~+/=-]{8,256}")


def validate_probe_parameters(parameters: Dict[str, Any]) -> Tuple[bool, str]:
    target = _http_target(parameters.get("target") or parameters.get("url"))
    if not target:
        return False, "target must be a credential-free HTTP(S) base URL without query or fragment"

    if str(parameters.get("mode") or "").lower() not in ALLOWED_MODES:
        return False, "mode must be idor-redirect-leak"
    if str(parameters.get("engagement") or "").lower() not in ALLOWED_ENGAGEMENTS:
        return False, "engagement must be aggressive, lab, or ctf"
    if parameters.get("allowUnsafeMethods") is not True:
        return False, "allowUnsafeMethods=true is required"

    for key in ("loginPath", "ownPath", "foreignPath", "denialPath", "solutionPath"):
        if not _relative_path(parameters.get(key)):
            return False, f"{key} must be a bounded same-origin relative path"
    for key in ("usernameField", "passwordField", "solutionField"):
        if not _field_name(parameters.get(key)):
            return False, f"{key} must be a valid form-field name"
    csrf_field = parameters.get("csrfField")
    if csrf_field is not None and not _field_name(csrf_field):
        return False, "csrfField must be a valid form-field name"

    username = str(parameters.get("username") or "")
    password = str(parameters.get("password") or "")
    if not username or len(username) > MAX_CREDENTIAL_CHARS:
        return False, "username is required and must be bounded"
    if not password or len(password) > MAX_CREDENTIAL_CHARS:
        return False, "password is required and must be bounded"

    markers = {
        key: str(parameters.get(key) or "")
        for key in ("ownMarker", "foreignMarker", "secretLabel", "solutionSuccessMarker")
    }
    for key, value in markers.items():
        if len(value) < 3 or len(value) > MAX_MARKER_CHARS:
            return False, f"{key} must contain 3 to {MAX_MARKER_CHARS} characters"
    if markers["ownMarker"] == markers["foreignMarker"]:
        return False, "ownMarker and foreignMarker must be distinct"

    try:
        timeout = int(parameters.get("timeoutSeconds") or 15)
    except (TypeError, ValueError):
        return False, "timeoutSeconds must be an integer"
    if timeout < 3 or timeout > 30:
        return False, "timeoutSeconds must be between 3 and 30"
    return True, ""


def extract_secret_after_marker(text: str, marker: str) -> Optional[str]:
    """Extract one bounded token immediately following a literal text marker."""

    raw = str(text or "")
    index = raw.find(marker)
    if index < 0:
        return None
    tail = raw[index + len(marker) : index + len(marker) + 1_024]
    visible_tail = unescape(re.sub(r"<[^>]{0,512}>", " ", tail))
    match = _SECRET_TOKEN.search(visible_tail)
    if not match:
        return None
    value = match.group(0)
    if len(value) > MAX_SECRET_CHARS or value == REDACTED_RUNTIME_SECRET:
        return None
    return value


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
        "User-Agent: xASM-Agentic-Access-Control-Probe/1.0",
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
        "template-id": "xasm-idor-redirect-body-leak-verified",
        "matcher-name": "idor-redirect-body-data-leak",
        "type": "http",
        "host": target,
        "matched-at": str(verification.get("foreignUrl") or target),
        "info": {
            "name": "Verified IDOR Data Leakage in Redirect Response",
            "severity": "high",
            "description": (
                "A low-privilege session retrieved a different user's object and sensitive "
                "value in the body of a denial redirect; the leaked value was accepted by "
                "the configured confirmation endpoint."
            ),
            "remediation": (
                "Authorize every object access before loading or rendering its data. Return "
                "a minimal denial response and use indirect, ownership-bound identifiers."
            ),
            "classification": {"cwe-id": ["CWE-639", "CWE-862"]},
        },
        "evidence": verification,
    }


class AccessControlProbeTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "web:access_control_probe"

    @property
    def description(self) -> str:
        return (
            "Confirms one same-origin IDOR redirect-body leak with exactly five requests: "
            "login page, approved login, own-object baseline, foreign-object denial, and "
            "submission of the leaked value to a confirmation endpoint."
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
                "ownPath": {"type": "string"},
                "foreignPath": {"type": "string"},
                "denialPath": {"type": "string"},
                "solutionPath": {"type": "string"},
                "usernameField": {"type": "string"},
                "passwordField": {"type": "string"},
                "csrfField": {"type": "string"},
                "solutionField": {"type": "string"},
                "username": {"type": "string", "x-hidden": True},
                "password": {"type": "string", "x-hidden": True},
                "ownMarker": {"type": "string"},
                "foreignMarker": {"type": "string"},
                "secretLabel": {"type": "string"},
                "solutionSuccessMarker": {"type": "string"},
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
                "ownPath",
                "foreignPath",
                "denialPath",
                "solutionPath",
                "usernameField",
                "passwordField",
                "solutionField",
                "username",
                "password",
                "ownMarker",
                "foreignMarker",
                "secretLabel",
                "solutionSuccessMarker",
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
            "output_type": ["findings", "access_control_proof"],
            "taxonomy_domain": ["web"],
            "lifecycle_phase": "exploit-test",
            "purpose_count": "single",
            "primary_purpose": "Confirm an IDOR redirect-body data leak",
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
            "User-Agent": "xASM-Agentic-Access-Control-Probe/1.0",
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

    async def execute(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        valid, reason = validate_probe_parameters(parameters)
        if not valid:
            return {"success": False, "fallback": False, "error": reason, "findings": []}

        target = _http_target(parameters.get("target") or parameters.get("url"))
        assert target is not None
        paths = {
            key: str(parameters[key])
            for key in ("loginPath", "ownPath", "foreignPath", "denialPath", "solutionPath")
        }
        urls = {key: urljoin(target, value) for key, value in paths.items()}
        username = str(parameters["username"])
        password = str(parameters["password"])
        own_marker = str(parameters["ownMarker"])
        foreign_marker = str(parameters["foreignMarker"])
        secret_label = str(parameters["secretLabel"])
        success_marker = str(parameters["solutionSuccessMarker"])
        csrf_field = str(parameters.get("csrfField") or "").strip()
        timeout = int(parameters.get("timeoutSeconds") or 15)

        request_count = 0
        evidence_steps = []
        csrf_token: Optional[str] = None
        own_secret: Optional[str] = None
        foreign_secret: Optional[str] = None
        timeout_config = aiohttp.ClientTimeout(total=timeout, connect=min(timeout, 8))
        try:
            cookie_jar = aiohttp.CookieJar(unsafe=True)
            async with aiohttp.ClientSession(timeout=timeout_config, cookie_jar=cookie_jar) as session:
                cookie = _cookie_header(session, urls["loginPath"])
                login_page = await self._request(session, "GET", urls["loginPath"])
                request_count += 1
                if login_page["truncated"] or login_page["status"] != 200:
                    raise ValueError("login page did not return a bounded HTTP 200 response")
                if own_marker in login_page["body"] or foreign_marker in login_page["body"]:
                    raise ValueError("an account marker is already present on the clean login page")
                if csrf_field:
                    csrf_token = extract_form_token(login_page["body"], csrf_field)
                    if not csrf_token:
                        raise ValueError("configured CSRF field was not found on the login page")
                evidence_steps.append(
                    build_http_evidence_step(
                        "login-page", "GET", urls["loginPath"], "", cookie, login_page,
                        (password, csrf_token),
                    )
                )

                login_form = {
                    str(parameters["usernameField"]): username,
                    str(parameters["passwordField"]): password,
                }
                if csrf_field and csrf_token:
                    login_form[csrf_field] = csrf_token
                login_body = urlencode(login_form)
                cookie = _cookie_header(session, urls["loginPath"])
                login_response = await self._request(
                    session, "POST", urls["loginPath"], login_body
                )
                request_count += 1
                login_location = str(login_response["headers"].get("Location") or "")
                login_redirect = urljoin(urls["loginPath"], login_location)
                if (
                    login_response["truncated"]
                    or login_response["status"] not in {302, 303}
                    or not login_location
                    or not _same_origin(target, login_redirect)
                    or _path_and_query(login_redirect) != paths["ownPath"]
                ):
                    raise ValueError("login did not redirect to the configured own-object path")
                evidence_steps.append(
                    build_http_evidence_step(
                        "low-priv-login", "POST", urls["loginPath"], login_body, cookie,
                        login_response, (password, csrf_token),
                    )
                )

                cookie = _cookie_header(session, urls["ownPath"])
                own_response = await self._request(session, "GET", urls["ownPath"])
                request_count += 1
                own_secret = extract_secret_after_marker(own_response["body"], secret_label)
                if (
                    own_response["truncated"]
                    or own_response["status"] != 200
                    or own_marker not in own_response["body"]
                    or foreign_marker in own_response["body"]
                    or not own_secret
                ):
                    raise ValueError("own-object baseline did not expose the configured identity and secret")
                evidence_steps.append(
                    build_http_evidence_step(
                        "own-object-baseline", "GET", urls["ownPath"], "", cookie,
                        own_response, (password, csrf_token, own_secret),
                    )
                )

                cookie = _cookie_header(session, urls["foreignPath"])
                foreign_response = await self._request(session, "GET", urls["foreignPath"])
                request_count += 1
                denial_location = str(foreign_response["headers"].get("Location") or "")
                denial_redirect = urljoin(urls["foreignPath"], denial_location)
                foreign_secret = extract_secret_after_marker(foreign_response["body"], secret_label)
                if (
                    foreign_response["truncated"]
                    or foreign_response["status"] not in {302, 303}
                    or not denial_location
                    or not _same_origin(target, denial_redirect)
                    or _path_and_query(denial_redirect) != paths["denialPath"]
                    or foreign_marker not in foreign_response["body"]
                    or own_marker in foreign_response["body"]
                    or not foreign_secret
                    or foreign_secret == own_secret
                ):
                    raise ValueError("foreign-object response did not prove the configured redirect-body leak")
                evidence_steps.append(
                    build_http_evidence_step(
                        "foreign-object-redirect-leak", "GET", urls["foreignPath"], "", cookie,
                        foreign_response, (password, csrf_token, own_secret, foreign_secret),
                    )
                )

                solution_body = urlencode({str(parameters["solutionField"]): foreign_secret})
                cookie = _cookie_header(session, urls["solutionPath"])
                solution_response = await self._request(
                    session, "POST", urls["solutionPath"], solution_body
                )
                request_count += 1
                if (
                    solution_response["truncated"]
                    or solution_response["status"] != 200
                    or success_marker not in solution_response["body"]
                ):
                    raise ValueError("confirmation endpoint did not return the configured success marker")
                evidence_steps.append(
                    build_http_evidence_step(
                        "solution-submit", "POST", urls["solutionPath"], solution_body, cookie,
                        solution_response, (password, csrf_token, own_secret, foreign_secret),
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

        assert own_secret is not None and foreign_secret is not None
        own_hash = hashlib.sha256(own_secret.encode("utf-8")).hexdigest()
        foreign_hash = hashlib.sha256(foreign_secret.encode("utf-8")).hexdigest()
        verification = {
            "verified": True,
            "fallback": False,
            "mode": str(parameters["mode"]).lower(),
            "target": target,
            "engagement": str(parameters["engagement"]).lower(),
            **paths,
            "usernameField": str(parameters["usernameField"]),
            "passwordField": str(parameters["passwordField"]),
            "csrfField": csrf_field or None,
            "solutionField": str(parameters["solutionField"]),
            "username": username,
            "ownMarker": own_marker,
            "foreignMarker": foreign_marker,
            "secretLabel": secret_label,
            "solutionSuccessMarker": success_marker,
            "ownSecretSha256": own_hash,
            "ownSecretLength": len(own_secret),
            "foreignSecretSha256": foreign_hash,
            "foreignSecretLength": len(foreign_secret),
            "submittedValueSha256": foreign_hash,
            "submittedValueLength": len(foreign_secret),
            "denialStatus": int(evidence_steps[3]["responseStatus"]),
            "solutionStatus": 200,
            "solutionSubmitted": True,
            "requestCount": request_count,
            "foreignUrl": urls["foreignPath"],
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
                "mode": verification["mode"],
                "requestCount": request_count,
                "findingCount": 1,
            },
        }


def get_tool() -> AccessControlProbeTool:
    return AccessControlProbeTool()
