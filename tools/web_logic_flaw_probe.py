"""Fail-closed business-logic confirmation primitives.

The first mode proves one narrow workflow flaw: a state-changing finalizer can
be invoked without the configured guarded step. It performs exactly six
same-origin requests, including a post-finalizer state confirmation, and
returns only bounded, sanitized HTTP evidence.
"""

from __future__ import annotations

import hashlib
from html import unescape
from typing import Any, Dict, Iterable, Optional, Tuple
from urllib.parse import urlencode, urljoin

import aiohttp

from plugin_interface import ToolPlugin
from tools._agentic_exploration_common import read_limited
from tools.web_authentication_probe import (
    ALLOWED_ENGAGEMENTS,
    MAX_CREDENTIAL_CHARS,
    MAX_EVIDENCE_CHARS,
    MAX_RESPONSE_BYTES,
    _cookie_header,
    _field_name,
    _http_target,
    _path_and_query,
    _relative_path,
    _same_origin,
    extract_form_token,
    sanitize_evidence_text,
)


ALLOWED_MODES = {"workflow-finalizer-skip"}
MAX_MARKER_CHARS = 512
MAX_VALUE_CHARS = 256
# #1648 — two-tier proof. The runtime tier proves the vulnerability from its own
# evidence and needs no PortSwigger status page; the lab tier brackets it with the
# unsolved -> solved transition for calibration. Before this, the transition was
# mandatory at BOTH layers, so a confirmed finding on a customer application was
# impossible by construction.
ALLOWED_PROOF_LEVELS = {"runtime-workflow-skip", "lab-state-change"}
STATE_CHANGE_ENGAGEMENTS = {"lab", "ctf"}
_STATE_CHANGE_PARAMETERS = {
    "baselinePath",
    "unsolvedMarker",
    "solvedMarker",
}
RUNTIME_EXPECTED_STEP_LABELS = (
    "login-page",
    "approved-login",
    "state-add",
    "guarded-step-bypass-finalizer",
)
LAB_EXPECTED_STEP_LABELS = (
    "unsolved-baseline",
    *RUNTIME_EXPECTED_STEP_LABELS,
    "solved-confirmation",
)
EXPECTED_STEP_LABELS_BY_PROOF_LEVEL = {
    "runtime-workflow-skip": RUNTIME_EXPECTED_STEP_LABELS,
    "lab-state-change": LAB_EXPECTED_STEP_LABELS,
}
# Back-compat alias; equals the lab shape.
EXPECTED_STEP_LABELS = LAB_EXPECTED_STEP_LABELS


def response_contains_marker(body: str, marker: str) -> bool:
    """Match operator-visible text without requiring raw HTML entity syntax."""
    return marker in body or marker in unescape(body)


def validate_probe_parameters(parameters: Dict[str, Any]) -> Tuple[bool, str]:
    target = _http_target(parameters.get("target") or parameters.get("url"))
    if not target:
        return False, "target must be a credential-free HTTP(S) base URL without query or fragment"
    if str(parameters.get("mode") or "").lower() not in ALLOWED_MODES:
        return False, "mode must be workflow-finalizer-skip"
    if str(parameters.get("engagement") or "").lower() not in ALLOWED_ENGAGEMENTS:
        return False, "engagement must be aggressive, lab, or ctf"
    if parameters.get("allowUnsafeMethods") is not True:
        return False, "allowUnsafeMethods=true is required"

    # #1648 — tier resolution. No defaulting: an unrecognised value is rejected so
    # a typo cannot silently downgrade or upgrade the assertions.
    proof_level = str(parameters.get("proofLevel") or "").lower()
    if proof_level not in ALLOWED_PROOF_LEVELS:
        return False, "proofLevel must be runtime-workflow-skip or lab-state-change"
    if proof_level == "lab-state-change":
        if str(parameters.get("engagement") or "").lower() not in STATE_CHANGE_ENGAGEMENTS:
            return False, "lab-state-change requires engagement lab or ctf"
    else:
        # The runtime tier must REJECT lab material rather than ignore it, or a
        # caller could believe a transition was proven when nothing checked it.
        unexpected = sorted(_STATE_CHANGE_PARAMETERS.intersection(parameters))
        if unexpected:
            return False, f"{unexpected[0]} is only allowed for proofLevel=lab-state-change"

    path_keys = (
        "baselinePath",
        "loginPath",
        "loginRedirectPath",
        "addPath",
        "addRedirectPath",
        "guardedStepPath",
        "finalizerPath",
    )
    paths = {key: str(parameters.get(key) or "") for key in path_keys}
    for key, value in paths.items():
        if not _relative_path(value):
            return False, f"{key} must be a bounded same-origin relative path"
    if paths["guardedStepPath"] in {
        paths["baselinePath"],
        paths["loginPath"],
        paths["addPath"],
        paths["finalizerPath"],
    }:
        return False, "guardedStepPath must be distinct from every executed request path"
    if paths["addPath"] == paths["finalizerPath"]:
        return False, "addPath and finalizerPath must be distinct"

    for key in ("usernameField", "passwordField", "productField", "quantityField"):
        if not _field_name(parameters.get(key)):
            return False, f"{key} must be a valid form-field name"
    for key in ("csrfField", "redirectField"):
        value = parameters.get(key)
        if value is not None and str(value).strip() and not _field_name(value):
            return False, f"{key} must be a valid form-field name"

    username = str(parameters.get("username") or "")
    password = str(parameters.get("password") or "")
    if not username or len(username) > MAX_CREDENTIAL_CHARS:
        return False, "username is required and must be bounded"
    if not password or len(password) > MAX_CREDENTIAL_CHARS:
        return False, "password is required and must be bounded"

    values = {
        key: str(parameters.get(key) or "")
        for key in ("productValue", "quantityValue")
    }
    for key, value in values.items():
        if not value or len(value) > MAX_VALUE_CHARS:
            return False, f"{key} is required and must be bounded"
    redirect_field = str(parameters.get("redirectField") or "").strip()
    redirect_value = str(parameters.get("redirectValue") or "")
    if redirect_field and (not redirect_value or len(redirect_value) > MAX_VALUE_CHARS):
        return False, "redirectValue is required and must be bounded when redirectField is set"
    if not redirect_field and redirect_value:
        return False, "redirectField is required when redirectValue is set"

    markers = {
        key: str(parameters.get(key) or "")
        for key in ("unsolvedMarker", "solvedMarker", "productMarker", "finalResultMarker")
    }
    for key, value in markers.items():
        if len(value) < 3 or len(value) > MAX_MARKER_CHARS:
            return False, f"{key} must contain 3 to {MAX_MARKER_CHARS} characters"
    if markers["unsolvedMarker"] == markers["solvedMarker"]:
        return False, "unsolvedMarker and solvedMarker must be distinct"

    try:
        timeout = int(parameters.get("timeoutSeconds") or 15)
    except (TypeError, ValueError):
        return False, "timeoutSeconds must be an integer"
    if timeout < 3 or timeout > 30:
        return False, "timeoutSeconds must be between 3 and 30"
    return True, ""


def _request_transcript(
    method: str,
    url: str,
    body: str,
    cookie: str,
    secret_values: Iterable[Any],
) -> str:
    from urllib.parse import urlsplit

    parsed = urlsplit(url)
    lines = [
        f"{method} {_path_and_query(url)} HTTP/1.1",
        f"Host: {parsed.netloc}",
        "User-Agent: xASM-Agentic-Logic-Flaw-Probe/1.0",
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
        "template-id": "xasm-workflow-finalizer-skip-verified",
        "matcher-name": "business-logic-guarded-step-bypass",
        "type": "http",
        "host": target,
        "matched-at": str(verification.get("finalizerUrl") or target),
        "info": {
            "name": "Verified Business-Logic Workflow Finalizer Bypass",
            "severity": "high",
            "description": (
                "An authenticated workflow reached its state-changing finalizer without "
                "executing the configured guarded step, producing the configured result "
                "and an explicit unsolved-to-solved transition."
            ),
            "remediation": (
                "Enforce the workflow state machine server-side. The finalizer must "
                "atomically revalidate authorization, prerequisites, inventory, and "
                "business invariants instead of trusting that an earlier step ran."
            ),
            "classification": {"cwe-id": ["CWE-841"]},
        },
        "evidence": verification,
    }


class LogicFlawProbeTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "web:logic_flaw_probe"

    @property
    def description(self) -> str:
        return (
            "Confirms a same-origin business-logic workflow finalizer bypass with exactly "
            "six requests: unsolved baseline, login page, approved login, one configured "
            "state add, direct finalizer invocation without the guarded step, and a "
            "post-finalizer solved-state confirmation."
        )

    @property
    def schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Authorized application base URL"},
                "url": {"type": "string", "description": "Alias for target"},
                "mode": {"type": "string", "enum": sorted(ALLOWED_MODES)},
                "proofLevel": {"type": "string", "enum": sorted(ALLOWED_PROOF_LEVELS)},
                "baselinePath": {"type": "string"},
                "loginPath": {"type": "string"},
                "loginRedirectPath": {"type": "string"},
                "addPath": {"type": "string"},
                "addRedirectPath": {"type": "string"},
                "guardedStepPath": {"type": "string"},
                "finalizerPath": {"type": "string"},
                "usernameField": {"type": "string"},
                "passwordField": {"type": "string"},
                "csrfField": {"type": "string"},
                "productField": {"type": "string"},
                "productValue": {"type": "string"},
                "quantityField": {"type": "string"},
                "quantityValue": {"type": "string"},
                "redirectField": {"type": "string"},
                "redirectValue": {"type": "string"},
                "username": {"type": "string", "x-hidden": True},
                "password": {"type": "string", "x-hidden": True},
                "unsolvedMarker": {"type": "string"},
                "solvedMarker": {"type": "string"},
                "productMarker": {"type": "string"},
                "finalResultMarker": {"type": "string"},
                "engagement": {
                    "type": "string",
                    "enum": ["standard", *sorted(ALLOWED_ENGAGEMENTS)],
                },
                "allowUnsafeMethods": {"type": "boolean", "default": False},
                "timeoutSeconds": {"type": "integer", "minimum": 3, "maximum": 30},
            },
                        # #1648 — `required` holds only the tier-INDEPENDENT fields; the
            # lab-only ones are conditionally required AND conditionally
            # forbidden by the allOf below (same shape as web_ssti_probe.py).
            "required": [
                "mode",
                "proofLevel",
                "loginPath",
                "loginRedirectPath",
                "addPath",
                "addRedirectPath",
                "guardedStepPath",
                "finalizerPath",
                "usernameField",
                "passwordField",
                "productField",
                "productValue",
                "quantityField",
                "quantityValue",
                "username",
                "password",
                "productMarker",
                "finalResultMarker",
                "engagement",
                "allowUnsafeMethods",
            ],
            "allOf": [
                {
                    "if": {"properties": {"proofLevel": {"const": "lab-state-change"}}},
                    "then": {"required": sorted(_STATE_CHANGE_PARAMETERS)},
                    "else": {
                        "not": {
                            "anyOf": [
                                {"required": [field]}
                                for field in sorted(_STATE_CHANGE_PARAMETERS)
                            ]
                        }
                    },
                }
            ],

            "oneOf": [{"required": ["target"]}, {"required": ["url"]}],
        }

    @property
    def metadata(self) -> Dict[str, Any]:
        return {
            "category": "exploit-test",
            "phase": 4,
            "domain": ["web"],
            "input_type": ["url", "credentials", "workflow"],
            "output_type": ["findings", "business_logic_proof"],
            "taxonomy_domain": ["web"],
            "lifecycle_phase": "exploit-test",
            "purpose_count": "single",
            "primary_purpose": "Confirm a guarded workflow-step bypass",
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
            "User-Agent": "xASM-Agentic-Logic-Flaw-Probe/1.0",
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
        path_keys = (
            "baselinePath",
            "loginPath",
            "loginRedirectPath",
            "addPath",
            "addRedirectPath",
            "guardedStepPath",
            "finalizerPath",
        )
        paths = {key: str(parameters[key]) for key in path_keys}
        urls = {key: urljoin(target, value) for key, value in paths.items()}
        username = str(parameters["username"])
        password = str(parameters["password"])
        csrf_field = str(parameters.get("csrfField") or "").strip()
        redirect_field = str(parameters.get("redirectField") or "").strip()
        redirect_value = str(parameters.get("redirectValue") or "")
        proof_level = str(parameters["proofLevel"]).lower()
        is_lab = proof_level == "lab-state-change"
        unsolved_marker = str(parameters["unsolvedMarker"]) if is_lab else ""
        solved_marker = str(parameters["solvedMarker"]) if is_lab else ""
        product_marker = str(parameters["productMarker"])
        final_result_marker = str(parameters["finalResultMarker"])
        timeout = int(parameters.get("timeoutSeconds") or 15)

        request_count = 0
        evidence_steps = []
        csrf_token: Optional[str] = None
        timeout_config = aiohttp.ClientTimeout(total=timeout, connect=min(timeout, 8))
        try:
            cookie_jar = aiohttp.CookieJar(unsafe=True)
            async with aiohttp.ClientSession(timeout=timeout_config, cookie_jar=cookie_jar) as session:
                cookie = _cookie_header(session, urls["baselinePath"])
                # #1648 — the unsolved baseline exists only on the lab tier.
                baseline = None
                if is_lab:
                    baseline = await self._request(session, "GET", urls["baselinePath"])
                    request_count += 1
                    if (
                        baseline["truncated"]
                        or baseline["status"] != 200
                        or not response_contains_marker(baseline["body"], unsolved_marker)
                        or response_contains_marker(baseline["body"], solved_marker)
                    ):
                        raise ValueError(
                            "clean baseline did not prove the configured unsolved state"
                        )
                    evidence_steps.append(
                        build_http_evidence_step(
                            "unsolved-baseline",
                            "GET",
                            urls["baselinePath"],
                            "",
                            cookie,
                            baseline,
                            (password,),
                        )
                    )

                cookie = _cookie_header(session, urls["loginPath"])
                login_page = await self._request(session, "GET", urls["loginPath"])
                request_count += 1
                if login_page["truncated"] or login_page["status"] != 200:
                    raise ValueError("login page did not return a bounded HTTP 200 response")
                if csrf_field:
                    csrf_token = extract_form_token(login_page["body"], csrf_field)
                    if not csrf_token:
                        raise ValueError("configured CSRF field was not found on the login page")
                evidence_steps.append(
                    build_http_evidence_step(
                        "login-page",
                        "GET",
                        urls["loginPath"],
                        "",
                        cookie,
                        login_page,
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
                    or _path_and_query(login_redirect) != paths["loginRedirectPath"]
                ):
                    raise ValueError("login did not redirect to the configured authenticated path")
                evidence_steps.append(
                    build_http_evidence_step(
                        "approved-login",
                        "POST",
                        urls["loginPath"],
                        login_body,
                        cookie,
                        login_response,
                        (password, csrf_token),
                    )
                )

                add_form = {
                    str(parameters["productField"]): str(parameters["productValue"]),
                    str(parameters["quantityField"]): str(parameters["quantityValue"]),
                }
                if redirect_field:
                    add_form[redirect_field] = redirect_value
                add_body = urlencode(add_form)
                cookie = _cookie_header(session, urls["addPath"])
                add_response = await self._request(session, "POST", urls["addPath"], add_body)
                request_count += 1
                add_location = str(add_response["headers"].get("Location") or "")
                add_redirect = urljoin(urls["addPath"], add_location)
                if (
                    add_response["truncated"]
                    or add_response["status"] not in {302, 303}
                    or not add_location
                    or not _same_origin(target, add_redirect)
                    or _path_and_query(add_redirect) != paths["addRedirectPath"]
                ):
                    raise ValueError("state-add request did not return the configured redirect")
                evidence_steps.append(
                    build_http_evidence_step(
                        "state-add",
                        "POST",
                        urls["addPath"],
                        add_body,
                        cookie,
                        add_response,
                        (password, csrf_token),
                    )
                )

                cookie = _cookie_header(session, urls["finalizerPath"])
                finalizer = await self._request(session, "GET", urls["finalizerPath"])
                request_count += 1
                if finalizer["truncated"] or finalizer["status"] != 200:
                    raise ValueError("direct finalizer did not return a bounded HTTP 200 response")
                evidence_steps.append(
                    build_http_evidence_step(
                        "guarded-step-bypass-finalizer",
                        "GET",
                        urls["finalizerPath"],
                        "",
                        cookie,
                        finalizer,
                        (password, csrf_token),
                    )
                )

                # #1648 — the solved confirmation is lab-tier only. On a real
                # application the finalizer reached with the guarded step never
                # requested, plus the configured result markers, IS the finding.
                confirmation = None
                if is_lab:
                    cookie = _cookie_header(session, urls["baselinePath"])
                    confirmation = await self._request(session, "GET", urls["baselinePath"])
                    request_count += 1
                    if (
                        confirmation["truncated"]
                        or confirmation["status"] != 200
                        or not response_contains_marker(confirmation["body"], solved_marker)
                        or response_contains_marker(confirmation["body"], unsolved_marker)
                    ):
                        raise ValueError(
                            "post-finalizer confirmation did not prove the configured "
                            "solved transition"
                        )
                result_marker_responses = tuple(
                    [("guarded-step-bypass-finalizer", finalizer["body"])]
                    + ([("solved-confirmation", confirmation["body"])] if is_lab else [])
                )
                final_result_marker_step = next(
                    (
                        label
                        for label, response_body in result_marker_responses
                        if response_contains_marker(response_body, final_result_marker)
                    ),
                    None,
                )
                if not final_result_marker_step:
                    raise ValueError(
                        "configured final result marker was absent from the finalizer "
                        "and post-finalizer confirmation responses"
                    )
                marker_responses = tuple(
                    ([("unsolved-baseline", baseline["body"])] if is_lab else [])
                    + [("guarded-step-bypass-finalizer", finalizer["body"])]
                    + ([("solved-confirmation", confirmation["body"])] if is_lab else [])
                )
                product_marker_step = next(
                    (
                        label
                        for label, response_body in marker_responses
                        if response_contains_marker(response_body, product_marker)
                    ),
                    None,
                )
                if not product_marker_step:
                    raise ValueError(
                        "configured product marker was absent from the bounded proof responses"
                    )
                evidence_steps.append(
                    build_http_evidence_step(
                        "solved-confirmation",
                        "GET",
                        urls["baselinePath"],
                        "",
                        cookie,
                        confirmation,
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
            "mode": str(parameters["mode"]).lower(),
            "target": target,
            "engagement": str(parameters["engagement"]).lower(),
            **paths,
            "usernameField": str(parameters["usernameField"]),
            "passwordField": str(parameters["passwordField"]),
            "csrfField": csrf_field or None,
            "productField": str(parameters["productField"]),
            "productValue": str(parameters["productValue"]),
            "quantityField": str(parameters["quantityField"]),
            "quantityValue": str(parameters["quantityValue"]),
            "redirectField": redirect_field or None,
            "redirectValue": redirect_value or None,
            "username": username,
            "proofLevel": proof_level,
            "productMarker": product_marker,
            "finalResultMarker": final_result_marker,
            "requestCount": request_count,
            # #1648 — indices shift by one when the unsolved baseline is absent.
            "loginStatus": int(evidence_steps[1 if is_lab else 0]["responseStatus"]),
            "addStatus": int(evidence_steps[3 if is_lab else 2]["responseStatus"]),
            "finalizerStatus": int(evidence_steps[4 if is_lab else 3]["responseStatus"]),
            "productMarkerStep": product_marker_step,
            "finalResultMarkerStep": final_result_marker_step,
            "guardedStepRequested": False,
            "finalizerUrl": urls["finalizerPath"],
            "httpEvidence": {"version": 1, "steps": evidence_steps},
        }
        # #1648 — lab-only proof material, emitted only on the lab tier.
        if is_lab:
            verification.update(
                {
                    "unsolvedMarker": unsolved_marker,
                    "solvedMarker": solved_marker,
                    "baselineStatus": int(evidence_steps[0]["responseStatus"]),
                    "confirmationStatus": int(evidence_steps[5]["responseStatus"]),
                    "solvedBefore": False,
                    "solvedAfter": True,
                }
            )
        finding = build_nuclei_finding(target, verification)
        return {
            "success": True,
            "fallback": False,
            "target": target,
            "requestCount": request_count,
            "verification": verification,
            "findings": [finding],
        }
