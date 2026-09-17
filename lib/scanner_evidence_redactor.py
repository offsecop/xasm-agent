"""Structure-preserving scanner evidence secret redaction (#2132).

Unlike the LLM prompt sanitizer this module deliberately preserves HTML,
JavaScript, SQL and template syntax. Those bytes are vulnerability evidence;
only values in authentication-shaped fields are replaced.
"""

from __future__ import annotations

import re
from typing import Any


REDACTED_RUNTIME_SECRET = "<redacted-runtime-secret>"

_SENSITIVE_NAMES = {
    "authorization", "proxyauthorization", "cookie", "cookies", "setcookie",
    "authcookie", "authcookies", "password", "passwd", "passphrase", "secret",
    "clientsecret", "apikey", "xapikey", "accesskey", "accesskeyid",
    "secretaccesskey", "token", "tokens", "accesstoken", "refreshtoken",
    "idtoken", "bearertoken", "session", "sessionid", "sessiontoken",
    "csrftoken", "xcsrftoken", "xsrftoken", "credential", "credentials",
}
_HEADER_CONTAINERS = {"header", "headers", "requestheader", "requestheaders",
                      "responseheader", "responseheaders", "authheader", "authheaders"}
_TOKEN_CONTAINERS = {"token", "tokens", "authtoken", "authtokens",
                     "authenticationtoken", "authenticationtokens", "credential", "credentials"}
_COOKIE_CONTAINERS = {"cookie", "cookies", "setcookie", "setcookies", "authcookie", "authcookies"}
_COOKIE_METADATA = {"name", "path", "domain", "maxage", "expires", "samesite", "secure", "httponly"}
_SENSITIVE_HEADERS = {
    "authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key",
    "api-key", "x-auth-token", "x-access-token", "x-csrf-token", "x-xsrf-token",
}
_PARAM = (
    r"(?:password|passwd|passphrase|secret|client[_-]?secret|api[_-]?key|"
    r"x[_-]?api[_-]?key|access[_-]?key(?:[_-]?id)?|secret[_-]?access[_-]?key|"
    r"token|access[_-]?token|refresh[_-]?token|id[_-]?token|bearer[_-]?token|"
    r"session(?:[_-]?(?:id|token))?|csrf(?:[_-]?token)?|xsrf(?:[_-]?token)?)"
)


def _normalized(name: str) -> str:
    return re.sub(r"[-_\s]", "", str(name)).lower()


def _is_sensitive_name(name: str) -> bool:
    return _normalized(name) in _SENSITIVE_NAMES


def _is_redaction_marker(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    trimmed = value.strip()
    return bool(
        trimmed == REDACTED_RUNTIME_SECRET
        or re.fullmatch(r"\*{3}REDACTED\*{3}", trimmed, re.I)
        or re.fullmatch(r"\[[^\]]*REDACTED[^\]]*\]", trimmed, re.I)
    )


def _redact_cookie(raw: str) -> str:
    if raw == REDACTED_RUNTIME_SECRET:
        return raw
    output = []
    for index, part in enumerate(re.split(r";\s*", raw)):
        if "=" not in part:
            output.append(part)
            continue
        name, value = part.split("=", 1)
        name = name.strip()
        if _is_redaction_marker(value):
            output.append(part)
            continue
        if index > 0 and re.fullmatch(r"path|domain|max-age|expires|samesite", name, re.I):
            output.append(f"{name}={value}")
        else:
            output.append(f"{name}={REDACTED_RUNTIME_SECRET}")
    return "; ".join(output)


def _redact_header(name: str, value: str) -> str:
    if _is_redaction_marker(value):
        return value
    if name.lower() in {"cookie", "set-cookie"}:
        return _redact_cookie(value)
    return REDACTED_RUNTIME_SECRET


def _redact_string(raw: str) -> str:
    value = raw

    def header(match: re.Match) -> str:
        name, separator, secret = match.group(1), match.group(2), match.group(3)
        return f"{name}{separator}{_redact_header(name, secret)}"

    value = re.sub(
        r"^(authorization|proxy-authorization|cookie|set-cookie|x-api-key|api-key|"
        r"x-auth-token|x-access-token|x-csrf-token|x-xsrf-token)(\s*:\s*)(.*)$",
        header,
        value,
        flags=re.I | re.M,
    )
    value = re.sub(
        rf"(^|[?&;\s])({_PARAM})(=)(?!{re.escape(REDACTED_RUNTIME_SECRET)})([^&#;\s\"'<>]*)",
        lambda m: (
            m.group(0)
            if _is_redaction_marker(m.group(4))
            else f"{m.group(1)}{m.group(2)}{m.group(3)}{REDACTED_RUNTIME_SECRET}"
        ),
        value,
        flags=re.I | re.M,
    )
    value = re.sub(
        rf"([\"']{_PARAM}[\"']\s*:\s*)([\"'])(.*?)(\2)",
        lambda m: (
            m.group(0)
            if _is_redaction_marker(m.group(3))
            else f"{m.group(1)}{m.group(2)}{REDACTED_RUNTIME_SECRET}{m.group(2)}"
        ),
        value,
        flags=re.I | re.M,
    )
    value = re.sub(
        rf"([\"']{_PARAM}[\"']\s*:\s*)(?![\"'{{\[])([^,}}\]\s]+)",
        lambda m: (
            m.group(0)
            if _is_redaction_marker(m.group(2))
            else f"{m.group(1)}{REDACTED_RUNTIME_SECRET}"
        ),
        value,
        flags=re.I | re.M,
    )
    value = re.sub(
        rf"(<input\b[^>]*\bname\s*=\s*[\"']?{_PARAM}[\"']?[^>]*\bvalue\s*=\s*)([\"'])(.*?)(\2)",
        lambda m: (
            m.group(0)
            if _is_redaction_marker(m.group(3))
            else f"{m.group(1)}{m.group(2)}{REDACTED_RUNTIME_SECRET}{m.group(2)}"
        ),
        value,
        flags=re.I | re.M,
    )
    value = re.sub(
        r"((?:^|\s)(?:-u|--user)\s+)([\"']?)([^\s\"']+)(\2)",
        lambda m: (
            m.group(0)
            if _is_redaction_marker(m.group(3))
            else f"{m.group(1)}{m.group(2)}{REDACTED_RUNTIME_SECRET}{m.group(2)}"
        ),
        value,
        flags=re.I | re.M,
    )
    value = re.sub(
        r"((?:^|\s)(?:-b|--cookie)\s+)([\"'])(.*?)(\2)",
        lambda m: f"{m.group(1)}{m.group(2)}{_redact_cookie(m.group(3))}{m.group(2)}",
        value,
        flags=re.I | re.M,
    )
    value = re.sub(
        r"((?:^|\s)(?:-H|--header)\s+)([\"'])(authorization|proxy-authorization|cookie|"
        r"set-cookie|x-api-key|api-key|x-auth-token|x-access-token|x-csrf-token|x-xsrf-token)"
        r"(\s*:\s*)(.*?)(\2)",
        lambda m: (
            f"{m.group(1)}{m.group(2)}{m.group(3)}{m.group(4)}"
            f"{_redact_header(m.group(3), m.group(5))}{m.group(2)}"
        ),
        value,
        flags=re.I | re.M,
    )
    value = re.sub(
        r"(https?://[^\s:/@]+:)([^\s/@]+)(@)",
        lambda m: (
            m.group(0)
            if _is_redaction_marker(m.group(2))
            else f"{m.group(1)}{REDACTED_RUNTIME_SECRET}{m.group(3)}"
        ),
        value,
        flags=re.I | re.M,
    )
    value = re.sub(
        r"\b(Bearer|Basic)(\s+)(?!<redacted-runtime-secret>)[A-Za-z0-9._~+/=-]{4,}",
        lambda m: f"{m.group(1)}{m.group(2)}{REDACTED_RUNTIME_SECRET}",
        value,
        flags=re.I,
    )
    return value


def redact_scanner_evidence(value: Any, parent_key: str | None = None) -> Any:
    """Return a redacted deep copy suitable for persistence or transport."""
    if value is None:
        return None
    if isinstance(value, str):
        if parent_key and _normalized(parent_key) in _COOKIE_CONTAINERS:
            return _redact_cookie(value)
        if parent_key and _is_sensitive_name(parent_key):
            return value if _is_redaction_marker(value) else REDACTED_RUNTIME_SECRET
        return _redact_string(value)
    if isinstance(value, list):
        if parent_key and _normalized(parent_key) in _TOKEN_CONTAINERS:
            return [entry if _is_redaction_marker(entry) else REDACTED_RUNTIME_SECRET for entry in value]
        return [redact_scanner_evidence(entry, parent_key) for entry in value]
    if not isinstance(value, dict):
        return value

    parent_normalized = _normalized(parent_key or "")
    parent_is_headers = parent_normalized in _HEADER_CONTAINERS
    parent_is_tokens = parent_normalized in _TOKEN_CONTAINERS
    parent_is_cookies = parent_normalized in _COOKIE_CONTAINERS
    named_header = (
        parent_is_headers
        and isinstance(value.get("name"), str)
        and value["name"].lower() in _SENSITIVE_HEADERS
    )
    named_cookie = parent_is_cookies and isinstance(value.get("name"), str) and "value" in value
    output = {}
    for key, nested in value.items():
        if named_header and str(key).lower() == "value" and isinstance(nested, str):
            output[key] = _redact_header(str(value["name"]), nested)
        elif parent_is_cookies and named_cookie and str(key).lower() == "value" and isinstance(nested, str):
            output[key] = nested if _is_redaction_marker(nested) else REDACTED_RUNTIME_SECRET
        elif parent_is_cookies and not named_cookie and _normalized(str(key)) not in _COOKIE_METADATA:
            output[key] = (
                nested
                if nested is None or _is_redaction_marker(nested)
                else REDACTED_RUNTIME_SECRET
            )
        elif parent_is_headers and str(key).lower() in _SENSITIVE_HEADERS:
            output[key] = (
                _redact_header(str(key), nested)
                if isinstance(nested, str) and not _is_redaction_marker(nested)
                else nested
            )
        elif (
            _normalized(str(key)) in _COOKIE_CONTAINERS | _TOKEN_CONTAINERS
            and nested is not None
            and isinstance(nested, (dict, list))
        ):
            output[key] = redact_scanner_evidence(nested, str(key))
        elif parent_is_tokens or _is_sensitive_name(str(key)):
            output[key] = (
                nested
                if nested is None or _is_redaction_marker(nested)
                else REDACTED_RUNTIME_SECRET
            )
        else:
            output[key] = redact_scanner_evidence(nested, str(key))
    return output


def redact_agent_result(tool_name: str | None, result: Any) -> Any:
    """Redact scanner output while preserving the auth tool's vault handoff.

    ``authentication:*`` is a dedicated credential transport: the backend
    immediately encrypts that session and redacts Job/trace persistence. If it
    were masked here, authenticated scans could not reuse the session.
    """
    if str(tool_name or "").startswith("authentication:"):
        return result
    return redact_scanner_evidence(result)
