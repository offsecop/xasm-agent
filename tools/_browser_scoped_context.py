"""Shared, scope-safe Playwright context for authenticated browser recon.

The authentication workflow intentionally persists only filtered cookies, not
Playwright ``storage_state``.  These helpers restore those cookies into a real
Chromium cookie jar so Domain/Path/Secure/HttpOnly/SameSite semantics are
honoured while keeping every browser request inside the authorized origin.
"""

from dataclasses import dataclass, field
import hashlib
import math
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from tools._agentic_exploration_common import parse_headers


COOKIE_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
SAFE_BROWSER_SCHEMES = ("about:", "blob:", "data:")
BROWSER_CONTEXT_SCOPE_OPTIONS = {"service_workers": "block"}
SERVER_BROWSER_ORIGIN_POLICY_KEY = "_serverBrowserOriginPolicy"
MAX_AUTHORIZED_BROWSER_ORIGINS = 64


@dataclass(frozen=True)
class BrowserOriginPolicy:
    primary_origin: str
    allowed_origins: Tuple[str, ...]
    server_attested: bool

    def url_is_primary(self, value: str) -> bool:
        return _exact_http_origin(value) == self.primary_origin

    def url_is_authorized(self, value: str) -> bool:
        return _exact_http_origin(value) in self.allowed_origins


class BrowserCoverageIncomplete(RuntimeError):
    """Typed browser-coverage failure that must not fall back anonymously."""

    def __init__(self, reason: str, detail: str):
        super().__init__(detail)
        self.reason = reason
        self.detail = detail


def _exact_http_origin(value: Any, *, require_origin_only: bool = False) -> Optional[str]:
    """Return a canonical HTTP(S) origin or ``None`` for ambiguous input."""

    if not isinstance(value, str):
        return None
    raw = value.strip()
    if (
        not raw
        or "*" in raw
        or any(char in raw for char in ("\r", "\n", "\0"))
        or not re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", raw)
    ):
        return None
    try:
        parsed = urlparse(raw)
        scheme = parsed.scheme.lower()
        if (
            scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
        ):
            return None
        if require_origin_only and (
            parsed.path not in {"", "/"} or parsed.params or parsed.query or parsed.fragment
        ):
            return None
        port = parsed.port
        default_port = 443 if scheme == "https" else 80
        host = parsed.hostname.lower()
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError:
            return None
        host_for_url = f"[{host}]" if ":" in host else host
        authority = host_for_url if port is None or port == default_port else f"{host_for_url}:{port}"
        return f"{scheme}://{authority}"
    except (TypeError, ValueError):
        return None


def _safe_origin_fingerprint(value: Any) -> str:
    origin = _exact_http_origin(value) or "invalid-origin"
    return hashlib.sha256(origin.encode("utf-8")).hexdigest()[:16]


def browser_scope_metadata(
    policy: BrowserOriginPolicy,
    *,
    blocked_urls: Optional[List[str]] = None,
    blocked_navigation_count: int = 0,
    rejected_cookie_count: int = 0,
    stripped_cross_origin_auth_headers: int = 0,
) -> Dict[str, Any]:
    fingerprints: List[str] = []
    for value in blocked_urls or []:
        fingerprint = _safe_origin_fingerprint(value)
        if fingerprint not in fingerprints:
            fingerprints.append(fingerprint)
        if len(fingerprints) >= 20:
            break
    return {
        "policyVersion": 1,
        "serverAttested": policy.server_attested,
        "allowedOriginCount": len(policy.allowed_origins),
        "blockedRequestCount": len(blocked_urls or []),
        "blockedNavigationCount": blocked_navigation_count,
        "blockedOriginFingerprints": fingerprints,
        "rejectedCookieCount": rejected_cookie_count,
        "strippedCrossOriginAuthHeaders": stripped_cross_origin_auth_headers,
    }


def browser_origin_policy(parameters: Dict[str, Any], target: str) -> BrowserOriginPolicy:
    """Validate the private server envelope without accepting caller expansion.

    Older native probes invoke the browser helper internally and therefore do
    not carry the dispatcher envelope. Their conservative compatibility lane
    remains restricted to the already scope-checked primary target only. When
    an envelope is present it must be the exact frozen server contract; any
    malformed or near-miss entry fails closed instead of being partially used.
    """

    target_origin = _exact_http_origin(target)
    if not target_origin:
        raise BrowserCoverageIncomplete(
            "INVALID_BROWSER_ORIGIN_POLICY",
            "browser target must be an absolute credential-free HTTP(S) URL",
        )

    raw = parameters.get(SERVER_BROWSER_ORIGIN_POLICY_KEY)
    if raw is None:
        return BrowserOriginPolicy(
            primary_origin=target_origin,
            allowed_origins=(target_origin,),
            server_attested=False,
        )
    if not isinstance(raw, dict) or set(raw) != {
        "version",
        "primaryOrigin",
        "allowedOrigins",
        "requireExactOrigin",
        "stripCrossOriginAuthHeaders",
    }:
        raise BrowserCoverageIncomplete(
            "INVALID_BROWSER_ORIGIN_POLICY",
            "server browser origin policy has an invalid shape",
        )
    allowed = raw.get("allowedOrigins")
    if (
        type(raw.get("version")) is not int
        or raw.get("version") != 1
        or raw.get("requireExactOrigin") is not True
        or raw.get("stripCrossOriginAuthHeaders") is not True
        or not isinstance(allowed, list)
        or not allowed
        or len(allowed) > MAX_AUTHORIZED_BROWSER_ORIGINS
        or any(not isinstance(item, str) for item in allowed)
    ):
        raise BrowserCoverageIncomplete(
            "INVALID_BROWSER_ORIGIN_POLICY",
            "server browser origin policy is not an exact-origin policy",
        )

    canonical_allowed = tuple(
        origin
        for origin in (
            _exact_http_origin(item, require_origin_only=True) for item in allowed
        )
        if origin is not None
    )
    canonical_primary = _exact_http_origin(
        raw.get("primaryOrigin"), require_origin_only=True
    )
    if (
        len(canonical_allowed) != len(allowed)
        or tuple(allowed) != canonical_allowed
        or tuple(sorted(set(canonical_allowed))) != canonical_allowed
        or canonical_primary != raw.get("primaryOrigin")
        or canonical_primary != target_origin
        or canonical_primary not in canonical_allowed
    ):
        raise BrowserCoverageIncomplete(
            "INVALID_BROWSER_ORIGIN_POLICY",
            "server browser origin policy does not match the exact target origin",
        )
    return BrowserOriginPolicy(
        primary_origin=canonical_primary,
        allowed_origins=canonical_allowed,
        server_attested=True,
    )


def _header_is_sensitive_cross_origin(name: Any) -> bool:
    normalized = str(name or "").strip().lower().replace("_", "-")
    return (
        normalized in {"authorization", "proxy-authorization", "x-api-key", "api-key"}
        or "token" in normalized
        or normalized.endswith("-secret")
        or normalized == "secret"
    )


def _cookie_domain_matches_authorized_origin(
    cookie: Dict[str, Any],
    allowed_origins: Tuple[str, ...],
) -> bool:
    domain = cookie.get("domain")
    if not domain:
        cookie_origin = _exact_http_origin(cookie.get("url"))
        return cookie_origin in allowed_origins
    if not isinstance(domain, str):
        return False
    normalized = domain.lstrip(".").strip().lower()
    if not normalized or any(char in normalized for char in ("/", "\\", ":", "*")):
        return False
    try:
        normalized = normalized.encode("idna").decode("ascii")
    except UnicodeError:
        return False
    for origin in allowed_origins:
        try:
            host = (urlparse(origin).hostname or "").lower()
        except (TypeError, ValueError):
            continue
        if host == normalized or host.endswith(f".{normalized}"):
            return True
    return False


@dataclass
class ScopedBrowserContext:
    context: Any
    target: str
    authenticated: bool
    installed_cookie_count: int
    rejected_cookie_count: int
    primary_origin: str = ""
    allowed_origins: Tuple[str, ...] = field(default_factory=tuple)
    server_attested_policy: bool = False
    has_sensitive_extra_headers: bool = False
    blocked_navigation_urls: List[str] = field(default_factory=list)
    blocked_request_count: int = 0
    blocked_origin_fingerprints: List[str] = field(default_factory=list)
    stripped_cross_origin_auth_headers: int = 0
    auth_failure_status: Optional[int] = None

    def url_is_primary(self, value: str) -> bool:
        return _exact_http_origin(value) == self.primary_origin

    def url_is_authorized(self, value: str) -> bool:
        return _exact_http_origin(value) in self.allowed_origins

    def note_blocked_url(self, value: str, *, navigation: bool = False) -> None:
        self.blocked_request_count += 1
        fingerprint = _safe_origin_fingerprint(value)
        if fingerprint not in self.blocked_origin_fingerprints:
            self.blocked_origin_fingerprints.append(fingerprint)
            del self.blocked_origin_fingerprints[20:]
        if navigation:
            self.blocked_navigation_urls.append(fingerprint)

    def scope_metadata(self) -> Dict[str, Any]:
        return {
            "policyVersion": 1,
            "serverAttested": self.server_attested_policy,
            "allowedOriginCount": len(self.allowed_origins),
            "blockedRequestCount": self.blocked_request_count,
            "blockedNavigationCount": len(self.blocked_navigation_urls),
            "blockedOriginFingerprints": list(self.blocked_origin_fingerprints),
            "rejectedCookieCount": self.rejected_cookie_count,
            "strippedCrossOriginAuthHeaders": self.stripped_cross_origin_auth_headers,
        }


def _contains_forbidden_cookie_chars(value: str) -> bool:
    return any(char in value for char in ("\r", "\n", "\0"))


def _normalize_same_site(value: Any) -> Optional[str]:
    if value is None or str(value).strip() == "":
        return None
    normalized = str(value).strip().lower()
    return {"strict": "Strict", "lax": "Lax", "none": "None"}.get(normalized)


def _target_origin(target: str) -> str:
    parsed = urlparse(target)
    return f"{parsed.scheme}://{parsed.netloc}/"


def normalize_browser_cookie(row: Any, target: str) -> Optional[Dict[str, Any]]:
    """Convert encrypted SessionData cookie metadata to Playwright's shape.

    Invalid names and control-character injection are rejected. Cookie values
    are otherwise opaque, so embedded ``=`` characters remain byte-for-byte.
    """

    if not isinstance(row, dict):
        return None
    name = row.get("name")
    value = row.get("value")
    if not isinstance(name, str) or not COOKIE_NAME_RE.fullmatch(name):
        return None
    if not isinstance(value, str) or _contains_forbidden_cookie_chars(value):
        return None

    cookie: Dict[str, Any] = {"name": name, "value": value}
    domain = row.get("domain")
    path = row.get("path")
    if domain is not None and (
        not isinstance(domain, str) or _contains_forbidden_cookie_chars(domain)
    ):
        return None
    if path is not None and (
        not isinstance(path, str) or _contains_forbidden_cookie_chars(path) or not path.startswith("/")
    ):
        return None
    if isinstance(domain, str) and domain.strip():
        cookie["domain"] = domain.strip()
        cookie["path"] = path or "/"
    else:
        cookie["url"] = _target_origin(target)

    if row.get("secure") is not None:
        cookie["secure"] = bool(row.get("secure"))
    if row.get("httpOnly") is not None:
        cookie["httpOnly"] = bool(row.get("httpOnly"))

    same_site = _normalize_same_site(row.get("sameSite"))
    if row.get("sameSite") is not None and same_site is None:
        return None
    if same_site:
        cookie["sameSite"] = same_site

    expiry = row.get("expiry", row.get("expires"))
    if expiry is not None:
        try:
            expiry_number = float(expiry)
        except (TypeError, ValueError):
            return None
        if not math.isfinite(expiry_number):
            return None
        # Playwright uses -1 for a session cookie; positive Unix timestamps
        # preserve persistent-cookie expiry semantics.
        if expiry_number == -1 or expiry_number > 0:
            cookie["expires"] = expiry_number
        elif expiry_number != 0:
            return None

    return cookie


def parse_cookie_header(cookie_header: Any, target: str) -> Tuple[List[Dict[str, Any]], int]:
    """Parse the legacy flat Cookie header without truncating values at ``=``."""

    if not isinstance(cookie_header, str) or not cookie_header.strip():
        return [], 0
    cookies: List[Dict[str, Any]] = []
    rejected = 0
    for part in cookie_header.split(";"):
        segment = part.strip()
        if not segment:
            continue
        name, separator, value = segment.partition("=")
        row = normalize_browser_cookie(
            {"name": name.strip(), "value": value if separator else "", "path": "/"},
            target,
        )
        if row is None or not separator:
            rejected += 1
        else:
            cookies.append(row)
    return cookies, rejected


def browser_cookie_rows(
    parameters: Dict[str, Any],
    target: str,
    allowed_origins: Optional[Tuple[str, ...]] = None,
) -> Tuple[List[Dict[str, Any]], int]:
    structured = parameters.get("cookieJar")
    if structured is not None:
        if not isinstance(structured, list):
            return [], 1
        rows: List[Dict[str, Any]] = []
        rejected = 0
        for raw in structured:
            normalized = normalize_browser_cookie(raw, target)
            if normalized is None or (
                allowed_origins is not None
                and not _cookie_domain_matches_authorized_origin(
                    normalized, allowed_origins
                )
            ):
                rejected += 1
            else:
                rows.append(normalized)
        return rows, rejected
    rows, rejected = parse_cookie_header(
        parameters.get("cookie") or parameters.get("authCookies"), target
    )
    if allowed_origins is None:
        return rows, rejected
    accepted = [
        row
        for row in rows
        if _cookie_domain_matches_authorized_origin(row, allowed_origins)
    ]
    return accepted, rejected + len(rows) - len(accepted)


def browser_extra_headers(parameters: Dict[str, Any]) -> Dict[str, str]:
    """Return generic headers without a caller-supplied Cookie header."""

    return {
        key: value
        for key, value in parse_headers(parameters).items()
        if str(key).lower() != "cookie"
    }


def has_browser_auth_material(parameters: Dict[str, Any]) -> bool:
    if any(parameters.get(key) is not None for key in ("cookieJar", "cookie", "authCookies")):
        return True
    return any(
        _header_is_sensitive_cross_origin(key)
        for key in browser_extra_headers(parameters)
    )


def same_websocket_origin(base: str, candidate: str) -> bool:
    return _exact_http_origin(base) == _websocket_http_origin(candidate)


def _websocket_http_origin(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    try:
        parsed = urlparse(value.strip())
        mapped_scheme = {"ws": "http", "wss": "https"}.get(parsed.scheme.lower())
        if not mapped_scheme:
            return None
        return _exact_http_origin(
            parsed._replace(scheme=mapped_scheme).geturl()
        )
    except (TypeError, ValueError):
        return None


async def create_scoped_browser_context(
    browser: Any,
    target: str,
    parameters: Dict[str, Any],
) -> ScopedBrowserContext:
    """Create one authenticated Playwright context with an exact-origin policy."""

    policy = browser_origin_policy(parameters, target)
    cookies, rejected = browser_cookie_rows(parameters, target, policy.allowed_origins)
    structured_present = parameters.get("cookieJar") is not None
    legacy_present = bool(parameters.get("cookie") or parameters.get("authCookies"))
    if (structured_present or legacy_present) and not cookies:
        raise BrowserCoverageIncomplete(
            "INVALID_AUTH_COOKIE_JAR",
            "authentication cookies were supplied but none passed validation",
        )

    headers = browser_extra_headers(parameters)
    has_sensitive_headers = any(_header_is_sensitive_cross_origin(key) for key in headers)
    authenticated = bool(cookies) or has_sensitive_headers
    context = await browser.new_context(
        ignore_https_errors=True,
        extra_http_headers=headers,
        **BROWSER_CONTEXT_SCOPE_OPTIONS,
    )
    state = ScopedBrowserContext(
        context=context,
        target=target,
        authenticated=authenticated,
        installed_cookie_count=len(cookies),
        rejected_cookie_count=rejected,
        primary_origin=policy.primary_origin,
        allowed_origins=policy.allowed_origins,
        server_attested_policy=policy.server_attested,
        has_sensitive_extra_headers=has_sensitive_headers,
    )

    async def keep_requests_in_scope(route: Any) -> None:
        request = route.request
        request_url = str(request.url)
        if request_url.startswith(SAFE_BROWSER_SCHEMES):
            await route.continue_()
            return
        navigation = False
        try:
            frame = request.frame
            navigation = request.is_navigation_request() and frame.parent_frame is None
        except Exception:
            pass
        # Secondary origins authorize SPA resources/API calls, not visible
        # navigation. The browser must remain rooted at the primary app.
        if state.url_is_authorized(request_url) and not (
            navigation and not state.url_is_primary(request_url)
        ):
            if not state.url_is_primary(request_url):
                request_headers: Dict[str, str]
                try:
                    all_headers = getattr(request, "all_headers", None)
                    request_headers = dict(
                        (await all_headers())
                        if callable(all_headers)
                        else (getattr(request, "headers", {}) or {})
                    )
                except Exception:
                    request_headers = dict(getattr(request, "headers", {}) or {})
                filtered_headers = {
                    key: value
                    for key, value in request_headers.items()
                    if not _header_is_sensitive_cross_origin(key)
                }
                removed = len(request_headers) - len(filtered_headers)
                state.stripped_cross_origin_auth_headers += removed
                if removed:
                    await route.continue_(headers=filtered_headers)
                    return
            await route.continue_()
            return
        state.note_blocked_url(request_url, navigation=navigation)
        await route.abort("blockedbyclient")

    async def keep_websockets_in_scope(websocket: Any) -> None:
        websocket_origin = _websocket_http_origin(websocket.url)
        secondary = websocket_origin != state.primary_origin
        if (
            websocket_origin in state.allowed_origins
            and not (secondary and state.has_sensitive_extra_headers)
        ):
            websocket.connect_to_server()
        else:
            state.note_blocked_url(websocket.url)
            await websocket.close(
                code=1008,
                reason="websocket blocked by authorized exact-origin scope",
            )

    await context.route("**/*", keep_requests_in_scope)
    await context.route_web_socket("**/*", keep_websockets_in_scope)
    if cookies:
        await context.add_cookies(cookies)
    return state


def attach_auth_loss_watch(state: ScopedBrowserContext, page: Any) -> None:
    """Track main-frame 401/403 responses across safe SPA interactions."""

    if not state.authenticated:
        return

    def observe(response: Any) -> None:
        try:
            request = response.request
            frame = request.frame
            resource_type = str(getattr(request, "resource_type", "")).lower()
            main_frame_navigation = request.is_navigation_request() and frame.parent_frame is None
            authenticated_api_call = (
                resource_type in {"xhr", "fetch"}
                and state.url_is_authorized(str(response.url))
            )
            if (main_frame_navigation or authenticated_api_call) and int(response.status) in {
                401,
                403,
            }:
                state.auth_failure_status = int(response.status)
        except Exception:
            return

    page.on("response", observe)


async def validate_authenticated_navigation(
    state: ScopedBrowserContext,
    page: Any,
    navigation: Any,
    target: str,
) -> None:
    """Raise typed INCOMPLETE when a supplied session is no longer valid."""

    if not state.authenticated:
        return
    if state.auth_failure_status in {401, 403}:
        raise BrowserCoverageIncomplete(
            f"AUTHENTICATION_LOST_HTTP_{state.auth_failure_status}",
            f"protected navigation returned HTTP {state.auth_failure_status}",
        )
    if state.blocked_navigation_urls:
        raise BrowserCoverageIncomplete(
            "AUTHENTICATION_LOST_REDIRECT",
            "authenticated navigation redirected outside the authorized origin",
        )
    if not state.url_is_primary(page.url):
        raise BrowserCoverageIncomplete(
            "AUTHENTICATION_LOST_REDIRECT",
            "authenticated navigation left the authorized origin",
        )
    status = int(navigation.status) if navigation and navigation.status is not None else 0
    if status in {401, 403}:
        raise BrowserCoverageIncomplete(
            f"AUTHENTICATION_LOST_HTTP_{status}",
            f"protected navigation returned HTTP {status}",
        )

    try:
        password_inputs = await page.locator('input[type="password"]').count()
        explicit_login_forms = await page.locator(
            'form[action*="login" i], form[action*="signin" i], form[action*="sign-in" i]'
        ).count()
    except Exception:
        password_inputs = 0
        explicit_login_forms = 0
    if password_inputs > 0 or explicit_login_forms > 0:
        raise BrowserCoverageIncomplete(
            "AUTHENTICATION_LOST_LOGIN_FORM",
            "protected navigation resolved to a login surface",
        )


def incomplete_output(
    target: str,
    failure: BrowserCoverageIncomplete,
    *,
    final_url: Optional[str] = None,
    status: Optional[int] = None,
    scoped: Optional[ScopedBrowserContext] = None,
) -> Dict[str, Any]:
    output = {
        "success": False,
        "coverageStatus": "INCOMPLETE",
        "coverageReason": failure.reason,
        "verified": False,
        "target": target,
        "finalUrl": final_url,
        "status": status,
        "error": failure.detail,
        "findings": [],
    }
    if scoped is not None:
        output["scopeMetadata"] = scoped.scope_metadata()
    return output
