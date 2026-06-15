"""
AI-Driven Browser Login Tool (Phase 3 + MFA Support)
Performs automated browser login using AI to identify and interact with login forms.
Supports multi-step MFA flows with hybrid screenshot+HTML analysis and multi-strategy locators.
"""

import asyncio
import base64
import json
import re
import yaml
import os
import time
from pathlib import Path
from typing import Dict, Any, List, Optional
from urllib.parse import parse_qs, urljoin, urlparse
from plugin_interface import ToolPlugin


# Phase 8 hardening (BUG-556): cookie filter for AI Login output.
# Without this, every cookie from every domain visited during the login
# (including third-party trackers, analytics, and SSO/OIDC intermediaries)
# was forwarded to the backend trace + cookies_string + artifact files,
# leaking session material that does not belong to the target.
_SESSION_COOKIE_NAME_PREFIXES = (
    "PHPSESSID", "JSESSIONID", "ASPSESSIONID", "ASP.NET_SessionId",
    "session", "sess", "sid", "auth", "csrf", "xsrf", "X-CSRF",
    "AWSELB", "AWSALB", "ROUTEID", "JWT", "access_token", "refresh_token",
    "_session", "_csrf", "remember", "rememberme",
)

USERNAME_FALLBACK_STRATEGIES = [
    {"type": "css", "selector": "input#i0116"},
    {"type": "css", "selector": "input[name='loginfmt']"},
    {"type": "css", "selector": "input[type='email']"},
    {"type": "css", "selector": "input[name='email']"},
    {"type": "css", "selector": "input[name='username']"},
    {"type": "css", "selector": "input[id*='email' i]"},
    {"type": "css", "selector": "input[id*='user' i]"},
    {"type": "css", "selector": "input[autocomplete='username']"},
    {"type": "css", "selector": "input[type='text']"},
]

PASSWORD_FALLBACK_STRATEGIES = [
    {"type": "css", "selector": "input#i0118"},
    {"type": "css", "selector": "input[name='passwd']"},
    {"type": "css", "selector": "input[name='Password']"},
    {"type": "css", "selector": "input[type='password']"},
    {"type": "css", "selector": "input[name='password']"},
    {"type": "css", "selector": "input[id*='pass' i]"},
    {"type": "css", "selector": "input[autocomplete='current-password']"},
]

SUBMIT_FALLBACK_STRATEGIES = [
    {"type": "css", "selector": "input#idSIButton9"},
    {"type": "css", "selector": "button#idSIButton9"},
    {"type": "css", "selector": "input#idSubmit_SAOTCC_Continue"},
    {"type": "css", "selector": "input[value='Next']"},
    {"type": "css", "selector": "input[value='Sign in']"},
    {"type": "css", "selector": "input[value='Verify']"},
    {"type": "css", "selector": "input[value='Continue']"},
    {"type": "css", "selector": "button[type='submit']"},
    {"type": "css", "selector": "input[type='submit']"},
    {"type": "css", "selector": "input[type='button']"},
    {"type": "css", "selector": "button:has-text('Sign in')"},
    {"type": "css", "selector": "button:has-text('Sign In')"},
    {"type": "css", "selector": "button:has-text('Log in')"},
    {"type": "css", "selector": "button:has-text('Login')"},
    {"type": "css", "selector": "button:has-text('Continue')"},
    {"type": "css", "selector": "button:has-text('Next')"},
    {"type": "css", "selector": "button:has-text('Entrar')"},
    {"type": "css", "selector": "button:has-text('Continuar')"},
    {"type": "css", "selector": "input[value='Next']"},
    {"type": "css", "selector": "input[value='Sign in']"},
    {"type": "css", "selector": "input[value='Verify']"},
    {"type": "css", "selector": "input[value='Entrar']"},
    {"type": "css", "selector": "input[value='Continuar']"},
    {"type": "css", "selector": "button:has-text('Microsoft')"},
    {"type": "css", "selector": "a:has-text('Microsoft')"},
    {"type": "css", "selector": "[role='button']:has-text('Microsoft')"},
    {"type": "css", "selector": "[role='button']:has-text('Sign in')"},
    {"type": "css", "selector": "[role='button']:has-text('Continue')"},
    {"type": "css", "selector": "[role='button']:has-text('Next')"},
]

POST_LOGIN_INTERSTITIAL_STRATEGIES = [
    {"type": "css", "selector": "input#idSIButton9"},
    {"type": "css", "selector": "button#idSIButton9"},
    {"type": "css", "selector": "input[value='Continue']"},
    {"type": "css", "selector": "input[value='Next']"},
    {"type": "css", "selector": "input[value='Yes']"},
    {"type": "css", "selector": "button:has-text('Continue')"},
    {"type": "css", "selector": "button:has-text('Continuar')"},
    {"type": "css", "selector": "button:has-text('Next')"},
    {"type": "css", "selector": "button:has-text('Yes')"},
    {"type": "css", "selector": "a:has-text('Continue')"},
    {"type": "css", "selector": "a:has-text('Continuar')"},
    {"type": "css", "selector": "[role='button']:has-text('Continue')"},
    {"type": "css", "selector": "[role='button']:has-text('Continuar')"},
    {"type": "css", "selector": "[data-testid*='continue' i]"},
]

OTP_FALLBACK_STRATEGIES = [
    {"type": "css", "selector": "input#idTxtBx_SAOTCC_OTC"},
    {"type": "css", "selector": "input[name='otc']"},
    {"type": "css", "selector": "input[autocomplete='one-time-code']"},
    {"type": "css", "selector": "input[inputmode='numeric']"},
    {"type": "css", "selector": "input[type='tel']"},
    {"type": "css", "selector": "input[type='number']"},
    {"type": "css", "selector": "input[id*='otp' i]"},
    {"type": "css", "selector": "input[name*='otp' i]"},
    {"type": "css", "selector": "input[id*='code' i]"},
    {"type": "css", "selector": "input[name*='code' i]"},
]

NUMBER_MATCHING_MARKERS = (
    "enter the number shown",
    "enter the number displayed",
    "enter this number",
    "enter the number",
    "type the number shown",
    "type the number displayed",
    "number matching",
    "approve sign in request",
    "approve the sign-in request",
    "digite o número",
    "digite o numero",
    "insira o número",
    "insira o numero",
    "número mostrado",
    "numero mostrado",
    "número exibido",
    "numero exibido",
)

OTP_APP_CODE_MARKERS = (
    "enter the code displayed in the microsoft authenticator app",
    "enter the code displayed",
    "enter code",
    "verification code",
    "one-time code",
    "código exibido",
    "codigo exibido",
    "código mostrado",
    "codigo mostrado",
    "código de verificação",
    "codigo de verificacao",
)

LOGIN_TRIGGER_LABEL_RE = re.compile(
    r"^(entrar|login|log in|sign in|sign-in|acessar)$",
    re.IGNORECASE,
)


async def request_operator_input(
    agent,
    job_id: Optional[str],
    request_id: str,
    *,
    kind: str,
    label: str,
    prompt: str,
    helper_text: Optional[str],
    current_target: str,
    expires_in_seconds: int,
    mfa_round: int,
    challenge_code: Optional[str] = None,
    display_value: Optional[str] = None,
    challenge_prompt: Optional[str] = None,
) -> bool:
    """Tell the backend/UI that this job is blocked on human MFA input."""
    if not agent or not job_id:
        return False
    try:
        import aiohttp

        payload = {
            "requestId": request_id,
            "kind": kind,
            "label": label,
            "prompt": prompt,
            "helperText": helper_text,
            "currentOperation": label,
            "currentTarget": current_target,
            "expiresInSeconds": expires_in_seconds,
            "mfaRound": mfa_round,
        }
        if challenge_code:
            payload["challengeCode"] = challenge_code
        if display_value:
            payload["displayValue"] = display_value
        if challenge_prompt:
            payload["challengePrompt"] = challenge_prompt
        async with aiohttp.ClientSession(headers={"X-API-Key": agent.api_key}) as session:
            async with session.post(
                f"{agent.api_url}/agents/jobs/{job_id}/operator-input/request",
                json=payload,
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                if 200 <= resp.status < 300:
                    return True
                body = await resp.text()
                print(f"[AI Login] Operator input request failed: HTTP {resp.status} {body[:200]}")
    except Exception as exc:
        print(f"[AI Login] Operator input request error: {exc}")
    return False


async def consume_operator_input(agent, job_id: Optional[str], request_id: str) -> Optional[Dict[str, Any]]:
    """Poll the backend for an operator-supplied MFA response."""
    if not agent or not job_id:
        return None
    try:
        import aiohttp

        async with aiohttp.ClientSession(headers={"X-API-Key": agent.api_key}) as session:
            async with session.get(
                f"{agent.api_url}/agents/jobs/{job_id}/operator-input",
                params={"requestId": request_id},
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                if 200 <= resp.status < 300:
                    data = await resp.json()
                    if data.get("available"):
                        return data
                return None
    except Exception as exc:
        print(f"[AI Login] Operator input poll error: {exc}")
        return None


def _domain_matches(cookie_domain: str, target_host: str) -> bool:
    """True if cookie_domain belongs to target_host (allowing leading dot)."""
    if not cookie_domain or not target_host:
        return False
    cd = cookie_domain.lstrip(".").lower()
    th = target_host.lower()
    return th == cd or th.endswith("." + cd) or cd.endswith("." + th)


def _is_session_cookie_name(name: str) -> bool:
    if not name:
        return False
    lower = name.lower()
    for prefix in _SESSION_COOKIE_NAME_PREFIXES:
        if lower == prefix.lower() or lower.startswith(prefix.lower()):
            return True
    return False


def filter_login_cookies(
    cookies: List[dict],
    login_url: str,
    extra_urls: Optional[List[str]] = None,
) -> List[dict]:
    """Restrict the cookie list to (a) the target domain or (b) known session
    cookie name prefixes. Defense in depth — drops third-party trackers and
    analytics cookies set during the login page load."""
    if not cookies:
        return []
    try:
        target_hosts = [urlparse(login_url).hostname or ""]
        for extra_url in extra_urls or []:
            extra_host = urlparse(extra_url).hostname or ""
            if extra_host:
                target_hosts.append(extra_host)
    except Exception:
        target_hosts = []
    out: List[dict] = []
    for c in cookies:
        try:
            domain_ok = any(
                _domain_matches(c.get("domain", ""), target_host)
                for target_host in target_hosts
            )
            name_ok = _is_session_cookie_name(c.get("name", ""))
            if domain_ok or name_ok:
                out.append(c)
        except Exception:
            # On any anomaly, exclude the cookie — fail closed.
            continue
    return out


# ---------------------------------------------------------------------------
# HTML extraction - pull out form-related elements to keep token count low
# ---------------------------------------------------------------------------

def extract_form_elements(html: str, max_chars: int = 12000) -> str:
    """Extract form/input/button/label elements from full page HTML.

    Falls back to truncated raw HTML if no forms are found.
    """
    # Try to extract <form>...</form> blocks first
    forms = re.findall(r"<form[\s\S]*?</form>", html, re.IGNORECASE)
    if forms:
        joined = "\n".join(forms)
        if len(joined) <= max_chars:
            return joined
        return joined[:max_chars]

    # No <form> tag - grab individual inputs/buttons/labels
    tags = re.findall(
        r"<(?:input|button|label|select|textarea|a\b)[^>]*(?:/>|>(?:[\s\S]*?</(?:button|label|select|textarea|a)>)?)",
        html,
        re.IGNORECASE,
    )
    if tags:
        joined = "\n".join(tags)
        if len(joined) <= max_chars:
            return joined
        return joined[:max_chars]

    # Last resort - head of body
    body_match = re.search(r"<body[\s\S]*", html, re.IGNORECASE)
    if body_match:
        return body_match.group(0)[:max_chars]
    return html[:max_chars]


# ---------------------------------------------------------------------------
# Multi-strategy field filling
# ---------------------------------------------------------------------------

async def fill_field(
    page,
    strategies: list,
    value: str,
    field_name: str,
    timeout_ms: int = 2500,
) -> bool:
    """Try multiple Playwright strategies to fill a form field."""
    for i, strat in enumerate(strategies):
        stype = strat.get("type", "")
        try:
            if stype == "role":
                locator = page.get_by_role(strat["role"], name=strat.get("name"))
            elif stype == "label":
                locator = page.get_by_label(strat["label"])
            elif stype == "placeholder":
                locator = page.get_by_placeholder(strat["placeholder"])
            elif stype == "css":
                locator = page.locator(strat["selector"])
            elif stype == "test_id":
                locator = page.get_by_test_id(strat["testId"])
            else:
                continue

            locator = first_locator(locator)
            await locator.wait_for(state="visible", timeout=timeout_ms)
            await locator.click(timeout=timeout_ms)
            await locator.fill(value, timeout=timeout_ms)
            print(f"[AI Login]   {field_name}: filled via '{stype}' strategy (attempt {i+1})")
            return True
        except Exception as exc:
            print(f"[AI Login]   {field_name}: strategy '{stype}' failed - {exc.__class__.__name__}")
            continue

    return False


async def click_element(
    page,
    strategies: list,
    element_name: str,
    timeout_ms: int = 2500,
) -> bool:
    """Try multiple Playwright strategies to click an element."""
    for i, strat in enumerate(strategies):
        stype = strat.get("type", "")
        try:
            if stype == "role":
                locator = page.get_by_role(strat["role"], name=strat.get("name"))
            elif stype == "label":
                locator = page.get_by_label(strat["label"])
            elif stype == "text":
                locator = page.get_by_text(strat["text"], exact=strat.get("exact", False))
            elif stype == "css":
                locator = page.locator(strat["selector"])
            elif stype == "test_id":
                locator = page.get_by_test_id(strat["testId"])
            else:
                continue

            locator = first_locator(locator)
            await locator.wait_for(state="visible", timeout=timeout_ms)
            await locator.click(timeout=timeout_ms)
            print(f"[AI Login]   {element_name}: clicked via '{stype}' strategy (attempt {i+1})")
            return True
        except Exception as exc:
            print(f"[AI Login]   {element_name}: strategy '{stype}' failed - {exc.__class__.__name__}")
            continue

    return False


def first_locator(locator):
    """Return the first locator for both old and new Playwright Python APIs."""
    first = getattr(locator, "first", None)
    return first() if callable(first) else first


async def has_visible_fillable_field(page, strategies: list, timeout_ms: int = 800) -> bool:
    """Return true only when a locator strategy points at a visible, enabled input."""
    for strat in strategies:
        stype = strat.get("type", "")
        try:
            if stype == "role":
                locator = page.get_by_role(strat["role"], name=strat.get("name"))
            elif stype == "label":
                locator = page.get_by_label(strat["label"])
            elif stype == "placeholder":
                locator = page.get_by_placeholder(strat["placeholder"])
            elif stype == "css":
                locator = page.locator(strat["selector"])
            elif stype == "test_id":
                locator = page.get_by_test_id(strat["testId"])
            else:
                continue

            locator = first_locator(locator)
            await locator.wait_for(state="visible", timeout=timeout_ms)
            if await locator.is_enabled(timeout=timeout_ms):
                return True
        except Exception:
            continue
    return False


async def extract_number_matching_challenge(page) -> Dict[str, Any]:
    """Detect Microsoft/SSO number matching where the operator enters the browser number in an app."""
    body_texts: List[str] = []
    visible_texts: List[str] = []
    number_candidates: List[Dict[str, Any]] = []
    extract_script = """() => {
        const isVisible = (el) => {
          const style = window.getComputedStyle(el);
          const rect = el.getBoundingClientRect();
          return style && style.visibility !== 'hidden' && style.display !== 'none' && rect.width > 0 && rect.height > 0;
        };
        const texts = [];
        const numbers = [];
        const pushText = (value, el, rect, style) => {
          const text = String(value || '').replace(/[\u200b\u200c\u200d]/g, '').trim();
          if (!text) return;
          texts.push(text);
          const clean = text.replace(/\\s+/g, ' ').trim();
          const compactDigits = clean.replace(/[\\s\\u00a0]+/g, '');
          const isChallengeSized = /^\\d{2,3}$/.test(compactDigits);
          const isStandaloneOrSpaced = /^\\d{2,3}$/.test(clean) || /^\\d(?:\\s+\\d){1,2}$/.test(clean);
          if (isChallengeSized && isStandaloneOrSpaced) {
            numbers.push({
              text: compactDigits,
              rawText: clean,
              fontSize: parseFloat(style.fontSize || '0') || 0,
              fontWeight: parseFloat(style.fontWeight || '0') || 0,
              area: Math.max(rect.width * rect.height, 0),
            });
          }
        };
        for (const el of Array.from(document.body ? document.body.querySelectorAll('*') : [])) {
          if (!isVisible(el)) continue;
          const rect = el.getBoundingClientRect();
          const style = window.getComputedStyle(el);
          const parts = [
            el.innerText,
            el.textContent,
            el.getAttribute('aria-label'),
            el.getAttribute('aria-description'),
            el.getAttribute('title'),
            el.getAttribute('value'),
            el.getAttribute('data-value'),
            el.getAttribute('data-code'),
          ];
          for (const text of Array.from(new Set(parts.filter(Boolean)))) {
            pushText(text, el, rect, style);
          }
        }
        numbers.sort((a, b) => (b.fontSize - a.fontSize) || (b.fontWeight - a.fontWeight) || (b.area - a.area));
        return {
          texts: Array.from(new Set(texts)).slice(0, 1200),
          numbers: numbers.slice(0, 30),
        };
    }"""

    frames = getattr(page, "frames", None) or []
    if callable(frames):
        try:
            frames = frames()
        except Exception:
            frames = []
    if not frames:
        frames = [page]

    for frame in frames:
        try:
            body_text = await frame.locator("body").inner_text(timeout=1200)
            if body_text:
                body_texts.append(body_text)
        except Exception:
            pass
        try:
            extracted = await frame.evaluate(extract_script)
            if isinstance(extracted, dict):
                visible_texts.extend(extracted.get("texts") or [])
                number_candidates.extend(extracted.get("numbers") or [])
        except Exception:
            continue

    combined_text = "\n".join(body_texts + visible_texts)
    normalized = combined_text.lower()
    if any(marker in normalized for marker in OTP_APP_CODE_MARKERS):
        return {"detected": False}

    marker_detected = any(marker in normalized for marker in NUMBER_MATCHING_MARKERS)
    if not marker_detected:
        return {"detected": False}

    candidates: List[str] = []
    for item in number_candidates:
        value = str(item.get("text", "")).strip()
        if re.fullmatch(r"\d{2,3}", value):
            candidates.append(value)

    body_lines = [line for text in body_texts for line in str(text).splitlines()]
    for text in visible_texts + body_lines:
        clean = " ".join(str(text).strip().split())
        if re.fullmatch(r"\d{2,3}", clean):
            candidates.append(clean)

    code_context_pattern = re.compile(
        r"(code|código|codigo|number|número|numero|shown|displayed|insira|enter|type|digite)",
        re.IGNORECASE,
    )
    noisy_context_pattern = re.compile(
        r"(phone|telefone|service desk|support|helpdesk|ticket|case|year|copyright)",
        re.IGNORECASE,
    )
    separated_digits_pattern = re.compile(r"(?<!\d)(\d(?:[\s\u00a0\u200b\u200c\u200d]*\d){1,2})(?!\d)")
    for raw_line in combined_text.splitlines():
        clean_line = " ".join(str(raw_line).strip().split())
        if not clean_line or noisy_context_pattern.search(clean_line):
            continue
        if not code_context_pattern.search(clean_line):
            continue
        for match in separated_digits_pattern.finditer(clean_line):
            compact = re.sub(r"\D", "", match.group(1))
            if 2 <= len(compact) <= 3:
                candidates.append(compact)

    if not candidates:
        contextual_patterns = [
            r"(?:enter|type|use|digite|insira)[^\d]{0,120}(\d(?:[\s\u00a0\u200b\u200c\u200d]*\d){1,2})",
            r"(\d(?:[\s\u00a0\u200b\u200c\u200d]*\d){1,2})[^\n]{0,120}(?:authenticator|aplicativo|app|aprovar|approve)",
            r"(?:code|código|codigo|number|número|numero)[^\d]{0,120}(\d(?:[\s\u00a0\u200b\u200c\u200d]*\d){1,2})",
        ]
        for pattern in contextual_patterns:
            match = re.search(pattern, combined_text, re.IGNORECASE)
            if match:
                candidates.append(re.sub(r"\D", "", match.group(1)))
                break

    seen_candidates = []
    for candidate in candidates:
        if candidate not in seen_candidates and not re.fullmatch(r"19\d{2}|20\d{2}", candidate):
            seen_candidates.append(candidate)

    challenge_code = seen_candidates[0] if seen_candidates else None
    snippet = " ".join(combined_text.split())[:240]
    return {
        "detected": True,
        "challengeCode": challenge_code,
        "displayValue": challenge_code,
        "challengePrompt": snippet,
    }


def normalize_number_matching_code(value: Any) -> Optional[str]:
    """Return a 2-3 digit Microsoft Authenticator number if one is present."""
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    compact = re.sub(r"\D", "", text)
    if 2 <= len(compact) <= 3 and not re.fullmatch(r"19\d{2}|20\d{2}", compact):
        return compact
    return None


async def count_visible_login_inputs(page) -> int:
    """Count visible fields that can plausibly participate in a login form."""
    try:
        return await page.locator(
            "input:visible, textarea:visible, [contenteditable='true']:visible"
        ).count()
    except Exception:
        return 0


async def count_visible_auth_challenge_inputs(page) -> int:
    """Count visible fields that strongly indicate an auth challenge.

    Authenticated apps commonly expose search boxes, filters, comments, and
    other inputs. Those must not make a protected resource validation fail.
    Only count fields that look like login, password, username, or IdP prompts.
    """
    selectors = [
        "input[type='password']:visible",
        "input[autocomplete='current-password']:visible",
        "input[autocomplete='username']:visible",
        "input[name='password' i]:visible",
        "input[id*='pass' i]:visible",
        "input[placeholder*='password' i]:visible",
        "input[type='email']:visible",
        "input[name='email' i]:visible",
        "input[id*='email' i]:visible",
        "input[placeholder*='email' i]:visible",
        "input[name='username' i]:visible",
        "input[id*='user' i]:visible",
        "input[placeholder*='username' i]:visible",
        "input[name='loginfmt']:visible",
        "input#i0116:visible",
        "input#i0118:visible",
    ]
    total = 0
    for selector in selectors:
        try:
            total += await page.locator(selector).count()
        except Exception:
            continue
    return total


async def open_login_surface_if_needed(page, wait_ms: int = 1000) -> bool:
    """Open SPA login modals/drawers when the initial URL has no form fields.

    Some apps keep the URL unchanged and expose the login form only after a
    header button ("Entrar", "Login", "Sign in") is clicked. Testing should be
    fast and deterministic for that common case instead of asking the LLM to
    infer selectors from a page that has no inputs.
    """
    if await count_visible_login_inputs(page) > 0:
        return False

    trigger_locators = [
        page.get_by_role("button", name=LOGIN_TRIGGER_LABEL_RE),
        page.get_by_role("link", name=LOGIN_TRIGGER_LABEL_RE),
        page.locator("button:has-text('Entrar')"),
        page.locator("a:has-text('Entrar')"),
        page.locator("button:has-text('Login')"),
        page.locator("a:has-text('Login')"),
        page.locator("button:has-text('Sign in')"),
        page.locator("a:has-text('Sign in')"),
    ]

    for i, locator in enumerate(trigger_locators):
        try:
            candidate = first_locator(locator)
            await candidate.wait_for(state="visible", timeout=1500)
            await candidate.click()
            await page.wait_for_timeout(wait_ms)
            if await count_visible_login_inputs(page) > 0:
                print(f"[AI Login]   Opened login surface via trigger strategy {i + 1}")
                return True
        except Exception as exc:
            print(f"[AI Login]   Login trigger strategy {i + 1} failed - {exc.__class__.__name__}")
            continue

    return False


def _url_host(url: Optional[str]) -> str:
    try:
        return urlparse(url or "").hostname or ""
    except Exception:
        return ""


def _looks_like_auth_url(current_url: str, login_url: str, protected_resource_url: str) -> bool:
    """Detect common IdP/login redirects after a supposed successful login."""
    current_host = _url_host(current_url)
    login_host = _url_host(login_url)
    protected_host = _url_host(protected_resource_url)
    if not current_host:
        return True
    if protected_host and _domain_matches(current_host, protected_host):
        return False
    if login_host and _domain_matches(current_host, login_host):
        return True
    lowered = current_url.lower()
    return any(
        marker in lowered
        for marker in (
            "/login",
            "/signin",
            "/sign-in",
            "/auth",
            "/oauth",
            "/saml",
            "mfa",
            "2fa",
            "idp",
            "identity",
        )
    )


def _continue_chain_reaches_protected(
    candidate_url: str,
    protected_resource_url: str,
    *,
    depth: int = 0,
) -> bool:
    """Return true when a redirect/continue chain eventually targets the protected app."""
    if depth > 3:
        return False
    protected_host = _url_host(protected_resource_url)
    candidate_host = _url_host(candidate_url)
    if candidate_host and protected_host and _domain_matches(candidate_host, protected_host):
        return True
    try:
        parsed = urlparse(candidate_url)
        query = parse_qs(parsed.query)
        for key, values in query.items():
            if key.lower() not in ("continue", "redirect", "redirect_uri", "return", "returnurl", "relaystate"):
                continue
            for value in values:
                nested = urljoin(candidate_url, value)
                if nested != candidate_url and _continue_chain_reaches_protected(
                    nested,
                    protected_resource_url,
                    depth=depth + 1,
                ):
                    return True
    except Exception:
        return False
    return False


def _extract_protected_continue_url(current_url: str, protected_resource_url: str) -> Optional[str]:
    """Return a safe IdP continuation URL when it points back to the protected app."""
    try:
        parsed = urlparse(current_url)
        query = parse_qs(parsed.query)
        protected_host = _url_host(protected_resource_url)
        for key, values in query.items():
            if key.lower() not in ("continue", "redirect", "redirect_uri", "return", "returnurl", "relaystate"):
                continue
            for value in values:
                candidate = urljoin(current_url, value)
                candidate_host = _url_host(candidate)
                if candidate_host and protected_host and _domain_matches(candidate_host, protected_host):
                    return candidate
                if _continue_chain_reaches_protected(candidate, protected_resource_url):
                    return candidate
    except Exception:
        return None
    return None


async def advance_post_login_interstitials(
    page,
    protected_resource_url: str,
    *,
    login_url: str,
    page_load_strategy: str,
    timeout_ms: int,
    settle_ms: int,
) -> List[Dict[str, Any]]:
    """Try to complete harmless post-login continue screens before validation.

    SSO providers frequently land on an IdP-hosted "continue to app" or
    "stay signed in" page after MFA. These are not new credentials prompts, so
    we can safely advance through explicit continue buttons or redirect params.
    We intentionally avoid "Request access" style actions because they create
    an external side effect and do not prove a reusable app session.
    """
    actions: List[Dict[str, Any]] = []
    visited: set = set()

    for attempt in range(6):
        current_url = page.url or ""
        if current_url in visited:
            break
        visited.add(current_url)

        if not _looks_like_auth_url(current_url, login_url, protected_resource_url):
            break

        continue_url = _extract_protected_continue_url(current_url, protected_resource_url)
        if continue_url and continue_url != current_url:
            actions.append({
                "action": "follow_continue_url",
                "from": current_url,
                "to": continue_url,
            })
            try:
                await page.goto(
                    continue_url,
                    wait_until=page_load_strategy,
                    timeout=timeout_ms,
                )
            except Exception as exc:
                actions.append({
                    "action": "follow_continue_url_failed",
                    "error": exc.__class__.__name__,
                })
                break
            if settle_ms > 0:
                await asyncio.sleep(max(settle_ms, 2500) / 1000)
            continue

        before_click_url = current_url
        clicked = await click_element(
            page,
            POST_LOGIN_INTERSTITIAL_STRATEGIES,
            "post_login_interstitial",
            timeout_ms=1500,
        )
        if clicked:
            actions.append({
                "action": "click_continue_control",
                "from": before_click_url,
            })
            try:
                await page.wait_for_load_state(page_load_strategy, timeout=min(timeout_ms, 10000))
            except Exception:
                pass
            if settle_ms > 0:
                await asyncio.sleep(max(settle_ms, 2500) / 1000)

            if page.url != before_click_url:
                continue

        break


    return actions


async def validate_protected_resource_session(
    page,
    protected_resource_url: Optional[str],
    *,
    login_url: str,
    page_load_strategy: str,
    timeout_ms: int,
    settle_ms: int,
    agent,
) -> Dict[str, Any]:
    """Open the protected app URL and verify the browser is not still at login.

    Job completion alone is not enough for SSO/MFA. The reusable session is only
    trustworthy when the browser can reach the tenant/app resource after the IdP
    flow has finished.
    """
    if not protected_resource_url:
        return {"valid": True, "reason": "no protected resource configured"}

    if agent:
        agent.report_progress(
            current_operation="Validating captured session against protected resource",
            current_target=protected_resource_url,
        )

    try:
        await page.goto(
            protected_resource_url,
            wait_until=page_load_strategy,
            timeout=timeout_ms,
        )
    except Exception as exc:
        return {
            "valid": False,
            "reason": f"Protected resource navigation failed: {exc.__class__.__name__}",
            "current_url": getattr(page, "url", protected_resource_url),
        }

    if settle_ms > 0:
        await asyncio.sleep(settle_ms / 1000)
    try:
        await page.wait_for_load_state(page_load_strategy, timeout=min(timeout_ms, 10000))
    except Exception:
        pass

    interstitial_actions = await advance_post_login_interstitials(
        page,
        protected_resource_url,
        login_url=login_url,
        page_load_strategy=page_load_strategy,
        timeout_ms=timeout_ms,
        settle_ms=settle_ms,
    )

    current_url = page.url or protected_resource_url
    page_inputs = await count_visible_login_inputs(page)
    auth_inputs = await count_visible_auth_challenge_inputs(page)
    auth_url = _looks_like_auth_url(current_url, login_url, protected_resource_url)

    if auth_url or auth_inputs > 0:
        return {
            "valid": False,
            "reason": (
                "Protected resource still looks unauthenticated "
                f"(currentUrl={current_url}, visibleAuthInputs={auth_inputs}, visiblePageInputs={page_inputs})"
            ),
            "current_url": current_url,
            "visible_login_inputs": auth_inputs,
            "visible_page_inputs": page_inputs,
            "auth_url": auth_url,
            "interstitial_actions": interstitial_actions,
        }

    return {
        "valid": True,
        "reason": "protected resource loaded without a login challenge",
        "current_url": current_url,
        "visible_login_inputs": auth_inputs,
        "visible_page_inputs": page_inputs,
        "auth_url": auth_url,
        "interstitial_actions": interstitial_actions,
    }


# ---------------------------------------------------------------------------
# Claude prompt builders
# ---------------------------------------------------------------------------

def build_selector_prompt(form_html: str, login_instructions: Optional[str]) -> str:
    extra = ""
    if login_instructions:
        extra = f"\nAdditional context from user: {login_instructions}\n"

    return f"""Analyze this login page. I am providing both a screenshot AND the actual HTML of the page.

Here is the HTML containing the form elements:

```html
{form_html}
```
{extra}
Provide Playwright locator strategies for:
1. The username / email input field
2. The password input field
3. The login / submit button

For EACH element, return an ordered list of strategies to try (best first).
Strategy types:
- {{"type":"role","role":"textbox","name":"Username"}}
- {{"type":"label","label":"Email"}}
- {{"type":"placeholder","placeholder":"Enter your email"}}
- {{"type":"css","selector":"#email"}}
- {{"type":"test_id","testId":"login-email"}}
- For buttons: {{"type":"role","role":"button","name":"Sign In"}} or {{"type":"text","text":"Log In"}}

Respond ONLY with valid JSON (no markdown fences):
{{
  "usernameField": [
    {{"type":"...","...":"..."}},
    ...
  ],
  "passwordField": [
    {{"type":"...","...":"..."}},
    ...
  ],
  "submitButton": [
    {{"type":"...","...":"..."}},
    ...
  ]
}}"""


def build_post_submit_prompt(form_html: str, login_instructions: Optional[str]) -> str:
    extra = ""
    if login_instructions:
        extra = f"\nContext: {login_instructions}\n"

    return f"""Analyze this page that appeared after submitting login credentials.
I am providing both a screenshot AND the actual HTML.

HTML:
```html
{form_html}
```
{extra}
Classify this page as ONE of:
A) Successful login (dashboard, main app, welcome page)
B) MFA / verification / 2FA / OTP code entry page
C) Login error (wrong password, account locked, etc.)

If B (MFA page), also provide Playwright locator strategies for:
- The code / OTP / verification input field (if present - some MFA pages are just method selection with no code field)
- The verify / submit / continue button

If the screenshot shows Microsoft Authenticator number matching, where the browser displays a
2-3 digit number that the operator must type into the mobile authenticator app, return that exact
number as "numberMatchingCode". This is different from an OTP input field. If no number is visible,
set "numberMatchingCode" to null.

Respond ONLY with valid JSON (no markdown fences):
For success: {{"status":"success"}}
For MFA:     {{"status":"mfa","codeField":[{{"type":"css","selector":"#otp"}}],"submitButton":[{{"type":"role","role":"button","name":"Verify"}}],"numberMatchingCode":null}}
For number matching MFA: {{"status":"mfa","codeField":[],"submitButton":[{{"type":"role","role":"button","name":"Continue"}}],"numberMatchingCode":"64"}}
For MFA without code field (method selection): {{"status":"mfa","codeField":[],"submitButton":[{{"type":"role","role":"button","name":"Continue"}}],"numberMatchingCode":null}}
For error:   {{"status":"error","message":"description"}}"""


RELAY_JSON_SYSTEM_PROMPT = (
    "You are an AI browser login assistant. Analyze screenshots and form HTML, "
    "then return only the requested JSON object. Do not include markdown fences."
)


def build_backend_url(api_url: str, path: str) -> str:
    """Resolve backend-relative config paths against the agent's /api URL."""
    if path.startswith("http://") or path.startswith("https://"):
        return path
    parsed = urlparse(api_url)
    if path.startswith("/"):
        return f"{parsed.scheme}://{parsed.netloc}{path}"
    return urljoin(api_url.rstrip("/") + "/", path)


async def ask_backend_relay(
    relay_url: str,
    agent_api_key: str,
    screenshot_b64: str,
    text_prompt: str,
    timeout_seconds: int = 75,
) -> dict:
    """Send screenshot + text to the backend LLM relay and parse JSON response."""
    import aiohttp

    body = {
        "kind": "agent_relay",
        "purpose": "browser_login_ai",
        "systemPrompt": RELAY_JSON_SYSTEM_PROMPT,
        "messages": [
            {
                "role": "user",
                "content": [
                    {
                        "type": "image",
                        "mediaType": "image/png",
                        "data": screenshot_b64,
                    },
                    {"type": "text", "text": text_prompt},
                ],
            }
        ],
        "maxOutputTokens": 1500,
    }
    timeout = aiohttp.ClientTimeout(total=timeout_seconds)
    async with aiohttp.ClientSession(timeout=timeout, headers={"X-API-Key": agent_api_key}) as session:
        async with session.post(relay_url, json=body, headers={"Content-Type": "application/json"}) as resp:
            text = await resp.text()
            if resp.status >= 400:
                raise RuntimeError(f"Backend LLM relay error {resp.status}: {text[:500]}")
            data = json.loads(text)
    raw = data.get("content") or ""
    return _extract_json_object(raw, vendor='backend_relay')


async def ask_claude(client, screenshot_b64: str, text_prompt: str) -> dict:
    """Send screenshot + text to Claude and parse JSON response."""
    response = await asyncio.to_thread(
        client.messages.create,
        model="claude-sonnet-4-20250514",
        max_tokens=1500,
        messages=[{
            "role": "user",
            "content": [
                {
                    "type": "image",
                    "source": {
                        "type": "base64",
                        "media_type": "image/png",
                        "data": screenshot_b64,
                    },
                },
                {"type": "text", "text": text_prompt},
            ],
        }],
    )

    raw = response.content[0].text
    return _extract_json_object(raw, vendor='anthropic')


# Phase 6 — Gemini multimodal client. The platform LLM is vendor-agnostic;
# when the operator configures Gemini (vendor='google'), this code path runs
# instead of `ask_claude` with the same multimodal contract (image + text →
# JSON). Uses Gemini's REST API directly so no new SDK install is required —
# the agent already has aiohttp.
# Phase 8 hardening (BUG-557): pass the Gemini API key in the `x-goog-api-key`
# header rather than as a `?key=` URL query parameter. URL query strings are
# captured verbatim in HTTP access logs on the agent host, by any TLS-
# terminating proxy in the path, and by Gemini error response bodies.
GEMINI_GENERATE_URL = (
    "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
)
# Translate the platform's stored model name into one the Gemini REST API
# accepts. The "preview" suffix is used by some internal naming; map to the
# closest published multimodal-capable Gemini for AI Login.
def _resolve_gemini_model(name: Optional[str]) -> str:
    if not name:
        return "gemini-2.5-flash"
    n = name.lower()
    if "flash-lite" in n:
        return "gemini-2.5-flash-lite"
    if "flash" in n:
        return "gemini-2.5-flash"
    if "pro" in n:
        return "gemini-2.5-pro"
    return "gemini-2.5-flash"


async def ask_gemini(
    api_key: str,
    model: str,
    screenshot_b64: str,
    text_prompt: str,
    timeout_seconds: int = 60,
) -> dict:
    """Send screenshot + text to Gemini multimodal API and parse JSON response."""
    import aiohttp
    body = {
        "contents": [
            {
                "role": "user",
                "parts": [
                    {"text": text_prompt},
                    {
                        "inline_data": {
                            "mime_type": "image/png",
                            "data": screenshot_b64,
                        }
                    },
                ],
            }
        ],
        "generationConfig": {
            "temperature": 0.0,
            "maxOutputTokens": 1500,
            "responseMimeType": "application/json",
        },
    }
    resolved = _resolve_gemini_model(model)
    url = GEMINI_GENERATE_URL.format(model=resolved)
    timeout = aiohttp.ClientTimeout(total=timeout_seconds)
    headers = {
        "Content-Type": "application/json",
        "x-goog-api-key": api_key,
    }
    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.post(url, json=body, headers=headers) as resp:
            text = await resp.text()
            if resp.status >= 400:
                # Sanitize any echo of the API key from the error body before raising.
                safe_text = text[:300].replace(api_key, "***REDACTED***") if api_key else text[:300]
                raise RuntimeError(f"Gemini API error {resp.status}: {safe_text}")
            data = json.loads(text)
    candidates = data.get("candidates") or []
    if not candidates:
        raise ValueError(f"Gemini returned no candidates: {text[:300]}")
    parts = (candidates[0].get("content") or {}).get("parts") or []
    raw_text = next((p.get("text") for p in parts if p.get("text")), None)
    if not raw_text:
        raise ValueError(f"Gemini returned no text content: {parts}")
    return _extract_json_object(raw_text, vendor='gemini')


def _extract_json_object(raw: str, vendor: str = 'llm') -> dict:
    """Extract the first balanced JSON object from a free-form LLM response."""
    start = raw.find('{')
    if start == -1:
        raise ValueError(f"{vendor} did not return valid JSON.\nRaw response:\n{raw[:500]}")
    depth = 0
    end = start
    for i in range(start, len(raw)):
        if raw[i] == '{':
            depth += 1
        elif raw[i] == '}':
            depth -= 1
            if depth == 0:
                end = i + 1
                break
    json_str = raw[start:end]
    if not json_str:
        raise ValueError(f"{vendor} did not return valid JSON.\nRaw response:\n{raw[:500]}")
    return json.loads(json_str)


async def ask_llm(
    *,
    vendor: str,
    screenshot_b64: str,
    text_prompt: str,
    relay_url: Optional[str] = None,
    agent_api_key: Optional[str] = None,
    anthropic_client=None,
    gemini_api_key: Optional[str] = None,
    gemini_model: Optional[str] = None,
    llm_timeout_seconds: int = 75,
) -> dict:
    """Vendor-agnostic LLM call. Branches on vendor and forwards to the
    matching provider implementation. Phase 6 — added Google/Gemini path so
    AI Login works against whichever LLM the operator configured at the
    platform (Settings → LLM)."""
    if relay_url and agent_api_key:
        return await ask_backend_relay(
            relay_url,
            agent_api_key,
            screenshot_b64,
            text_prompt,
            timeout_seconds=llm_timeout_seconds,
        )
    if vendor == 'anthropic':
        if anthropic_client is None:
            raise ValueError("anthropic vendor selected but client is None")
        return await ask_claude(anthropic_client, screenshot_b64, text_prompt)
    if vendor in ('google', 'gemini'):
        if not gemini_api_key:
            raise ValueError("google/gemini vendor selected but api key is missing")
        return await ask_gemini(
            gemini_api_key,
            gemini_model or "gemini-2.5-flash",
            screenshot_b64,
            text_prompt,
            timeout_seconds=llm_timeout_seconds,
        )
    raise NotImplementedError(
        f"AI Login does not yet support LLM vendor '{vendor}'. "
        "Configure 'anthropic' or 'google' in platform LLM settings."
    )


# ---------------------------------------------------------------------------
# Debug screenshot helper
# ---------------------------------------------------------------------------

DEBUG_SCREENSHOT_DIR = Path("/tmp/ai_login_debug")


async def save_debug_screenshot(page, step: int, description: str, enabled: bool = False) -> Optional[str]:
    """Save a debug screenshot if debug mode is enabled."""
    if not enabled:
        return None
    DEBUG_SCREENSHOT_DIR.mkdir(parents=True, exist_ok=True)
    filename = f"step_{step:02d}_{description}.png"
    filepath = DEBUG_SCREENSHOT_DIR / filename
    await page.screenshot(path=str(filepath))
    print(f"[AI Login]   Debug screenshot saved: {filepath}")
    return str(filepath)


class BrowserLoginAiTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "authentication:ai_browser_login"

    @property
    def description(self) -> str:
        return "Authentication - AI Browser Login: AI-driven browser login using natural language instructions to authenticate on any login page. Supports multi-step MFA flows."

    @property
    def schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "loginUrl": {
                    "type": "string",
                    "description": "Login page URL (auto-injected from credentials)"
                },
                "username": {
                    "type": "string",
                    "description": "Username for login (auto-injected from credentials)"
                },
                "password": {
                    "type": "string",
                    "description": "Password for login (auto-injected from credentials)"
                },
                "loginInstructions": {
                    "type": "string",
                    "description": "Natural language instructions for AI (auto-injected from credentials)"
                },
                "headless": {
                    "type": "boolean",
                    "description": "Run browser in headless mode",
                    "default": True
                },
                "timeout_seconds": {
                    "type": "integer",
                    "description": "Maximum time to wait for login",
                    "default": 120
                },
                "mfaAutoFillTimeout": {
                    "type": "integer",
                    "description": "Seconds to poll for OTP auto-fill (default: 60)",
                    "default": 60
                },
                "mfaMaxRounds": {
                    "type": "integer",
                    "description": "Max MFA loop iterations (default: 5)",
                    "default": 5
                },
                "browserUserAgent": {
                    "type": "string",
                    "description": "Custom user-agent string for browser"
                },
                "browserViewport": {
                    "type": "object",
                    "description": "Custom viewport {width, height}",
                    "x-widget": "dimensions",
                    "properties": {
                        "width": {"type": "integer"},
                        "height": {"type": "integer"}
                    }
                },
                "debugScreenshots": {
                    "type": "boolean",
                    "description": "Save step-by-step debug screenshots to /tmp/ai_login_debug/",
                    "default": False
                }
            },
            "required": ["loginUrl", "username", "password"]
        }

    @property
    def metadata(self):
        return {
            "category": "auth",
            "phase": 0,
            "domain": ["web"],
            "input_type": ["url"],
            "output_type": ["session"],
            "chainable_after": [],
            "chainable_before": ["katana:", "nuclei:", "sqlmap:"],
        }

    async def execute(self, parameters: Dict[str, Any]) -> Any:
        # Credentials are auto-injected by workflow engine
        login_url = parameters.get('loginUrl')
        username = parameters.get('username')
        password = parameters.get('password')
        login_instructions = parameters.get('loginInstructions')
        headless = parameters.get('headless', True)
        timeout_seconds = parameters.get('timeout_seconds', 120)
        protected_resource_url = parameters.get('protectedResourceUrl')
        agent = parameters.get('_agent')

        print(f"[AI Login] Starting execution for: {login_url}")
        print(f"[AI Login] Credentials: username=***REDACTED***, password={'***' if password else 'NONE'}")
        print(f"[AI Login] Headless: {headless}, Timeout: {timeout_seconds}s")

        try:
            # Report initial progress
            if agent:
                agent.report_progress(
                    current_operation="Initializing AI browser for login",
                    current_target=login_url,
                    items_processed=0,
                    total_items=None
                )

            # Validate required parameters
            if not login_url or not username or not password:
                error_msg = f'Missing required parameters: loginUrl={bool(login_url)}, username={bool(username)}, password={bool(password)}'
                print(f"[AI Login] ERROR: {error_msg}")
                return {
                    'status': 'FAILED',
                    'error': error_msg,
                    'session_valid': False
                }

            # Report progress
            if agent:
                agent.report_progress(
                    current_operation="Performing AI-driven browser login",
                    current_target=login_url,
                    items_processed=1,
                    total_items=4
                )

            # Perform AI-driven login
            print(f"[AI Login] Calling _ai_driven_login...")
            login_result = await self._ai_driven_login(
                login_url=login_url,
                username=username,
                password=password,
                login_instructions=login_instructions,
                headless=headless,
                timeout_seconds=timeout_seconds,
                agent=agent,
                parameters=parameters
            )

            print(f"[AI Login] Login result: success={login_result.get('success')}, cookies_count={len(login_result.get('cookies', []))}")

            if not login_result['success']:
                error = login_result.get('error', 'Login failed')
                print(f"[AI Login] Login FAILED: {error[0:200]}")
                return {
                    'status': 'FAILED',
                    'error': error,
                    'session_valid': False,
                    'login_method': 'ai'
                }

            # Report progress
            if agent:
                agent.report_progress(
                    current_operation="Extracting session artifacts",
                    current_target=login_url,
                    items_processed=2,
                    total_items=4
                )

            # Phase 8 hardening (BUG-556): filter cookies to the login target's
            # domain or to known session cookie name prefixes BEFORE passing
            # them to artifact generation, the inline cookies_string, the
            # cookies_list reported to the backend, and the result returned to
            # the agent. Third-party tracker/analytics cookies set during the
            # login page load do not belong to the target and must not be
            # forwarded to downstream scanners or to the trace event stream.
            raw_cookies = login_result.get('cookies', []) or []
            filtered_cookies = filter_login_cookies(
                raw_cookies,
                login_url,
                extra_urls=[protected_resource_url] if protected_resource_url else None,
            )
            dropped = len(raw_cookies) - len(filtered_cookies)
            if dropped > 0:
                print(f"[AI Login] Filtered out {dropped} non-session/cross-domain cookie(s) before artifact generation.")

            if not filtered_cookies:
                return {
                    'status': 'FAILED',
                    'error': (
                        'Login flow completed, but no reusable cookies were captured for '
                        'the login or protected resource domains.'
                    ),
                    'session_valid': False,
                    'login_method': 'ai'
                }

            # Phase 8 hardening (BUG-558): do NOT forward the full
            # `storage_state` (Playwright returns localStorage + sessionStorage
            # for every origin visited during the login flow, including
            # OAuth/OIDC intermediaries that may store access/refresh tokens
            # in localStorage in plaintext). The downstream scanners only
            # need the cookie string; storage_state is intentionally dropped.
            artifacts = self._generate_artifacts(
                cookies=filtered_cookies,
                storage_state={}
            )

            # Report completion
            if agent:
                agent.report_progress(
                    current_operation="AI browser login completed",
                    current_target=login_url,
                    items_processed=4,
                    total_items=4
                )

            # Generate inline cookies string for auto-injection to subsequent steps
            cookies_string = '; '.join([f"{c['name']}={c['value']}" for c in filtered_cookies])

            result = {
                'status': 'SUCCESS',
                'login_method': 'ai',
                'headers_file': artifacts['headers_file'],
                'cookies_file': artifacts['cookies_file'],
                'secrets_file': artifacts['secrets_file'],
                'cookies': cookies_string,  # Inline cookies for auto-injection (Phase 3)
                'session_valid': True,
                'cookies_list': [
                    {'name': c['name'], 'domain': c.get('domain', '')}
                    for c in filtered_cookies
                ],
                'protected_resource_url': protected_resource_url,
                'protected_resource_validation': login_result.get('protected_resource_validation'),
                'execution_time_seconds': login_result.get('execution_time', 0),
                'ai_actions_count': login_result.get('actions_count', 0)
            }

            print(f"[AI Login] SUCCESS! Returning output with {len(result)} keys")
            print(f"[AI Login] Output keys: {list(result.keys())}")
            print(f"[AI Login] Cookies string: [REDACTED - {len(login_result['cookies'])} cookies captured]")

            return result

        except Exception as e:
            import traceback
            error_full = f"{str(e)}\n{traceback.format_exc()}"
            print(f"[AI Login] EXCEPTION in execute(): {error_full[0:300]}")
            return {
                'status': 'FAILED',
                'error': error_full,
                'session_valid': False,
                'login_method': 'ai'
            }

    async def _ai_driven_login(
        self,
        login_url: str,
        username: str,
        password: str,
        login_instructions: str,
        headless: bool,
        timeout_seconds: int,
        agent,
        parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Perform AI-assisted browser login using Playwright + Claude API.
        Supports multi-step MFA flows with hybrid screenshot+HTML analysis
        and multi-strategy Playwright locators.
        """
        try:
            from playwright.async_api import async_playwright

            # Read AI config parameters (injected from aiConfig)
            mfa_auto_fill_timeout = parameters.get('mfaAutoFillTimeout', 60)
            mfa_max_rounds = parameters.get('mfaMaxRounds', 5)
            browser_user_agent = parameters.get('browserUserAgent',
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            )
            browser_viewport = parameters.get('browserViewport', {"width": 1280, "height": 900})
            protected_resource_url = parameters.get('protectedResourceUrl')
            debug_screenshots = parameters.get('debugScreenshots', False)
            login_test_mode = bool(parameters.get('loginTestMode') or parameters.get('testMode'))
            job_id = parameters.get('_job_id')
            interactive_mfa = (
                parameters.get('sessionCaptureMode') == 'INTERACTIVE_SSO'
                or bool(parameters.get('humanMfaRequired'))
                or parameters.get('mfaInteractionMode') == 'operator_assisted'
            )
            if login_test_mode and not interactive_mfa:
                # Smoke tests must prove the auth path quickly. Full authenticated
                # scans can still use the richer, slower defaults.
                mfa_auto_fill_timeout = min(mfa_auto_fill_timeout, 5)
                mfa_max_rounds = min(mfa_max_rounds, 1)
                # 25s was too tight for a cold browser navigating a real
                # OIDC login over a corporate VPN (observed timeouts on
                # login.uat.questrade.com). 60s keeps the smoke test fast while
                # tolerating cold-start + redirect latency.
                timeout_seconds = min(timeout_seconds, 60)
            page_load_strategy = parameters.get(
                'pageLoadStrategy',
                'domcontentloaded' if login_test_mode else 'networkidle',
            )
            if page_load_strategy not in ('commit', 'domcontentloaded', 'load', 'networkidle'):
                page_load_strategy = 'domcontentloaded' if login_test_mode else 'networkidle'
            post_submit_wait_ms = int(parameters.get('postSubmitWaitMs', 1000 if login_test_mode else 2000))
            post_submit_load_timeout_ms = int(parameters.get('postSubmitLoadTimeoutMs', 3000 if login_test_mode else 15000))
            llm_timeout_seconds = int(parameters.get('llmTimeoutSeconds', 15 if login_test_mode else 75))
            initial_render_wait_ms = int(parameters.get('initialRenderWaitMs', 1000 if login_test_mode else 0))

            print(
                "[AI Login] Config: "
                f"mfaAutoFillTimeout={mfa_auto_fill_timeout}s, "
                f"mfaMaxRounds={mfa_max_rounds}, debug={debug_screenshots}, "
                f"testMode={login_test_mode}, pageLoadStrategy={page_load_strategy}, "
                f"llmTimeout={llm_timeout_seconds}s, initialRenderWait={initial_render_wait_ms}ms, "
                f"interactiveMfa={interactive_mfa}"
            )

            # Phase 6 — vendor-agnostic LLM resolution. Pull the platform LLM
            # config from /agents/config. Prefer the backend relay so the agent
            # does not receive raw provider keys.
            llm_vendor = None
            llm_model = None
            llm_api_key = None
            relay_url = None
            agent_api_key = getattr(agent, 'api_key', None)
            if agent:
                try:
                    import aiohttp
                    async with aiohttp.ClientSession(headers={'X-API-Key': agent.api_key}) as session:
                        async with session.get(f"{agent.api_url}/agents/config", timeout=aiohttp.ClientTimeout(total=10)) as resp:
                            if resp.status == 200:
                                config_data = await resp.json()
                                llm = config_data.get('llm') or {}
                                llm_vendor = llm.get('vendor')
                                llm_model = llm.get('model')
                                llm_api_key = llm.get('apiKey')
                                if config_data.get('relayUrl'):
                                    relay_url = build_backend_url(agent.api_url, config_data['relayUrl'])
                                    print(f"[AI Login] Using backend LLM relay: {relay_url}")
                                if llm_api_key:
                                    print(f"[AI Login] Using platform LLM: vendor={llm_vendor} model={llm_model}")
                except Exception as e:
                    print(f"[AI Login] Could not fetch LLM config from backend: {e}")

            use_backend_relay = bool(relay_url and agent_api_key)

            # Env-var fallback is retained only for standalone/local execution
            # when no agent relay is available.
            if not use_backend_relay and not llm_api_key:
                env_anthropic = os.getenv('ANTHROPIC_API_KEY')
                env_google = os.getenv('GOOGLE_API_KEY') or os.getenv('GEMINI_API_KEY')
                if env_anthropic:
                    llm_vendor = 'anthropic'
                    llm_api_key = env_anthropic
                    print("[AI Login] Using Anthropic API key from environment variable (legacy)")
                elif env_google:
                    llm_vendor = 'google'
                    llm_api_key = env_google
                    print("[AI Login] Using Google/Gemini API key from environment variable (legacy)")

            if not use_backend_relay and (not llm_api_key or not llm_vendor):
                raise ValueError(
                    "No LLM relay or API key available. Configure the platform LLM and "
                    "agent backend relay, or set "
                    "ANTHROPIC_API_KEY / GOOGLE_API_KEY in the agent environment."
                )

            anthropic_client = None
            if use_backend_relay:
                llm_vendor = 'backend_relay'
            elif llm_vendor == 'anthropic':
                from anthropic import Anthropic
                anthropic_client = Anthropic(api_key=llm_api_key)
            elif llm_vendor in ('google', 'gemini'):
                # No SDK needed — ask_gemini uses aiohttp + the REST endpoint.
                pass
            else:
                raise NotImplementedError(
                    f"AI Login does not yet support LLM vendor '{llm_vendor}'. "
                    "Use 'anthropic' or 'google'."
                )

            # Helper closure so the rest of the function stays vendor-agnostic.
            async def _ask(screenshot_b64: str, text_prompt: str) -> dict:
                return await ask_llm(
                    vendor=llm_vendor,
                    screenshot_b64=screenshot_b64,
                    text_prompt=text_prompt,
                    relay_url=relay_url,
                    agent_api_key=agent_api_key,
                    anthropic_client=anthropic_client,
                    gemini_api_key=llm_api_key,
                    gemini_model=llm_model,
                    llm_timeout_seconds=llm_timeout_seconds,
                )

            start_time = time.time()
            actions_count = 0
            entry_url = (
                protected_resource_url
                if protected_resource_url and interactive_mfa
                else login_url
            )
            if entry_url != login_url:
                print(
                    "[AI Login] Using protected resource as SSO entrypoint: "
                    f"{entry_url} (loginUrl fallback: {login_url})"
                )

            # Report progress
            if agent:
                agent.report_progress(
                    current_operation=f"Opening browser and navigating to: {entry_url}",
                    current_target=entry_url
                )

            # Initialize Playwright with hardened browser settings
            async with async_playwright() as p:
                browser = await p.chromium.launch(
                    headless=headless,
                    args=[
                        "--no-sandbox",
                        "--disable-dev-shm-usage",
                        "--disable-blink-features=AutomationControlled",
                    ],
                )
                context = await browser.new_context(
                    viewport=browser_viewport,
                    user_agent=browser_user_agent,
                )
                page = await context.new_page()

                try:
                    # Step 1: Navigate to login page
                    print(f"[AI Login] Step 1: Navigating to {entry_url}")
                    await page.goto(
                        entry_url,
                        wait_until=page_load_strategy,
                        timeout=timeout_seconds * 1000,
                    )
                    if initial_render_wait_ms > 0:
                        await asyncio.sleep(initial_render_wait_ms / 1000)

                    opened_login_surface = await open_login_surface_if_needed(
                        page,
                        wait_ms=max(initial_render_wait_ms, 1000),
                    )
                    if opened_login_surface and agent:
                        agent.report_progress(
                            current_operation="Opened login form from page trigger",
                            current_target=entry_url,
                        )
                    await save_debug_screenshot(page, 1, "page_loaded", debug_screenshots)

                    # Step 2: Capture screenshot + HTML for hybrid AI analysis
                    print("[AI Login] Step 2: Capturing screenshot + HTML for Claude analysis")
                    screenshot_bytes = await page.screenshot()
                    screenshot_b64 = base64.b64encode(screenshot_bytes).decode('utf-8')
                    html = await page.content()
                    form_html = extract_form_elements(html)
                    print(f"[AI Login]   Extracted {len(form_html)} chars of form-related HTML")

                    # Report progress
                    if agent:
                        agent.report_progress(
                            current_operation="AI analyzing login page structure (screenshot + HTML)",
                            current_target=login_url
                        )

                    selectors = {}
                    deterministic_form_filled = False

                    if login_test_mode:
                        print("[AI Login] Step 3: Trying deterministic login selectors before LLM")
                        username_ok = await fill_field(page, USERNAME_FALLBACK_STRATEGIES, username, "username")
                        password_ok = await fill_field(page, PASSWORD_FALLBACK_STRATEGIES, password, "password")
                        if username_ok and password_ok:
                            deterministic_form_filled = True
                            actions_count += 2
                            print("[AI Login]   Deterministic login field fill succeeded")
                        else:
                            print("[AI Login]   Deterministic login field fill incomplete; falling back to LLM")

                    # Step 3: Ask the platform LLM for multi-strategy locators
                    if not deterministic_form_filled:
                        print(f"[AI Login] Step 3: Sending to LLM ({llm_vendor}) for analysis...")
                        prompt = build_selector_prompt(form_html, login_instructions)
                        try:
                            selectors = await _ask(screenshot_b64, prompt)
                            print(f"[AI Login]   LLM returned strategies for: {list(selectors.keys())}")
                        except Exception as _ask_err:
                            # Vision-LLM locator hinting is best-effort. If the model is
                            # unavailable or returns unparseable output (common with some
                            # local/Ollama-served models that emit chain-of-thought prose),
                            # degrade gracefully to the deterministic fallback selector
                            # strategies below instead of aborting the entire login.
                            print(f"[AI Login]   LLM locator hint failed ({_ask_err}); "
                                  f"falling back to deterministic selectors")
                            selectors = {}
                        actions_count += 1

                    # Step 4: Fill username using multi-strategy
                    print("[AI Login] Step 4: Filling username")
                    if agent:
                        agent.report_progress(
                            current_operation="Filling login form with credentials",
                            current_target=login_url
                        )

                    if not deterministic_form_filled:
                        username_strategies = (selectors.get("usernameField", []) or []) + USERNAME_FALLBACK_STRATEGIES
                        ok = await fill_field(page, username_strategies, username, "username")
                        if not ok:
                            print("[AI Login] FATAL: Could not fill username field with any strategy")
                            await save_debug_screenshot(page, 4, "username_failed", debug_screenshots)
                            return {
                                'success': False,
                                'error': 'Could not fill username field - all locator strategies failed',
                                'cookies': [],
                                'storage_state': {}
                            }
                        await save_debug_screenshot(page, 4, "username_filled", debug_screenshots)
                        actions_count += 1

                    submit_strategies = (selectors.get("submitButton", []) or []) + SUBMIT_FALLBACK_STRATEGIES

                    # Step 5: Fill password using multi-strategy. SSO flows
                    # often split identity-provider login across screens:
                    # email -> continue -> Microsoft/Okta -> password -> MFA.
                    # Do not fail just because the first page has no password
                    # field; advance through a small number of "next" surfaces.
                    print("[AI Login] Step 5: Filling password")
                    if not deterministic_form_filled:
                        fast_staged_login = login_test_mode or interactive_mfa
                        password_strategies = (selectors.get("passwordField", []) or []) + PASSWORD_FALLBACK_STRATEGIES
                        ok = await fill_field(
                            page,
                            password_strategies,
                            password,
                            "password",
                            timeout_ms=1500 if fast_staged_login else 2500,
                        )
                        if not ok:
                            username_strategies = (selectors.get("usernameField", []) or []) + USERNAME_FALLBACK_STRATEGIES
                            for stage_attempt in range(3):
                                print(
                                    "[AI Login]   Password field not visible yet; "
                                    f"advancing staged SSO/login flow ({stage_attempt + 1}/3)"
                                )
                                if agent:
                                    agent.report_progress(
                                        current_operation=(
                                            "Advancing multi-step SSO/login flow before password entry"
                                        ),
                                        current_target=page.url or login_url,
                                    )

                                # Some IdPs ask for email again after the tenant
                                # login page redirects to Microsoft/Okta/Google.
                                await fill_field(
                                    page,
                                    username_strategies,
                                    username,
                                    f"username stage {stage_attempt + 1}",
                                    timeout_ms=1200,
                                )

                                advanced = await click_element(
                                    page,
                                    submit_strategies,
                                    f"continue_to_password_{stage_attempt + 1}",
                                    timeout_ms=1200,
                                )
                                if not advanced:
                                    print("[AI Login]   Could not advance staged login flow")
                                    break
                                actions_count += 1
                                await asyncio.sleep(max(post_submit_wait_ms, 0) / 1000)
                                try:
                                    await page.wait_for_load_state(
                                        page_load_strategy,
                                        timeout=post_submit_load_timeout_ms,
                                    )
                                except Exception:
                                    pass
                                await save_debug_screenshot(
                                    page,
                                    5,
                                    f"staged_login_{stage_attempt + 1}",
                                    debug_screenshots,
                                )

                                # Refresh selectors after navigation/modal
                                # changes. Try deterministic IdP selectors
                                # first so Microsoft/Okta flows do not spend
                                # a full LLM round trip on every transition.
                                password_strategies = PASSWORD_FALLBACK_STRATEGIES
                                ok = await fill_field(
                                    page,
                                    password_strategies,
                                    password,
                                    f"password stage {stage_attempt + 1}",
                                    timeout_ms=1200,
                                )
                                if ok:
                                    break

                                if fast_staged_login:
                                    # Interactive SSO tests must reach the MFA
                                    # prompt quickly. Microsoft/Okta/Google
                                    # screens are covered by deterministic
                                    # selectors, so avoid spending a full LLM
                                    # round trip on every "next" transition.
                                    continue

                                try:
                                    stage_screenshot = await page.screenshot()
                                    stage_b64 = base64.b64encode(stage_screenshot).decode("utf-8")
                                    stage_html = extract_form_elements(await page.content())
                                    stage_selectors = await _ask(
                                        stage_b64,
                                        build_selector_prompt(stage_html, login_instructions),
                                    )
                                    password_strategies = (
                                        stage_selectors.get("passwordField", []) or []
                                    ) + PASSWORD_FALLBACK_STRATEGIES
                                    submit_strategies = (
                                        stage_selectors.get("submitButton", []) or []
                                    ) + submit_strategies
                                    actions_count += 1
                                except Exception as stage_err:
                                    print(
                                        "[AI Login]   Staged selector refresh failed "
                                        f"({stage_err}); using deterministic selectors"
                                    )

                                ok = await fill_field(
                                    page,
                                    password_strategies,
                                    password,
                                    f"password stage {stage_attempt + 1}",
                                    timeout_ms=1200,
                                )
                                if ok:
                                    break

                        if not ok:
                            print("[AI Login] FATAL: Could not fill password field with any strategy")
                            await save_debug_screenshot(page, 5, "password_failed", debug_screenshots)
                            return {
                                'success': False,
                                'error': (
                                    'Could not fill password field after staged SSO/login advances - '
                                    'all locator strategies failed'
                                ),
                                'cookies': [],
                                'storage_state': {}
                            }
                        await save_debug_screenshot(page, 5, "password_filled", debug_screenshots)
                        actions_count += 1

                    # Step 6: Click submit using multi-strategy
                    print("[AI Login] Step 6: Clicking submit")
                    ok = await click_element(page, submit_strategies, "submit")
                    if not ok:
                        print("[AI Login] FATAL: Could not click submit button with any strategy")
                        await save_debug_screenshot(page, 6, "submit_failed", debug_screenshots)
                        return {
                            'success': False,
                            'error': 'Could not click submit button - all locator strategies failed',
                            'cookies': [],
                            'storage_state': {}
                        }
                    actions_count += 1

                    # Wait for navigation/response
                    await asyncio.sleep(max(post_submit_wait_ms, 0) / 1000)
                    try:
                        await page.wait_for_load_state(
                            page_load_strategy,
                            timeout=post_submit_load_timeout_ms,
                        )
                    except Exception:
                        pass
                    await save_debug_screenshot(page, 6, "post_submit", debug_screenshots)

                    # Step 7+: Multi-step MFA loop
                    mfa_round = 0
                    step_num = 7

                    while mfa_round < mfa_max_rounds:
                        mfa_round += 1
                        print(f"[AI Login] Step {step_num}: Analyzing page (MFA round {mfa_round}/{mfa_max_rounds})...")

                        if agent:
                            agent.report_progress(
                                current_operation=f"AI analyzing page (MFA round {mfa_round})",
                                current_target=login_url
                            )

                        # Capture screenshot + HTML for post-submit analysis
                        post_screenshot = await page.screenshot()
                        post_b64 = base64.b64encode(post_screenshot).decode('utf-8')
                        post_html = await page.content()
                        post_form_html = extract_form_elements(post_html)

                        post_prompt = build_post_submit_prompt(post_form_html, login_instructions)
                        try:
                            post_result = await _ask(post_b64, post_prompt)
                        except Exception as classify_error:
                            if protected_resource_url:
                                print(
                                    "[AI Login]   Post-submit page classification failed; "
                                    "deferring to protected resource validation: "
                                    f"{classify_error}"
                                )
                                break
                            raise
                        status = post_result.get("status", "unknown")
                        print(f"[AI Login]   Page classification: {status}")
                        actions_count += 1

                        if status == "success":
                            print("[AI Login]   Login appears successful!")
                            break

                        if status == "error":
                            error_msg = post_result.get("message", "Login error detected by AI")
                            print(f"[AI Login]   Login error: {error_msg}")
                            await save_debug_screenshot(page, step_num, "login_error", debug_screenshots)
                            return {
                                'success': False,
                                'error': f'Login error: {error_msg}',
                                'cookies': [],
                                'storage_state': {}
                            }

                        if status != "mfa":
                            if protected_resource_url:
                                print(
                                    f"[AI Login]   Unknown status '{status}', "
                                    "deferring to protected resource validation"
                                )
                                break
                            if login_test_mode:
                                return {
                                    'success': False,
                                    'error': (
                                        f"AI could not confirm login success (status={status}) "
                                        "and no protectedResourceUrl was configured for validation."
                                    ),
                                    'cookies': [],
                                    'storage_state': {}
                                }
                            print(f"[AI Login]   Unknown status '{status}', assuming success for non-test flow")
                            break

                        # MFA step detected
                        print(f"[AI Login]   MFA step {mfa_round} detected")
                        detected_code_strategies = post_result.get("codeField", []) or []
                        code_strategies = detected_code_strategies + OTP_FALLBACK_STRATEGIES
                        mfa_submit_strategies = (
                            post_result.get("submitButton", []) or []
                        ) + SUBMIT_FALLBACK_STRATEGIES
                        number_challenge = await extract_number_matching_challenge(page)
                        llm_number_matching_code = normalize_number_matching_code(
                            post_result.get("numberMatchingCode")
                            or post_result.get("authenticatorNumber")
                            or post_result.get("challengeCode")
                            or post_result.get("displayValue")
                        )
                        if number_challenge.get("detected") and llm_number_matching_code:
                            if not number_challenge.get("challengeCode"):
                                number_challenge["challengeCode"] = llm_number_matching_code
                                number_challenge["displayValue"] = llm_number_matching_code
                            number_challenge["challengePrompt"] = (
                                number_challenge.get("challengePrompt")
                                or f"LLM extracted authenticator number {llm_number_matching_code} from the screenshot."
                            )
                        if number_challenge.get("detected") and not number_challenge.get("challengeCode"):
                            if agent:
                                agent.report_progress(
                                    current_operation=(
                                        f"MFA step {mfa_round}: waiting for authenticator number to render"
                                    ),
                                    current_target=page.url or login_url,
                                )
                            for _ in range(2):
                                await asyncio.sleep(1)
                                refreshed_number_challenge = await extract_number_matching_challenge(page)
                                if refreshed_number_challenge.get("challengeCode"):
                                    number_challenge = refreshed_number_challenge
                                    break
                        has_otp_field = (
                            False
                            if number_challenge.get("detected")
                            else await has_visible_fillable_field(page, code_strategies, timeout_ms=800)
                        )

                        if agent:
                            if number_challenge.get("detected"):
                                mfa_operation = "Waiting for operator to enter authenticator number"
                            elif has_otp_field:
                                mfa_operation = "Waiting for operator/auto-filled OTP"
                            else:
                                mfa_operation = "Waiting for push/method confirmation"
                            agent.report_progress(
                                current_operation=(
                                    f"MFA step {mfa_round}: {mfa_operation}"
                                ),
                                current_target=login_url
                            )

                        # Number matching is a push-style challenge where the
                        # operator types the browser number into Authenticator.
                        number_matching_approved = False
                        if number_challenge.get("detected"):
                            challenge_code = number_challenge.get("challengeCode")
                            print(
                                "[AI Login]   Number matching MFA detected"
                                + (f" (challenge: {challenge_code})" if challenge_code else "")
                            )
                            if interactive_mfa:
                                request_id = f"{job_id or 'local'}-mfa-{mfa_round}-number"
                                await request_operator_input(
                                    agent,
                                    job_id,
                                    request_id,
                                    kind="number_matching",
                                    label=f"Authenticator number required (round {mfa_round})",
                                    prompt=(
                                        "Enter the number shown here in your authenticator app, "
                                        "approve the sign-in request, then confirm below."
                                    ),
                                    helper_text=(
                                        "This is not an OTP to type into xASM. Type the displayed number "
                                        "in Microsoft Authenticator or the SSO app."
                                    ),
                                    current_target=page.url or login_url,
                                    expires_in_seconds=mfa_auto_fill_timeout,
                                    mfa_round=mfa_round,
                                    challenge_code=challenge_code,
                                    display_value=number_challenge.get("displayValue"),
                                    challenge_prompt=number_challenge.get("challengePrompt"),
                                )
                                for elapsed in range(mfa_auto_fill_timeout):
                                    operator_response = await consume_operator_input(
                                        agent,
                                        job_id,
                                        request_id,
                                    )
                                    if operator_response:
                                        print(
                                            f"[AI Login]   Operator confirmed number matching after {elapsed+1}s"
                                        )
                                        number_matching_approved = True
                                        break
                                    if elapsed % 10 == 9:
                                        print(
                                            f"[AI Login]   Still waiting for number matching approval... ({elapsed+1}s)"
                                        )
                                    await asyncio.sleep(1)
                                if not number_matching_approved:
                                    return {
                                        'success': False,
                                        'error': (
                                            f'Number matching MFA was not approved within '
                                            f'{mfa_auto_fill_timeout} seconds'
                                        ),
                                        'cookies': [],
                                        'storage_state': {},
                                    }

                        # If there's an OTP code field, poll while the operator
                        # enters the code in the live browser or the IdP auto-fills it.
                        elif has_otp_field:
                            print(f"[AI Login]   Waiting for OTP/operator entry (up to {mfa_auto_fill_timeout}s)...")
                            otp_filled = False
                            request_id = f"{job_id or 'local'}-mfa-{mfa_round}"
                            if interactive_mfa:
                                await request_operator_input(
                                    agent,
                                    job_id,
                                    request_id,
                                    kind="otp",
                                    label=f"MFA code required (round {mfa_round})",
                                    prompt=(
                                        "Enter the one-time verification code shown by the identity provider. "
                                        "The agent will fill it into the remote browser and continue."
                                    ),
                                    helper_text="Use this for SMS, email, authenticator app, or any OTP-style challenge.",
                                    current_target=page.url or login_url,
                                    expires_in_seconds=mfa_auto_fill_timeout,
                                    mfa_round=mfa_round,
                                )
                            for elapsed in range(mfa_auto_fill_timeout):
                                if interactive_mfa and elapsed % 2 == 0:
                                    operator_response = await consume_operator_input(
                                        agent,
                                        job_id,
                                        request_id,
                                    )
                                    operator_code = (
                                        operator_response.get("value", "").strip()
                                        if operator_response
                                        else ""
                                    )
                                    if operator_code:
                                        print(
                                            f"[AI Login]   Operator OTP received after {elapsed+1}s "
                                            f"(value length: {len(operator_code)})"
                                        )
                                        if agent:
                                            agent.report_progress(
                                                current_operation="Operator MFA code received; filling verification field",
                                                current_target=page.url or login_url,
                                            )
                                        otp_filled = await fill_field(
                                            page,
                                            code_strategies,
                                            operator_code,
                                            "operator OTP",
                                            timeout_ms=1500,
                                        )
                                        if otp_filled:
                                            break

                                for strat in code_strategies:
                                    try:
                                        if strat.get("type") == "css":
                                            val = await page.evaluate(
                                                f'document.querySelector("{strat["selector"]}")?.value || ""'
                                            )
                                        else:
                                            if strat.get("type") == "role":
                                                loc = page.get_by_role(strat["role"], name=strat.get("name"))
                                            elif strat.get("type") == "label":
                                                loc = page.get_by_label(strat["label"])
                                            elif strat.get("type") == "placeholder":
                                                loc = page.get_by_placeholder(strat["placeholder"])
                                            else:
                                                continue
                                            val = await loc.input_value(timeout=2000)

                                        if val and val.strip():
                                            print(f"[AI Login]   OTP detected after {elapsed+1}s (value length: {len(val.strip())})")
                                            otp_filled = True
                                            break
                                    except Exception:
                                        continue
                                if otp_filled:
                                    break
                                if elapsed % 10 == 9:
                                    print(f"[AI Login]   Still waiting for OTP/operator action... ({elapsed+1}s)")
                                await asyncio.sleep(1)

                            if not otp_filled:
                                print(f"[AI Login]   WARNING: OTP was not provided after {mfa_auto_fill_timeout}s")
                        else:
                            print("[AI Login]   No OTP code field (method selection, WebAuthn, or push confirmation page)")
                            if interactive_mfa:
                                request_id = f"{job_id or 'local'}-mfa-{mfa_round}-action"
                                await request_operator_input(
                                    agent,
                                    job_id,
                                    request_id,
                                    kind="push_or_webauthn",
                                    label=f"Approve MFA challenge (round {mfa_round})",
                                    prompt=(
                                        "Approve the push/WebAuthn/SSO challenge in the identity provider, "
                                        "then confirm in the modal so the agent can continue."
                                    ),
                                    helper_text="Use this when there is no OTP field, such as Microsoft Authenticator push or passkey prompts.",
                                    current_target=page.url or login_url,
                                    expires_in_seconds=mfa_auto_fill_timeout,
                                    mfa_round=mfa_round,
                                )
                                for elapsed in range(mfa_auto_fill_timeout):
                                    operator_response = await consume_operator_input(
                                        agent,
                                        job_id,
                                        request_id,
                                    )
                                    if operator_response:
                                        print(
                                            f"[AI Login]   Operator confirmed MFA action after {elapsed+1}s"
                                        )
                                        break
                                    if elapsed % 10 == 9:
                                        print(
                                            f"[AI Login]   Still waiting for operator MFA confirmation... ({elapsed+1}s)"
                                        )
                                    await asyncio.sleep(1)

                        await save_debug_screenshot(page, step_num, f"mfa_round{mfa_round}_before_submit", debug_screenshots)

                        if number_matching_approved:
                            if agent:
                                agent.report_progress(
                                    current_operation="Number matching approved; waiting for identity provider to continue",
                                    current_target=page.url or login_url,
                                )
                            await asyncio.sleep(3)
                            try:
                                await page.wait_for_load_state(
                                    page_load_strategy,
                                    timeout=post_submit_load_timeout_ms,
                                )
                            except Exception:
                                pass
                            await save_debug_screenshot(page, step_num, f"mfa_round{mfa_round}_number_matching_approved", debug_screenshots)
                            if protected_resource_url:
                                print(
                                    "[AI Login]   Number matching approved, deferring to protected resource validation"
                                )
                                break
                            print(f"[AI Login]   Number matching approved, re-analyzing...")
                            step_num += 1
                            continue

                        # Click the MFA submit/continue button
                        print(f"[AI Login]   Clicking MFA submit/continue (round {mfa_round})")
                        ok = await click_element(
                            page,
                            mfa_submit_strategies,
                            "mfa_submit",
                            timeout_ms=1500,
                        )
                        if not ok:
                            print("[AI Login]   WARNING: Could not click MFA submit button")
                            await save_debug_screenshot(page, step_num, f"mfa_round{mfa_round}_submit_failed", debug_screenshots)
                            if has_otp_field:
                                break
                        else:
                            actions_count += 1

                        await asyncio.sleep(max(post_submit_wait_ms, 0) / 1000)
                        try:
                            await page.wait_for_load_state(
                                page_load_strategy,
                                timeout=post_submit_load_timeout_ms,
                            )
                        except Exception:
                            pass
                        await save_debug_screenshot(page, step_num, f"mfa_round{mfa_round}_submitted", debug_screenshots)
                        print(f"[AI Login]   MFA round {mfa_round} submitted, re-analyzing...")
                        step_num += 1

                    protected_validation = await validate_protected_resource_session(
                        page,
                        protected_resource_url,
                        login_url=login_url,
                        page_load_strategy=page_load_strategy,
                        timeout_ms=max(post_submit_load_timeout_ms, 10000),
                        settle_ms=max(initial_render_wait_ms, 1000),
                        agent=agent,
                    )
                    if not protected_validation.get("valid"):
                        error = protected_validation.get("reason") or "protected resource validation failed"
                        print(f"[AI Login] Protected resource validation FAILED: {error}")
                        return {
                            'success': False,
                            'error': error,
                            'protected_resource_validation': protected_validation,
                            'cookies': [],
                            'storage_state': {}
                        }

                    # Extract cookies and storage state
                    execution_time = time.time() - start_time
                    cookies = await context.cookies()
                    storage_state = await context.storage_state()
                    await save_debug_screenshot(page, step_num + 1, "final_state", debug_screenshots)

                    print(f"[AI Login] Login completed in {execution_time:.1f}s with {actions_count} AI actions")
                    print(f"[AI Login] Cookies extracted: {len(cookies)}")
                    print(f"[AI Login] Cookie names: {[c['name'] for c in cookies]}")

                    return {
                        'success': True,
                        'cookies': cookies,
                        'storage_state': storage_state,
                        'execution_time': execution_time,
                        'actions_count': actions_count,
                        'protected_resource_validation': protected_validation,
                    }

                finally:
                    await browser.close()

        except Exception as e:
            import traceback
            error_details = f"{str(e)}\n{traceback.format_exc()}"
            return {
                'success': False,
                'error': error_details,
                'cookies': [],
                'storage_state': {}
            }

    def _generate_artifacts(
        self,
        cookies: list,
        storage_state: dict
    ) -> Dict[str, str]:
        """Generate output files for Katana and Nuclei"""
        # Generate unique output paths based on timestamp
        timestamp = int(time.time())
        headers_file = f'/tmp/ai_login_headers_{timestamp}.txt'
        cookies_file = f'/tmp/ai_login_cookies_{timestamp}.json'
        secrets_file = f'/tmp/ai_login_secrets_{timestamp}.yaml'

        # Ensure directories exist
        for file_path in [headers_file, cookies_file, secrets_file]:
            Path(file_path).parent.mkdir(parents=True, exist_ok=True)

        # Generate headers.txt for Katana (single Cookie header with all cookies)
        cookie_values = '; '.join(f"{cookie['name']}={cookie['value']}" for cookie in cookies)
        headers_content = f"Cookie: {cookie_values}" if cookies else ""

        with open(headers_file, 'w') as f:
            f.write(headers_content)

        # Generate secrets.yaml for Nuclei
        unique_domains = list(set(c.get('domain', '') for c in cookies if c.get('domain')))
        secrets = {
            'static': [
                {
                    'type': 'cookie',
                    'domains': unique_domains,
                    'cookies': [
                        {'key': c['name'], 'value': c['value']}
                        for c in cookies
                    ]
                }
            ]
        }

        with open(secrets_file, 'w') as f:
            yaml.dump(secrets, f)

        # Save cookies JSON for reference
        with open(cookies_file, 'w') as f:
            json.dump(cookies, f, indent=2)

        return {
            'headers_file': headers_file,
            'cookies_file': cookies_file,
            'secrets_file': secrets_file
        }


def get_tool():
    return BrowserLoginAiTool()
