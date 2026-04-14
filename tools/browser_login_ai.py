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
from plugin_interface import ToolPlugin


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

async def fill_field(page, strategies: list, value: str, field_name: str) -> bool:
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

            await locator.wait_for(state="visible", timeout=5000)
            await locator.click()
            await locator.fill(value)
            print(f"[AI Login]   {field_name}: filled via '{stype}' strategy (attempt {i+1})")
            return True
        except Exception as exc:
            print(f"[AI Login]   {field_name}: strategy '{stype}' failed - {exc.__class__.__name__}")
            continue

    return False


async def click_element(page, strategies: list, element_name: str) -> bool:
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

            await locator.wait_for(state="visible", timeout=5000)
            await locator.click()
            print(f"[AI Login]   {element_name}: clicked via '{stype}' strategy (attempt {i+1})")
            return True
        except Exception as exc:
            print(f"[AI Login]   {element_name}: strategy '{stype}' failed - {exc.__class__.__name__}")
            continue

    return False


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

Respond ONLY with valid JSON (no markdown fences):
For success: {{"status":"success"}}
For MFA:     {{"status":"mfa","codeField":[{{"type":"css","selector":"#otp"}}],"submitButton":[{{"type":"role","role":"button","name":"Verify"}}]}}
For MFA without code field (method selection): {{"status":"mfa","codeField":[],"submitButton":[{{"type":"role","role":"button","name":"Continue"}}]}}
For error:   {{"status":"error","message":"description"}}"""


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
    # Find the first '{' and match brackets to extract the JSON object
    start = raw.find('{')
    if start == -1:
        raise ValueError(f"Claude did not return valid JSON.\nRaw response:\n{raw}")
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
        raise ValueError(f"Claude did not return valid JSON.\nRaw response:\n{raw}")
    return json.loads(json_str)


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

            # Generate output artifacts with default paths
            artifacts = self._generate_artifacts(
                cookies=login_result['cookies'],
                storage_state=login_result.get('storage_state', {})
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
            cookies_string = '; '.join([f"{c['name']}={c['value']}" for c in login_result['cookies']])

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
                    for c in login_result['cookies']
                ],
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
            from anthropic import Anthropic

            # Read AI config parameters (injected from aiConfig)
            mfa_auto_fill_timeout = parameters.get('mfaAutoFillTimeout', 60)
            mfa_max_rounds = parameters.get('mfaMaxRounds', 5)
            browser_user_agent = parameters.get('browserUserAgent',
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            )
            browser_viewport = parameters.get('browserViewport', {"width": 1280, "height": 900})
            debug_screenshots = parameters.get('debugScreenshots', False)

            print(f"[AI Login] Config: mfaAutoFillTimeout={mfa_auto_fill_timeout}s, mfaMaxRounds={mfa_max_rounds}, debug={debug_screenshots}")

            # Get Anthropic API key — prefer DB-stored key (via agent config endpoint), fall back to env var
            anthropic_api_key = None
            if agent:
                try:
                    import aiohttp
                    async with aiohttp.ClientSession(headers={'X-API-Key': agent.api_key}) as session:
                        async with session.get(f"{agent.api_url}/agents/config", timeout=aiohttp.ClientTimeout(total=10)) as resp:
                            if resp.status == 200:
                                config_data = await resp.json()
                                llm = config_data.get('llm')
                                if llm and llm.get('vendor') == 'anthropic' and llm.get('apiKey'):
                                    anthropic_api_key = llm['apiKey']
                                    print("[AI Login] Using Anthropic API key from platform LLM configuration")
                                elif llm and llm.get('apiKey'):
                                    # Non-Anthropic vendor configured — can still try if it's the only key available
                                    print(f"[AI Login] LLM vendor is '{llm.get('vendor')}', not anthropic — checking env fallback")
                except Exception as e:
                    print(f"[AI Login] Could not fetch LLM config from backend: {e}")

            if not anthropic_api_key:
                anthropic_api_key = os.getenv('ANTHROPIC_API_KEY')
                if anthropic_api_key:
                    print("[AI Login] Using Anthropic API key from environment variable (legacy)")

            if not anthropic_api_key:
                raise ValueError("No Anthropic API key available. Configure LLM in Administration > Integrations, or set ANTHROPIC_API_KEY environment variable.")

            client = Anthropic(api_key=anthropic_api_key)
            start_time = time.time()
            actions_count = 0

            # Report progress
            if agent:
                agent.report_progress(
                    current_operation=f"Opening browser and navigating to: {login_url}",
                    current_target=login_url
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
                    print(f"[AI Login] Step 1: Navigating to {login_url}")
                    await page.goto(login_url, wait_until='networkidle', timeout=timeout_seconds * 1000)
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

                    # Step 3: Ask Claude for multi-strategy locators
                    print("[AI Login] Step 3: Sending to Claude for analysis...")
                    prompt = build_selector_prompt(form_html, login_instructions)
                    selectors = await ask_claude(client, screenshot_b64, prompt)
                    print(f"[AI Login]   Claude returned strategies for: {list(selectors.keys())}")
                    actions_count += 1

                    # Step 4: Fill username using multi-strategy
                    print("[AI Login] Step 4: Filling username")
                    if agent:
                        agent.report_progress(
                            current_operation="Filling login form with credentials",
                            current_target=login_url
                        )

                    ok = await fill_field(page, selectors.get("usernameField", []), username, "username")
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

                    # Step 5: Fill password using multi-strategy
                    print("[AI Login] Step 5: Filling password")
                    ok = await fill_field(page, selectors.get("passwordField", []), password, "password")
                    if not ok:
                        print("[AI Login] FATAL: Could not fill password field with any strategy")
                        await save_debug_screenshot(page, 5, "password_failed", debug_screenshots)
                        return {
                            'success': False,
                            'error': 'Could not fill password field - all locator strategies failed',
                            'cookies': [],
                            'storage_state': {}
                        }
                    await save_debug_screenshot(page, 5, "password_filled", debug_screenshots)
                    actions_count += 1

                    # Step 6: Click submit using multi-strategy
                    print("[AI Login] Step 6: Clicking submit")
                    ok = await click_element(page, selectors.get("submitButton", []), "submit")
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
                    await asyncio.sleep(2)
                    try:
                        await page.wait_for_load_state('networkidle', timeout=15000)
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
                        post_result = await ask_claude(client, post_b64, post_prompt)
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
                            print(f"[AI Login]   Unknown status '{status}', assuming success")
                            break

                        # MFA step detected
                        print(f"[AI Login]   MFA step {mfa_round} detected")
                        code_strategies = post_result.get("codeField", [])
                        mfa_submit_strategies = post_result.get("submitButton", [])

                        if agent:
                            agent.report_progress(
                                current_operation=f"MFA step {mfa_round}: {'Waiting for OTP auto-fill' if code_strategies else 'Method selection/confirmation'}",
                                current_target=login_url
                            )

                        # If there's an OTP code field, poll for auto-fill
                        if code_strategies:
                            print(f"[AI Login]   Waiting for OTP auto-fill (up to {mfa_auto_fill_timeout}s)...")
                            otp_filled = False
                            for elapsed in range(mfa_auto_fill_timeout):
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
                                            print(f"[AI Login]   OTP auto-filled after {elapsed+1}s (value length: {len(val.strip())})")
                                            otp_filled = True
                                            break
                                    except Exception:
                                        continue
                                if otp_filled:
                                    break
                                if elapsed % 10 == 9:
                                    print(f"[AI Login]   Still waiting for OTP... ({elapsed+1}s)")
                                await asyncio.sleep(1)

                            if not otp_filled:
                                print(f"[AI Login]   WARNING: OTP not auto-filled after {mfa_auto_fill_timeout}s")
                        else:
                            print("[AI Login]   No OTP code field (method selection or confirmation page)")

                        await save_debug_screenshot(page, step_num, f"mfa_round{mfa_round}_before_submit", debug_screenshots)

                        # Click the MFA submit/continue button
                        print(f"[AI Login]   Clicking MFA submit/continue (round {mfa_round})")
                        ok = await click_element(page, mfa_submit_strategies, "mfa_submit")
                        if not ok:
                            print("[AI Login]   WARNING: Could not click MFA submit button")
                            await save_debug_screenshot(page, step_num, f"mfa_round{mfa_round}_submit_failed", debug_screenshots)
                            break
                        actions_count += 1

                        await asyncio.sleep(2)
                        try:
                            await page.wait_for_load_state('networkidle', timeout=15000)
                        except Exception:
                            pass
                        await save_debug_screenshot(page, step_num, f"mfa_round{mfa_round}_submitted", debug_screenshots)
                        print(f"[AI Login]   MFA round {mfa_round} submitted, re-analyzing...")
                        step_num += 1

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
