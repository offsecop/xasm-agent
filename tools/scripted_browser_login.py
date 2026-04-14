"""
Scripted Browser Login Tool (Phase 2)

Automated browser login using Playwright with explicit CSS selectors.
- Cost: $0 (no LLM usage)
- Speed: 5-10 seconds
- Use case: Known login forms with stable selectors
"""

import os
import json
import yaml
import time
from typing import Dict, Any, List
from plugin_interface import ToolPlugin

try:
    from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeout, Error as PlaywrightError
except ImportError:
    print("[Warning] playwright not installed. Install with: pip install playwright")
    sync_playwright = None
    PlaywrightTimeout = Exception
    PlaywrightError = Exception


class ScriptedBrowserLoginTool(ToolPlugin):
    """
    Automated browser login using Playwright with explicit CSS selectors.
    """

    @property
    def name(self) -> str:
        return "authentication:scripted_login"

    @property
    def description(self) -> str:
        return "Authentication - Scripted Login: Automate browser login with explicit CSS selectors ($0 cost, 5-10s)"

    @property
    def schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "loginUrl": {
                    "type": "string",
                    "description": "URL of the login page"
                },
                "username": {
                    "type": "string",
                    "description": "Username for login"
                },
                "password": {
                    "type": "string",
                    "description": "Password for login"
                },
                "selectors": {
                    "type": "object",
                    "properties": {
                        "usernameField": {
                            "type": "string",
                            "description": "CSS selector for username input field"
                        },
                        "passwordField": {
                            "type": "string",
                            "description": "CSS selector for password input field"
                        },
                        "submitButton": {
                            "type": "string",
                            "description": "CSS selector for submit button"
                        },
                        "successIndicator": {
                            "type": "string",
                            "description": "CSS selector for element that appears after successful login (optional)"
                        }
                    },
                    "required": ["usernameField", "passwordField", "submitButton"]
                },
                "timeoutMs": {
                    "type": "integer",
                    "description": "Timeout in milliseconds",
                    "default": 10000
                },
                "headless": {
                    "type": "boolean",
                    "description": "Run browser in headless mode",
                    "default": True
                },
                "executionId": {
                    "type": "string",
                    "description": "Unique execution ID for output files"
                }
            },
            "required": ["loginUrl", "username", "password", "selectors"]
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
        """Execute scripted browser login (async wrapper for sync Playwright)"""
        # Playwright sync API - run in thread
        import asyncio
        from concurrent.futures import ThreadPoolExecutor

        with ThreadPoolExecutor() as executor:
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(
                executor, self._execute_sync, parameters
            )

    def _execute_sync(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Execute scripted browser login (sync implementation)"""
        start_time = time.time()

        print(f"[Scripted Login] Starting browser automation")
        print(f"[Scripted Login] Parameters received: [REDACTED - {len(params)} parameters]")

        try:
            # Check if playwright is available
            if sync_playwright is None:
                return {
                    'success': False,
                    'error': 'playwright library not installed',
                    'login_method': 'scripted',
                }

            # Extract required parameters
            login_url = params.get('loginUrl')
            username = params.get('username')
            password = params.get('password')
            selectors = params.get('selectors', {})
            timeout_ms = params.get('timeoutMs', 10000)
            headless = params.get('headless', True)

            # Validate required fields
            if not login_url:
                return {
                    'success': False,
                    'error': 'loginUrl is required',
                    'login_method': 'scripted',
                }

            if not username or not password:
                return {
                    'success': False,
                    'error': 'username and password are required',
                    'login_method': 'scripted',
                }

            if not selectors or not selectors.get('usernameField') or not selectors.get('passwordField') or not selectors.get('submitButton'):
                return {
                    'success': False,
                    'error': 'selectors.usernameField, selectors.passwordField, and selectors.submitButton are required',
                    'login_method': 'scripted',
                }

            print(f"[Scripted Login] Login URL: {login_url}")
            print(f"[Scripted Login] Username: ***REDACTED***")
            print(f"[Scripted Login] Selectors: {selectors}")

            # Output file paths (use temp directory with unique ID from parameters if provided)
            execution_id = params.get('executionId', 'default')
            headers_file = f"/tmp/session_headers_{execution_id}.txt"
            cookies_file = f"/tmp/session_cookies_{execution_id}.json"
            secrets_file = f"/tmp/session_secrets_{execution_id}.yaml"

            # Launch Playwright browser
            with sync_playwright() as p:
                print(f"[Scripted Login] Launching browser (headless={headless})")
                browser = p.chromium.launch(headless=headless)
                context = browser.new_context()
                page = context.new_page()

                try:
                    # Step 1: Navigate to login page
                    print(f"[Scripted Login] Navigating to {login_url}")
                    page.goto(login_url, timeout=timeout_ms, wait_until='networkidle')
                    print(f"[Scripted Login] Page loaded successfully")

                    # Step 2: Fill username
                    username_selector = selectors['usernameField']
                    print(f"[Scripted Login] Filling username field: {username_selector}")
                    page.wait_for_selector(username_selector, timeout=timeout_ms)
                    page.fill(username_selector, username)
                    print(f"[Scripted Login] Username filled: ***REDACTED***")

                    # Step 3: Fill password
                    password_selector = selectors['passwordField']
                    print(f"[Scripted Login] Filling password field: {password_selector}")
                    page.wait_for_selector(password_selector, timeout=timeout_ms)
                    page.fill(password_selector, password)
                    print(f"[Scripted Login] Password filled: ***REDACTED***")

                    # Step 4: Click submit button
                    submit_selector = selectors['submitButton']
                    print(f"[Scripted Login] Clicking submit: {submit_selector}")
                    page.wait_for_selector(submit_selector, timeout=timeout_ms)
                    page.click(submit_selector)
                    print(f"[Scripted Login] Submit button clicked")

                    # Step 5: Wait for navigation/success indicator
                    success_indicator = selectors.get('successIndicator')
                    if success_indicator:
                        print(f"[Scripted Login] Waiting for success indicator: {success_indicator}")
                        page.wait_for_selector(success_indicator, timeout=timeout_ms)
                        print(f"[Scripted Login] Success indicator found")
                    else:
                        # Wait for network idle as fallback
                        print(f"[Scripted Login] No success indicator, waiting for navigation to complete")
                        page.wait_for_load_state('networkidle', timeout=timeout_ms)
                        print(f"[Scripted Login] Navigation completed")

                    # Step 6: Extract cookies
                    cookies = context.cookies()
                    print(f"[Scripted Login] Extracted {len(cookies)} cookies")

                    # Step 7: Extract localStorage (if needed)
                    try:
                        local_storage = page.evaluate("() => Object.entries(localStorage)")
                        print(f"[Scripted Login] Extracted {len(local_storage)} localStorage items")
                    except Exception as e:
                        print(f"[Scripted Login] Could not extract localStorage: {e}")
                        local_storage = []

                    # Step 8: Generate auth artifacts
                    self._generate_headers_file(cookies, headers_file)
                    self._generate_cookies_file(cookies, cookies_file)
                    self._generate_secrets_file(cookies, secrets_file, login_url)

                    execution_time = time.time() - start_time

                    # Format cookies as string for inline passing (no file sharing needed)
                    cookies_string = "; ".join([f"{c['name']}={c['value']}" for c in cookies])

                    print(f"[Scripted Login] ✅ Login successful! (execution time: {execution_time:.2f}s)")

                    return {
                        'success': True,
                        'headers_file': headers_file,
                        'cookies_file': cookies_file,
                        'secrets_file': secrets_file,
                        'cookies_count': len(cookies),
                        'cookies': cookies_string,  # Phase 2: Inline cookies for cross-agent workflows
                        'login_method': 'scripted',
                        'execution_time_seconds': execution_time,
                    }

                except PlaywrightTimeout as e:
                    print(f"[Scripted Login] ❌ Timeout error: {e}")
                    return {
                        'success': False,
                        'error': f'Timeout: {str(e)}',
                        'login_method': 'scripted',
                        'execution_time_seconds': time.time() - start_time,
                    }
                except PlaywrightError as e:
                    print(f"[Scripted Login] ❌ Playwright error: {e}")
                    return {
                        'success': False,
                        'error': f'Playwright error: {str(e)}',
                        'login_method': 'scripted',
                        'execution_time_seconds': time.time() - start_time,
                    }
                finally:
                    browser.close()
                    print(f"[Scripted Login] Browser closed")

        except Exception as e:
            print(f"[Scripted Login] ❌ Unexpected error: {e}")
            import traceback
            traceback.print_exc()
            return {
                'success': False,
                'error': str(e),
                'login_method': 'scripted',
                'execution_time_seconds': time.time() - start_time,
            }

    def _generate_headers_file(self, cookies: List[Dict], file_path: str):
        """Generate headers file with Cookie header for tools like Katana"""
        cookie_header = "; ".join([f"{c['name']}={c['value']}" for c in cookies])
        with open(file_path, 'w') as f:
            f.write(f"Cookie: {cookie_header}\n")
        print(f"[Scripted Login] Generated headers file: {file_path}")

    def _generate_cookies_file(self, cookies: List[Dict], file_path: str):
        """Generate cookies JSON file for reference"""
        with open(file_path, 'w') as f:
            json.dump(cookies, f, indent=2)
        print(f"[Scripted Login] Generated cookies file: {file_path}")

    def _generate_secrets_file(self, cookies: List[Dict], file_path: str, login_url: str):
        """Generate secrets YAML file (nuclei format)"""
        # Extract domain from login URL for nuclei secrets
        from urllib.parse import urlparse
        parsed = urlparse(login_url)
        domain = parsed.netloc

        secrets = {
            "static": [
                {
                    "type": "cookie",
                    "domains": [domain] if domain else [],
                    "cookies": [
                        {"key": c['name'], "value": c['value']}
                        for c in cookies
                    ]
                }
            ]
        }
        with open(file_path, 'w') as f:
            yaml.dump(secrets, f)
        print(f"[Scripted Login] Generated secrets file: {file_path}")


def get_tool():
    return ScriptedBrowserLoginTool()
