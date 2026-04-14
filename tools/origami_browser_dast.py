"""
Origami Browser DAST Tool
Headless browser security analysis using the Origami Chrome extension.
Launches Chrome with Origami loaded, navigates to targets, and extracts
security findings via the Origami MCP server bridge (JSON-RPC 2.0 over stdio).

Architecture:
  Python Agent -> subprocess stdin/stdout (MCP) -> Node.js MCP Server -> WebSocket :9340 -> Chrome Extension
"""

import asyncio
import fnmatch
import json
import os
import time
import traceback
from urllib.parse import urlparse
from typing import Dict, Any, Optional
from plugin_interface import ToolPlugin


# CWE mapping for Origami finding categories
CWE_MAP = {
    'xss': {'id': 'CWE-79', 'name': 'Cross-site Scripting'},
    'dom-xss': {'id': 'CWE-79', 'name': 'Cross-site Scripting (DOM-based)'},
    'csrf': {'id': 'CWE-352', 'name': 'Cross-Site Request Forgery'},
    'missing-csp': {'id': 'CWE-1021', 'name': 'Missing Content Security Policy'},
    'csp-issues': {'id': 'CWE-1021', 'name': 'Content Security Policy Issues'},
    'missing-hsts': {'id': 'CWE-523', 'name': 'Missing HTTP Strict Transport Security'},
    'missing-x-frame-options': {'id': 'CWE-1021', 'name': 'Missing X-Frame-Options'},
    'missing-x-content-type-options': {'id': 'CWE-16', 'name': 'Missing X-Content-Type-Options'},
    'cookie-no-httponly': {'id': 'CWE-1004', 'name': 'Cookie Without HttpOnly Flag'},
    'cookie-no-secure': {'id': 'CWE-614', 'name': 'Cookie Without Secure Flag'},
    'cookie-no-samesite': {'id': 'CWE-1275', 'name': 'Cookie Without SameSite Flag'},
    'cors-misconfiguration': {'id': 'CWE-942', 'name': 'CORS Misconfiguration'},
    'mixed-content': {'id': 'CWE-319', 'name': 'Mixed Content (HTTP in HTTPS)'},
    'exposed-secrets': {'id': 'CWE-798', 'name': 'Hardcoded Credentials/Secrets'},
    'insecure-form': {'id': 'CWE-319', 'name': 'Insecure Form Submission'},
    'outdated-library': {'id': 'CWE-1104', 'name': 'Use of Unmaintained Component'},
    'sri-missing': {'id': 'CWE-353', 'name': 'Missing Subresource Integrity'},
    'prototype-pollution': {'id': 'CWE-1321', 'name': 'Prototype Pollution'},
    'open-redirect': {'id': 'CWE-601', 'name': 'Open Redirect'},
    'graphql-introspection': {'id': 'CWE-200', 'name': 'GraphQL Introspection Enabled'},
    'websocket-insecure': {'id': 'CWE-319', 'name': 'Insecure WebSocket'},
    'jwt-issues': {'id': 'CWE-347', 'name': 'JWT Verification Issues'},
    'cloud-storage-exposure': {'id': 'CWE-200', 'name': 'Cloud Storage Exposure'},
    'session-issues': {'id': 'CWE-613', 'name': 'Session Management Issues'},
    'crypto-issues': {'id': 'CWE-327', 'name': 'Broken Cryptographic Algorithm'},
    'permissions-policy': {'id': 'CWE-16', 'name': 'Missing Permissions Policy'},
}

# Default MCP category → platform category mapping (refined per-finding when possible)
MCP_CATEGORY_MAP = {
    'secrets': 'exposed-secrets',
    'headers': 'missing-csp',
    'cookies': 'cookie-no-httponly',
    'vulnerabilities': 'xss',
    'sensitiveFiles': 'exposed-secrets',
    'sessionState': 'session-issues',
    'technologies': 'outdated-library',
    'correlationChains': 'xss',
    'oauthFlows': 'csrf',
    'graphql': 'graphql-introspection',
    'crypto': 'crypto-issues',
    'cloudStorage': 'cloud-storage-exposure',
    'exfiltration': 'exposed-secrets',
    'websockets': 'websocket-insecure',
}

# All MCP finding categories to query
MCP_CATEGORIES = [
    'secrets', 'headers', 'cookies', 'vulnerabilities',
    'sensitiveFiles', 'sessionState', 'technologies',
    'correlationChains', 'oauthFlows', 'graphql',
    'crypto', 'cloudStorage', 'exfiltration', 'websockets',
]


class OrigamiMCPClient:
    """Lightweight MCP client for Origami security scanner via JSON-RPC 2.0 over subprocess stdio."""

    MCP_SERVER_PATH = os.environ.get('ORIGAMI_MCP_SERVER_PATH', '/opt/origami/mcp-server/index.js')
    WS_TOKEN = 'xasm-origami-bridge-token'

    def __init__(self):
        self.process = None
        self._request_id = 0
        self._connected = False
        self._stderr_task = None

    async def start(self, timeout=15):
        """Start MCP server subprocess and perform initialize handshake."""
        try:
            if not os.path.exists(self.MCP_SERVER_PATH):
                print(f"[Origami MCP] MCP server not found at {self.MCP_SERVER_PATH}")
                return False

            env = os.environ.copy()
            env['ORIGAMI_WS_TOKEN'] = self.WS_TOKEN

            self.process = await asyncio.create_subprocess_exec(
                'node', self.MCP_SERVER_PATH,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )

            # Drain stderr in background to prevent pipe buffer overflow
            self._stderr_task = asyncio.create_task(self._drain_stderr())

            # Give the server time to start (binds WebSocket server on :9340)
            await asyncio.sleep(1)

            # MCP initialize handshake
            result = await self._send_request('initialize', {
                'protocolVersion': '2024-11-05',
                'capabilities': {},
                'clientInfo': {'name': 'xasm-origami-dast', 'version': '1.0.0'},
            }, timeout=timeout)

            if result is not None:
                await self._send_notification('notifications/initialized')
                self._connected = True
                proto = result.get('protocolVersion', 'unknown')
                print(f"[Origami MCP] Server started successfully (protocol: {proto})")
                return True

            print("[Origami MCP] Failed to initialize MCP server (no response)")
            return False

        except Exception as e:
            print(f"[Origami MCP] Failed to start MCP server: {e}")
            traceback.print_exc()
            return False

    async def call_tool(self, name, arguments=None, timeout=60):
        """Call an MCP tool and return the parsed result."""
        if not self._connected or not self.process:
            return None

        result = await self._send_request('tools/call', {
            'name': name,
            'arguments': arguments or {},
        }, timeout=timeout)

        if result is None:
            return None

        # Check for MCP-level error
        if result.get('isError'):
            content = result.get('content', [])
            error_text = ' '.join(c.get('text', '') for c in content if c.get('type') == 'text')
            print(f"[Origami MCP] Tool error ({name}): {error_text}")
            return None

        # Extract text content from MCP response
        content = result.get('content', [])
        texts = [c.get('text', '') for c in content if c.get('type') == 'text']
        combined = '\n'.join(texts)

        if not combined:
            return None

        # Try to parse as JSON (MCP server serializes tool results as JSON text)
        try:
            return json.loads(combined)
        except json.JSONDecodeError:
            return combined

    async def stop(self):
        """Gracefully stop the MCP server subprocess."""
        self._connected = False
        if self._stderr_task:
            self._stderr_task.cancel()
            try:
                await self._stderr_task
            except asyncio.CancelledError:
                pass
            self._stderr_task = None

        if self.process:
            try:
                if self.process.stdin and not self.process.stdin.is_closing():
                    self.process.stdin.close()
                self.process.terminate()
                try:
                    await asyncio.wait_for(self.process.wait(), timeout=5)
                except asyncio.TimeoutError:
                    self.process.kill()
                    await self.process.wait()
            except Exception as e:
                print(f"[Origami MCP] Error stopping server: {e}")
            finally:
                self.process = None

    async def _send_request(self, method, params=None, timeout=30):
        """Send JSON-RPC 2.0 request and wait for matching response by ID."""
        if not self.process or not self.process.stdin or not self.process.stdout:
            return None

        self._request_id += 1
        request_id = self._request_id
        request = {
            'jsonrpc': '2.0',
            'method': method,
            'id': request_id,
        }
        if params is not None:
            request['params'] = params

        msg = json.dumps(request) + '\n'
        try:
            self.process.stdin.write(msg.encode())
            await self.process.stdin.drain()
        except Exception as e:
            print(f"[Origami MCP] Failed to send request: {e}")
            return None

        # Read lines from stdout until we find our response (matched by id)
        deadline = time.time() + timeout
        while time.time() < deadline:
            remaining = deadline - time.time()
            if remaining <= 0:
                break
            try:
                line = await asyncio.wait_for(
                    self.process.stdout.readline(),
                    timeout=min(remaining, 5),
                )
                if not line:
                    print("[Origami MCP] EOF on stdout (server exited)")
                    self._connected = False
                    return None

                line_str = line.decode().strip()
                if not line_str:
                    continue

                try:
                    response = json.loads(line_str)
                except json.JSONDecodeError:
                    continue

                if response.get('id') == request_id:
                    if 'error' in response:
                        err = response['error']
                        print(f"[Origami MCP] RPC error: {err.get('message', err)}")
                        return None
                    return response.get('result')

                # Not our response (notification or other), continue reading

            except asyncio.TimeoutError:
                continue

        print(f"[Origami MCP] Timeout waiting for response to {method} (id={request_id})")
        return None

    async def _send_notification(self, method, params=None):
        """Send JSON-RPC 2.0 notification (no response expected)."""
        if not self.process or not self.process.stdin:
            return

        notification = {
            'jsonrpc': '2.0',
            'method': method,
        }
        if params is not None:
            notification['params'] = params

        msg = json.dumps(notification) + '\n'
        try:
            self.process.stdin.write(msg.encode())
            await self.process.stdin.drain()
        except Exception:
            pass

    async def _drain_stderr(self):
        """Background task to drain stderr and log MCP server output."""
        try:
            while True:
                line = await self.process.stderr.readline()
                if not line:
                    break
                text = line.decode().strip()
                if text:
                    print(f"[Origami MCP Server] {text}")
        except asyncio.CancelledError:
            pass
        except Exception:
            pass


class OrigamiBrowserDastTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "origami:browser_dast"

    @property
    def description(self) -> str:
        return ("Browser DAST - Origami Security Analysis: Launches headless Chrome with the Origami "
                "extension to perform comprehensive client-side security analysis including DOM XSS, "
                "cookie auditing, header analysis, secret scanning, technology fingerprinting, and more.")

    @property
    def schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Single URL to scan (e.g., https://example.com)"
                },
                "targets": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Multiple URLs to scan (for workflow chaining)"
                },
                "maxTargets": {
                    "type": "integer",
                    "description": "Max number of targets to process (default: 10)",
                    "default": 10
                },
                "timeout_seconds": {
                    "type": "integer",
                    "description": "Per-target timeout in seconds (default: 120)",
                    "default": 120
                },
                "authCookies": {
                    "type": "string",
                    "description": "Cookie string from upstream auth step (e.g., 'session=abc123; token=xyz')"
                },
                "authHeaders": {
                    "type": "object",
                    "description": "Custom headers from upstream auth step",
                    "x-hidden": True
                },
                "crawlDepth": {
                    "type": "integer",
                    "description": "Follow same-origin links to this depth (0 = single page, default: 0)",
                    "default": 0
                },
                "waitForAnalysis": {
                    "type": "integer",
                    "description": "Seconds to wait for Origami analyzers to complete (default: 15)",
                    "default": 15
                }
            },
            "oneOf": [
                {"required": ["target"]},
                {"required": ["targets"]}
            ]
        }

    @property
    def metadata(self):
        return {
            "category": "browser-dast",
            "phase": 4,
            "domain": ["web"],
            "input_type": ["url"],
            "output_type": ["findings"],
            "chainable_after": ["katana:", "httpx:", "authentication:"],
            "chainable_before": [],
        }

    def _resolve_targets(self, parameters: Dict[str, Any]) -> list:
        """Resolve target/targets parameter into a list."""
        if 'targets' in parameters and parameters['targets']:
            targets_param = parameters['targets']
            if isinstance(targets_param, str):
                try:
                    return json.loads(targets_param)
                except json.JSONDecodeError:
                    return [targets_param]
            elif isinstance(targets_param, list):
                return targets_param
            else:
                return [str(targets_param)]
        elif 'target' in parameters and parameters['target']:
            return [parameters['target']]
        return []

    async def execute(self, parameters: Dict[str, Any]) -> Any:
        agent = parameters.get('_agent')
        targets = self._resolve_targets(parameters)
        max_targets = parameters.get('maxTargets', 10)
        timeout_seconds = parameters.get('timeout_seconds', 120)
        auth_cookies = parameters.get('authCookies', '')
        auth_headers = parameters.get('authHeaders', {})
        crawl_depth = parameters.get('crawlDepth', 0)
        wait_for_analysis = parameters.get('waitForAnalysis', 15)

        # Extract exclusion patterns
        exclusion_patterns = parameters.get('exclusionPatterns') or parameters.get('exclusionRules')
        exclusion_url_patterns = []
        if exclusion_patterns and isinstance(exclusion_patterns, dict):
            exclusion_url_patterns = exclusion_patterns.get('urlPatterns', [])

        if not targets:
            return {
                'success': False,
                'error': 'No targets specified. Provide "target" or "targets" parameter.',
                'output': {'findings': [], 'technologies': [], 'security_score': None},
                'raw_output': ''
            }

        targets = targets[:max_targets]

        # Filter out excluded URLs
        if exclusion_url_patterns:
            filtered_targets = []
            for t in targets:
                url_path = urlparse(t).path
                excluded = any(fnmatch.fnmatch(url_path, pat) for pat in exclusion_url_patterns)
                if excluded:
                    print(f"[Origami DAST] Skipping excluded URL: {t}")
                else:
                    filtered_targets.append(t)
            if len(filtered_targets) < len(targets):
                print(f"[Origami DAST] Excluded {len(targets) - len(filtered_targets)} URLs via exclusion patterns")
            targets = filtered_targets

        print(f"[Origami DAST] Starting browser DAST scan of {len(targets)} target(s)")
        print(f"[Origami DAST] Crawl depth: {crawl_depth}, Wait: {wait_for_analysis}s, Timeout: {timeout_seconds}s")

        all_findings = []
        all_technologies = []
        all_attack_chains = []
        security_scores = []
        scan_results = []
        raw_lines = []

        try:
            from playwright.async_api import async_playwright
        except ImportError:
            return {
                'success': False,
                'error': 'Playwright not installed. Cannot run browser DAST.',
                'output': {'findings': [], 'technologies': [], 'security_score': None},
                'raw_output': ''
            }

        # Start Origami MCP server for extension bridge communication
        mcp_client = OrigamiMCPClient()
        mcp_started = False
        ext_connected = False

        context = None
        pw = None
        user_data_dir = None
        try:
            # Start MCP server BEFORE browser launch (it starts WebSocket server on :9340)
            mcp_started = await mcp_client.start()
            if mcp_started:
                print("[Origami DAST] MCP server started, WebSocket bridge listening on :9340")
            else:
                print("[Origami DAST] MCP server failed to start, will use basic analysis fallback")

            pw = await async_playwright().__aenter__()

            # Use launch_persistent_context so pages live in Chrome's default browser
            # context. This is critical: extensions can only see tabs in the default
            # context via chrome.tabs.query. browser.new_context() creates isolated
            # incognito contexts invisible to extensions.
            import tempfile
            user_data_dir = tempfile.mkdtemp(prefix='origami-dast-')

            context = await pw.chromium.launch_persistent_context(
                user_data_dir=user_data_dir,
                headless=False,
                ignore_https_errors=True,
                args=[
                    '--no-sandbox',
                    '--disable-dev-shm-usage',
                    '--disable-gpu',
                    '--disable-blink-features=AutomationControlled',
                    '--headless=new',
                    f'--disable-extensions-except={os.environ.get("ORIGAMI_EXT_PATH", "/opt/origami")}',
                    f'--load-extension={os.environ.get("ORIGAMI_EXT_PATH", "/opt/origami")}',
                ],
                viewport={'width': 1280, 'height': 900},
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
            )

            # Inject auth cookies if provided
            if auth_cookies:
                await self._inject_cookies(context, auth_cookies, targets)

            # Wait for extension to connect to MCP server via WebSocket bridge
            if mcp_started:
                ext_connected = await self._wait_for_extension_connection(mcp_client)
                if ext_connected:
                    print("[Origami DAST] Extension connected to MCP bridge - full analyzer pipeline available")
                else:
                    print("[Origami DAST] Extension did not connect to MCP bridge, will use basic analysis")

            for idx, target_url in enumerate(targets):
                if agent:
                    agent.report_progress(
                        current_operation=f'Scanning target {idx + 1}/{len(targets)}',
                        current_target=target_url,
                        items_processed=idx,
                        total_items=len(targets),
                    )

                result = await self._scan_target(
                    context, target_url, wait_for_analysis, timeout_seconds,
                    crawl_depth, raw_lines, mcp_client if ext_connected else None
                )
                scan_results.append(result)

                if result.get('findings'):
                    all_findings.extend(result['findings'])
                if result.get('technologies'):
                    all_technologies.extend(result['technologies'])
                if result.get('attack_chains'):
                    all_attack_chains.extend(result['attack_chains'])
                if result.get('security_score') is not None:
                    security_scores.append(result['security_score'])

        except Exception as exc:
            print(f"[Origami DAST] Browser error: {exc}")
            traceback.print_exc()
            raw_lines.append(f"ERROR: {str(exc)}")
        finally:
            if context:
                await context.close()
            if pw:
                try:
                    await pw.__aexit__(None, None, None)
                except Exception:
                    pass
            # Stop MCP server subprocess
            await mcp_client.stop()
            # Clean up temp user data dir
            if user_data_dir:
                try:
                    import shutil
                    shutil.rmtree(user_data_dir, ignore_errors=True)
                except Exception:
                    pass

        # Deduplicate findings by category+title+url
        deduped = {}
        for f in all_findings:
            key = f"{f.get('category', '')}-{f.get('title', '')}-{f.get('url', '')}"
            if key not in deduped:
                deduped[key] = f
        all_findings = list(deduped.values())

        # Deduplicate technologies
        tech_seen = set()
        unique_techs = []
        for t in all_technologies:
            key = f"{t.get('name', '')}-{t.get('version', '')}"
            if key not in tech_seen:
                tech_seen.add(key)
                unique_techs.append(t)

        avg_score = round(sum(security_scores) / len(security_scores)) if security_scores else None

        scan_method = "MCP bridge" if ext_connected else "basic analysis"
        print(f"[Origami DAST] ========== SCAN COMPLETE ({scan_method}) ==========")
        print(f"[Origami DAST] Targets scanned: {len(scan_results)}")
        print(f"[Origami DAST] Total findings: {len(all_findings)}")
        print(f"[Origami DAST] Technologies detected: {len(unique_techs)}")
        print(f"[Origami DAST] Average security score: {avg_score}")

        return {
            'success': True,
            'output': {
                'findings': all_findings,
                'technologies': unique_techs,
                'security_score': avg_score,
                'attack_chains': all_attack_chains,
                'targets_scanned': len(scan_results),
                'scan_results': scan_results,
                'scan_method': scan_method,
                'tool': 'origami',
                'scan_type': 'browser_dast',
            },
            'raw_output': '\n'.join(raw_lines),
        }

    async def _inject_cookies(self, context, cookie_string: str, targets: list):
        """Parse and inject cookies into browser context."""
        try:
            cookies = []
            for part in cookie_string.split(';'):
                part = part.strip()
                if '=' in part:
                    name, value = part.split('=', 1)
                    domains = set()
                    for t in targets:
                        try:
                            parsed = urlparse(t)
                            if parsed.hostname:
                                domains.add(parsed.hostname)
                        except Exception:
                            pass
                    for domain in domains:
                        cookies.append({
                            'name': name.strip(),
                            'value': value.strip(),
                            'domain': domain,
                            'path': '/',
                        })
            if cookies:
                await context.add_cookies(cookies)
                print(f"[Origami DAST] Injected {len(cookies)} cookies for authenticated scan")
        except Exception as e:
            print(f"[Origami DAST] Warning: Failed to inject cookies: {e}")

    async def _wait_for_extension_connection(self, mcp_client, timeout=30):
        """Poll get_connection_status until the extension connects to the MCP bridge."""
        print(f"[Origami DAST] Waiting up to {timeout}s for extension to connect to MCP bridge...")
        deadline = time.time() + timeout
        attempt = 0
        while time.time() < deadline:
            attempt += 1
            result = await mcp_client.call_tool('get_connection_status', timeout=5)
            if result and isinstance(result, dict) and result.get('connected'):
                print(f"[Origami DAST] Extension connected after {attempt} attempt(s)")
                return True
            await asyncio.sleep(2)
        return False

    async def _scan_target(self, context, url: str, wait_secs: int, timeout: int,
                           crawl_depth: int, raw_lines: list, mcp_client=None) -> dict:
        """Scan a single target URL with Origami."""
        result = {
            'url': url,
            'success': False,
            'findings': [],
            'technologies': [],
            'attack_chains': [],
            'security_score': None,
            'pages_analyzed': 0,
            'scan_method': 'mcp' if mcp_client else 'basic',
            'error': None,
        }

        page = None
        try:
            page = await context.new_page()

            # Navigate to target — use domcontentloaded instead of networkidle because
            # many sites have persistent connections (analytics, websockets, long-polling)
            # that prevent networkidle from ever firing, causing a timeout.
            print(f"[Origami DAST] Navigating to {url}")
            response = await page.goto(url, wait_until='domcontentloaded', timeout=timeout * 1000)

            if not response:
                result['error'] = f"No response from {url}"
                raw_lines.append(f"ERROR: No response from {url}")
                return result

            result['http_status'] = response.status
            raw_lines.append(f"[{response.status}] {url}")

            # Wait for page to settle and Origami extension to initialize on this tab
            await asyncio.sleep(min(wait_secs, 5))

            if mcp_client:
                # Use MCP bridge for full Origami analysis (24 analyzers)
                mcp_result = await self._scan_via_mcp(mcp_client, url)

                if mcp_result and mcp_result.get('findings'):
                    result['findings'] = mcp_result['findings']
                    result['technologies'] = mcp_result.get('technologies', [])
                    result['attack_chains'] = mcp_result.get('attack_chains', [])
                    result['security_score'] = mcp_result.get('security_score')
                    result['pages_analyzed'] = 1
                    result['success'] = True
                    result['scan_method'] = 'mcp'
                    raw_lines.append(f"  Scan complete via MCP: {len(result['findings'])} findings, score: {result['security_score']}")
                else:
                    # MCP scan returned empty - retry once after brief wait
                    print(f"[Origami DAST] MCP scan returned empty, retrying after 5s...")
                    await asyncio.sleep(5)
                    mcp_result = await self._scan_via_mcp(mcp_client, url)

                    if mcp_result and mcp_result.get('findings'):
                        result['findings'] = mcp_result['findings']
                        result['technologies'] = mcp_result.get('technologies', [])
                        result['attack_chains'] = mcp_result.get('attack_chains', [])
                        result['security_score'] = mcp_result.get('security_score')
                        result['pages_analyzed'] = 1
                        result['success'] = True
                        result['scan_method'] = 'mcp'
                        raw_lines.append(f"  Scan complete via MCP (retry): {len(result['findings'])} findings")
                    else:
                        # Fall through to basic analysis
                        print(f"[Origami DAST] MCP scan failed after retry, falling back to basic analysis")
                        basic = await self._basic_analysis(page, url, response)
                        result['findings'] = basic.get('findings', [])
                        result['success'] = True
                        result['scan_method'] = 'basic-fallback'
                        result['pages_analyzed'] = 1
                        raw_lines.append(f"  Findings (basic fallback): {len(result['findings'])}")
            else:
                # No MCP connection - use basic header/cookie analysis
                print(f"[Origami DAST] No MCP connection, performing basic header/cookie analysis")
                basic = await self._basic_analysis(page, url, response)
                result['findings'] = basic.get('findings', [])
                result['success'] = True
                result['pages_analyzed'] = 1
                raw_lines.append(f"  Findings (basic): {len(result['findings'])}")

            # Optional crawl for additional pages
            if crawl_depth > 0:
                crawled = await self._crawl_and_analyze(
                    context, page, url, crawl_depth, wait_secs, timeout, raw_lines, mcp_client,
                    exclusion_url_patterns=exclusion_url_patterns or None
                )
                result['findings'].extend(crawled.get('findings', []))
                result['technologies'].extend(crawled.get('technologies', []))
                result['pages_analyzed'] += crawled.get('pages_analyzed', 0)

        except Exception as exc:
            result['error'] = str(exc)
            raw_lines.append(f"ERROR scanning {url}: {exc}")
            print(f"[Origami DAST] Error scanning {url}: {exc}")
        finally:
            if page:
                try:
                    await page.close()
                except Exception:
                    pass

        return result

    async def _scan_via_mcp(self, mcp_client, url: str) -> Optional[dict]:
        """Run full Origami scan via MCP bridge and return normalized findings."""
        findings = []
        technologies = []
        attack_chains = []
        security_score = None

        try:
            # Step 1: Trigger full 13-step analyzer pipeline
            print(f"[Origami DAST] Triggering MCP scan_page for {url}")
            scan_result = await mcp_client.call_tool('scan_page', timeout=60)

            if scan_result and isinstance(scan_result, dict) and scan_result.get('error'):
                print(f"[Origami DAST] scan_page error: {scan_result.get('message', 'unknown')}")
                return None

            # Extension attaches _tabId to results so subsequent calls can target the same tab
            tab_id = None
            if scan_result and isinstance(scan_result, dict):
                tab_id = scan_result.get('_tabId')
                if tab_id:
                    print(f"[Origami DAST] Resolved tabId={tab_id} from scan_page response")

            tab_args = {'tabId': tab_id} if tab_id else {}
            print(f"[Origami DAST] scan_page complete, fetching results...")

            # Step 2: Get findings summary to identify non-empty categories
            summary = await mcp_client.call_tool('get_findings_summary', tab_args, timeout=15)
            if not summary or not isinstance(summary, dict):
                print("[Origami DAST] No findings summary available")
                return None

            categories_data = summary.get('categories', {})
            total_findings = summary.get('totalFindings', 0)
            print(f"[Origami DAST] Summary: {total_findings} total findings across {len(categories_data)} categories")

            # Step 3: Fetch detailed findings for each non-empty category
            for category in MCP_CATEGORIES:
                cat_info = categories_data.get(category, {})
                count = cat_info.get('count', 0) if isinstance(cat_info, dict) else 0
                if count == 0:
                    continue

                print(f"[Origami DAST] Fetching {count} findings from category: {category}")
                cat_findings = await mcp_client.call_tool('get_findings_by_category', {
                    'category': category,
                    **tab_args,
                }, timeout=15)

                if cat_findings:
                    normalized = self._normalize_mcp_findings(cat_findings, category, url)
                    findings.extend(normalized)

            # Step 4: Get security score
            score_data = await mcp_client.call_tool('get_security_score', tab_args, timeout=10)
            if score_data and isinstance(score_data, dict):
                score = score_data.get('score') or score_data.get('securityScore')
                if isinstance(score, (int, float)):
                    security_score = int(score)

            # Step 5: Get detected technologies
            tech_data = await mcp_client.call_tool('get_technologies', tab_args, timeout=10)
            if tech_data:
                tech_list = tech_data if isinstance(tech_data, list) else tech_data.get('technologies', [])
                for t in (tech_list if isinstance(tech_list, list) else []):
                    if isinstance(t, dict):
                        technologies.append({
                            'name': t.get('name', 'Unknown'),
                            'version': t.get('version', ''),
                            'category': t.get('category', ''),
                            'confidence': t.get('confidence', 0),
                            'cves': t.get('cves', []),
                        })
                    elif isinstance(t, str):
                        technologies.append({'name': t, 'version': '', 'category': '', 'confidence': 0, 'cves': []})

            # Step 6: Get attack chains from correlation engine
            chains_data = await mcp_client.call_tool('get_attack_chains', tab_args, timeout=10)
            if chains_data:
                chain_list = chains_data if isinstance(chains_data, list) else chains_data.get('chains', [])
                if isinstance(chain_list, list):
                    attack_chains.extend(chain_list)

            print(f"[Origami DAST] MCP scan results: {len(findings)} findings, "
                  f"{len(technologies)} technologies, score: {security_score}")

        except Exception as e:
            print(f"[Origami DAST] MCP scan error: {e}")
            traceback.print_exc()
            return None

        return {
            'findings': findings,
            'technologies': technologies,
            'attack_chains': attack_chains,
            'security_score': security_score,
        }

    def _normalize_mcp_findings(self, findings_data, mcp_category: str, target_url: str) -> list:
        """Convert MCP findings response to platform finding format."""
        findings = []

        # findings_data can be a list of findings or a dict with a 'findings' key
        if isinstance(findings_data, dict):
            items = findings_data.get('findings', [])
            if not isinstance(items, list):
                items = [findings_data]
        elif isinstance(findings_data, list):
            items = findings_data
        else:
            return findings

        for item in items:
            if not isinstance(item, dict):
                continue

            finding = self._normalize_finding(item, target_url)
            if not finding:
                continue

            # If finding has no specific category, use MCP category mapping
            if not finding.get('category') or finding['category'] == 'general':
                finding['category'] = MCP_CATEGORY_MAP.get(mcp_category, mcp_category)

            # Ensure CWE mapping for the resolved category
            if not finding.get('cwe_id'):
                cwe = CWE_MAP.get(finding['category'], {})
                finding['cwe_id'] = cwe.get('id', '')
                finding['cwe_name'] = cwe.get('name', '')

            # Tag the analyzer source
            if not finding.get('analyzer'):
                finding['analyzer'] = f'origami-{mcp_category}'

            findings.append(finding)

        return findings

    def _normalize_finding(self, finding: dict, target_url: str) -> dict:
        """Normalize a single Origami finding to platform format."""
        if not isinstance(finding, dict):
            return {}

        category = (finding.get('category', '') or finding.get('type', '') or 'general').lower().strip()
        severity = (finding.get('severity', '') or 'INFO').upper().strip()
        title = finding.get('title', '') or finding.get('name', '') or finding.get('message', '') or 'Unknown Finding'
        description = finding.get('description', '') or finding.get('detail', '') or finding.get('details', '') or ''
        url = finding.get('url', '') or target_url

        # Normalize severity
        if severity not in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'):
            severity_map = {'error': 'HIGH', 'warning': 'MEDIUM', 'warn': 'MEDIUM', 'notice': 'LOW', 'information': 'INFO'}
            severity = severity_map.get(severity.lower(), 'INFO')

        # Map to CWE
        cwe = CWE_MAP.get(category, {})
        if not cwe:
            # Try partial match
            for cwe_key, cwe_val in CWE_MAP.items():
                if cwe_key in category or category in cwe_key:
                    cwe = cwe_val
                    break

        recommendation = finding.get('recommendation', '') or finding.get('remediation', '') or self._default_recommendation(category)

        return {
            'title': title,
            'description': description,
            'severity': severity,
            'category': category,
            'url': url,
            'cwe_id': cwe.get('id', ''),
            'cwe_name': cwe.get('name', ''),
            'recommendation': recommendation,
            'evidence': finding.get('evidence', {}) or {},
            'analyzer': finding.get('analyzer', ''),
            'confidence': finding.get('confidence', ''),
        }

    def _default_recommendation(self, category: str) -> str:
        """Return a default recommendation based on finding category."""
        recommendations = {
            'xss': 'Sanitize user input and use Content Security Policy to prevent XSS attacks.',
            'dom-xss': 'Avoid using dangerous sinks like innerHTML, eval(), document.write(). Use textContent or DOMPurify.',
            'csrf': 'Implement anti-CSRF tokens and verify the Origin/Referer header on state-changing requests.',
            'missing-csp': 'Implement a Content Security Policy header to prevent XSS and injection attacks.',
            'missing-hsts': 'Add Strict-Transport-Security header with max-age of at least 31536000.',
            'missing-x-frame-options': 'Add X-Frame-Options: DENY or SAMEORIGIN header to prevent clickjacking.',
            'cookie-no-httponly': 'Set the HttpOnly flag on cookies to prevent client-side script access.',
            'cookie-no-secure': 'Set the Secure flag on cookies to ensure they are only sent over HTTPS.',
            'cookie-no-samesite': 'Set the SameSite attribute on cookies to prevent CSRF attacks.',
            'cors-misconfiguration': 'Configure CORS to allow only trusted origins. Never reflect arbitrary origins.',
            'mixed-content': 'Serve all resources over HTTPS. Update HTTP URLs to HTTPS.',
            'exposed-secrets': 'Remove hardcoded secrets from client-side code. Use environment variables and server-side storage.',
            'sri-missing': 'Add integrity attributes to third-party script and stylesheet tags.',
            'outdated-library': 'Update the library to the latest version to patch known vulnerabilities.',
        }
        return recommendations.get(category, 'Review and address this security finding according to your security policy.')

    async def _basic_analysis(self, page, url: str, response) -> dict:
        """Perform basic security header and cookie analysis when MCP is unavailable."""
        findings = []
        headers = response.headers if response else {}

        # Check security headers
        security_headers = {
            'content-security-policy': ('missing-csp', 'MEDIUM', 'Missing Content Security Policy Header'),
            'strict-transport-security': ('missing-hsts', 'MEDIUM', 'Missing HTTP Strict Transport Security Header'),
            'x-frame-options': ('missing-x-frame-options', 'MEDIUM', 'Missing X-Frame-Options Header'),
            'x-content-type-options': ('missing-x-content-type-options', 'LOW', 'Missing X-Content-Type-Options Header'),
            'permissions-policy': ('permissions-policy', 'LOW', 'Missing Permissions-Policy Header'),
            'referrer-policy': ('missing-referrer-policy', 'LOW', 'Missing Referrer-Policy Header'),
        }

        for header_name, (category, severity, title) in security_headers.items():
            if header_name not in headers:
                cwe = CWE_MAP.get(category, {})
                findings.append({
                    'title': title,
                    'description': f'The HTTP response from {url} is missing the {header_name} header.',
                    'severity': severity,
                    'category': category,
                    'url': url,
                    'cwe_id': cwe.get('id', ''),
                    'cwe_name': cwe.get('name', ''),
                    'recommendation': self._default_recommendation(category),
                    'evidence': {'missing_header': header_name, 'response_headers': dict(headers)},
                    'analyzer': 'basic-header-check',
                    'confidence': 'high',
                })

        # Check cookies
        cookies = await page.context.cookies(url)
        for cookie in cookies:
            if not cookie.get('httpOnly', False):
                findings.append({
                    'title': f'Cookie "{cookie["name"]}" Missing HttpOnly Flag',
                    'description': f'The cookie "{cookie["name"]}" on {url} does not have the HttpOnly flag set.',
                    'severity': 'MEDIUM',
                    'category': 'cookie-no-httponly',
                    'url': url,
                    'cwe_id': 'CWE-1004',
                    'cwe_name': 'Cookie Without HttpOnly Flag',
                    'recommendation': self._default_recommendation('cookie-no-httponly'),
                    'evidence': {'cookie_name': cookie['name'], 'cookie_domain': cookie.get('domain', '')},
                    'analyzer': 'basic-cookie-check',
                    'confidence': 'high',
                })
            if not cookie.get('secure', False) and url.startswith('https'):
                findings.append({
                    'title': f'Cookie "{cookie["name"]}" Missing Secure Flag',
                    'description': f'The cookie "{cookie["name"]}" on {url} does not have the Secure flag set despite being served over HTTPS.',
                    'severity': 'MEDIUM',
                    'category': 'cookie-no-secure',
                    'url': url,
                    'cwe_id': 'CWE-614',
                    'cwe_name': 'Cookie Without Secure Flag',
                    'recommendation': self._default_recommendation('cookie-no-secure'),
                    'evidence': {'cookie_name': cookie['name'], 'cookie_domain': cookie.get('domain', '')},
                    'analyzer': 'basic-cookie-check',
                    'confidence': 'high',
                })

        return {'findings': findings}

    async def _crawl_and_analyze(self, context, page, base_url: str, depth: int,
                                  wait_secs: int, timeout: int, raw_lines: list,
                                  mcp_client=None, exclusion_url_patterns=None) -> dict:
        """Shallow crawl: extract same-origin links and analyze each page."""
        all_findings = []
        all_technologies = []
        pages_analyzed = 0
        visited = {base_url}

        try:
            parsed_base = urlparse(base_url)
            base_origin = f"{parsed_base.scheme}://{parsed_base.netloc}"

            # Extract links from current page
            links = await page.evaluate('''() => {
                return Array.from(document.querySelectorAll('a[href]'))
                    .map(a => a.href)
                    .filter(href => href.startsWith('http'));
            }''')

            # Filter to same-origin, limit to 20
            same_origin_links = []
            for link in links:
                try:
                    parsed = urlparse(link)
                    link_origin = f"{parsed.scheme}://{parsed.netloc}"
                    if link_origin == base_origin and link not in visited:
                        # Check exclusion patterns
                        if exclusion_url_patterns and any(
                            fnmatch.fnmatch(parsed.path, pat) for pat in exclusion_url_patterns
                        ):
                            print(f"[Origami DAST] Skipping excluded URL: {link}")
                            continue
                        same_origin_links.append(link)
                        visited.add(link)
                except Exception:
                    pass

            same_origin_links = same_origin_links[:20]
            print(f"[Origami DAST] Crawling {len(same_origin_links)} same-origin links (depth={depth})")

            for link in same_origin_links:
                try:
                    crawl_page = await context.new_page()
                    response = await crawl_page.goto(link, wait_until='domcontentloaded', timeout=timeout * 1000)
                    await asyncio.sleep(min(wait_secs, 5))  # Shorter wait for crawled pages

                    if mcp_client:
                        # Use MCP for crawled page analysis
                        mcp_result = await self._scan_via_mcp(mcp_client, link)
                        if mcp_result and mcp_result.get('findings'):
                            all_findings.extend(mcp_result['findings'])
                            all_technologies.extend(mcp_result.get('technologies', []))
                        elif response:
                            # MCP failed for this page, fall back to basic
                            basic = await self._basic_analysis(crawl_page, link, response)
                            all_findings.extend(basic.get('findings', []))
                    elif response:
                        basic = await self._basic_analysis(crawl_page, link, response)
                        all_findings.extend(basic.get('findings', []))

                    pages_analyzed += 1
                    raw_lines.append(f"  Crawled: {link} ({len(all_findings)} cumulative findings)")
                    await crawl_page.close()
                except Exception as e:
                    print(f"[Origami DAST] Error crawling {link}: {e}")
                    raw_lines.append(f"  ERROR crawling {link}: {e}")

        except Exception as e:
            print(f"[Origami DAST] Crawl error: {e}")

        return {
            'findings': all_findings,
            'technologies': all_technologies,
            'pages_analyzed': pages_analyzed,
        }


def get_tool():
    return OrigamiBrowserDastTool()
