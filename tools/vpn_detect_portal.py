"""
VPN Portal Detection Tool
Probes HTTPS ports for VPN portal signatures (FortiGate, GlobalProtect,
Prisma Access, Cisco AnyConnect, Pulse Secure, Citrix Gateway).
"""

import asyncio
import aiohttp
import json
import re
import ssl
import time
from typing import Dict, Any, List, Optional
from plugin_interface import ToolPlugin


# VPN signature definitions
VPN_SIGNATURES = {
    'fortigate': {
        'label': 'FortiGate / FortiOS',
        'paths': ['/remote/login', '/remote/logincheck'],
        'title_patterns': [r'FortiGate', r'FortiOS', r'FortiToken'],
        'header_patterns': {'server': [r'Fortinet', r'FortiOS']},
        'body_patterns': [r'fortinet', r'fgt_lang', r'SVPNCOOKIE', r'/remote/login'],
        'cert_cn_patterns': [r'Fortinet', r'FortiGate'],
    },
    'globalprotect': {
        'label': 'Palo Alto GlobalProtect',
        'paths': ['/global-protect/login.esp', '/ssl-vpn/login.esp', '/global-protect/portal/portal.esp'],
        'title_patterns': [r'GlobalProtect\s+Portal', r'GlobalProtect'],
        'header_patterns': {},
        'body_patterns': [r'global-protect', r'login\.esp', r'gpRealm', r'inputCredential'],
        'cert_cn_patterns': [r'Palo\s*Alto'],
    },
    'prisma_access': {
        'label': 'Prisma Access',
        'paths': ['/global-protect/login.esp'],
        'title_patterns': [r'Prisma\s+Access'],
        'header_patterns': {},
        'body_patterns': [r'prisma', r'saml.*redirect', r'Prisma\s+Access'],
        'cert_cn_patterns': [r'Prisma'],
    },
    'cisco_anyconnect': {
        'label': 'Cisco AnyConnect',
        'paths': ['/+CSCOE+/logon.html', '/+webvpn+/index.html'],
        'title_patterns': [r'WebVPN', r'AnyConnect', r'Cisco.*SSL\s+VPN'],
        'header_patterns': {'server': [r'Cisco']},
        'body_patterns': [r'CSCOE', r'webvpn', r'anyconnect', r'cisco.*vpn'],
        'cert_cn_patterns': [r'Cisco'],
    },
    'pulse_secure': {
        'label': 'Pulse Secure / Ivanti',
        'paths': ['/dana-na/auth/url_default/welcome.cgi', '/dana-na/auth/url_0/welcome.cgi'],
        'title_patterns': [r'Pulse\s+Secure', r'Ivanti\s+Connect', r'Juniper.*VPN'],
        'header_patterns': {},
        'body_patterns': [r'pulse.*secure', r'dana-na', r'DSIDFormDataStr', r'ivanti'],
        'cert_cn_patterns': [r'Pulse\s*Secure', r'Ivanti'],
    },
    'citrix_gateway': {
        'label': 'Citrix Gateway / NetScaler',
        'paths': ['/vpn/index.html', '/logon/LogonPoint/', '/logon/LogonPoint/tmindex.html'],
        'title_patterns': [r'Citrix\s+Gateway', r'NetScaler', r'Citrix.*Login'],
        'header_patterns': {},
        'body_patterns': [r'citrix', r'LogonPoint', r'netscaler', r'NSC_'],
        'cert_cn_patterns': [r'Citrix', r'NetScaler'],
    },
}


class VpnDetectPortalTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "vpn:detect_portal"

    @property
    def description(self) -> str:
        return "Probe HTTPS ports for VPN portal signatures (FortiGate, GlobalProtect, Prisma Access, Cisco AnyConnect, Pulse Secure, Citrix Gateway)"

    @property
    def schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target host or URL to probe for VPN portals"
                },
                "ports": {
                    "type": "array",
                    "items": {"type": "integer"},
                    "description": "Ports to probe (default: [443, 4443, 8443, 10443])"
                },
            },
            "required": ["target"]
        }

    @property
    def metadata(self) -> Dict[str, Any]:
        return {
            "category": "recon",
            "phase": 2,
            "domain": ["infra"],
            "input_type": ["ip", "hostname"],
            "output_type": ["services"],
            "chainable_after": ["nmap:service_scan"],
            "chainable_before": ["credential_test:leaked"],
        }

    async def execute(self, parameters: Dict[str, Any]) -> Any:
        agent = parameters.get('_agent')
        target = parameters.get('target', '').strip()
        ports = parameters.get('ports', [443, 4443, 8443, 10443])

        if isinstance(ports, str):
            ports = json.loads(ports)

        # Normalize target: strip protocol/path, keep hostname
        host = target
        for prefix in ['https://', 'http://']:
            if host.startswith(prefix):
                host = host[len(prefix):]
        host = host.split('/')[0].split(':')[0]

        start_time = time.time()
        portals = []

        if agent:
            agent.report_progress(
                current_operation=f"Probing {host} for VPN portals",
                current_target=host,
                items_processed=0,
                total_items=len(ports),
            )

        # SSL context that skips verification (VPN portals often use self-signed certs)
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE

        connector = aiohttp.TCPConnector(ssl=ssl_ctx)
        timeout = aiohttp.ClientTimeout(total=15, connect=10)

        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            for i, port in enumerate(ports):
                if agent:
                    agent.report_progress(
                        current_operation=f"Probing port {port} on {host}",
                        current_target=host,
                        items_processed=i,
                        total_items=len(ports),
                    )
                detected = await self._probe_port(session, host, port, agent)
                portals.extend(detected)

        elapsed = time.time() - start_time

        output = {
            'target': host,
            'portsScanned': ports,
            'portals': portals,
            'summary': {
                'totalPortals': len(portals),
                'portsScanned': len(ports),
                'vpnTypes': list(set(p['type'] for p in portals)),
            },
            'tool': 'vpn_detect',
            'scan_type': 'detect_portal',
        }

        raw_output = json.dumps(output, indent=2, default=str)

        if agent:
            agent.report_progress(
                current_operation=f"VPN portal scan complete: {len(portals)} portals found on {host}",
                current_target=host,
                items_processed=len(ports),
                total_items=len(ports),
            )
            agent.append_output(raw_output)

        return {
            'success': True,
            'output': output,
            'raw_output': raw_output,
            'execution_metrics': {
                'duration_seconds': round(elapsed, 2),
                'ports_scanned': len(ports),
                'portals_found': len(portals),
            }
        }

    async def _probe_port(self, session: aiohttp.ClientSession, host: str, port: int, agent=None) -> List[Dict]:
        """Probe a single port for VPN portal signatures."""
        portals = []
        base_url = f"https://{host}:{port}" if port != 443 else f"https://{host}"

        for vpn_type, sig in VPN_SIGNATURES.items():
            evidence = []
            confidence = 0

            # 1. Probe known paths
            for path in sig['paths']:
                url = f"{base_url}{path}"
                try:
                    async with session.get(url, allow_redirects=True) as resp:
                        status = resp.status
                        body = await resp.text(errors='replace')
                        headers = resp.headers

                        if status in (200, 301, 302, 401, 403):
                            # Check page title
                            title_match = re.search(r'<title>(.*?)</title>', body, re.IGNORECASE | re.DOTALL)
                            page_title = title_match.group(1).strip() if title_match else ''

                            for pattern in sig['title_patterns']:
                                if re.search(pattern, page_title, re.IGNORECASE):
                                    evidence.append(f"Page title matches: '{page_title}' at {path}")
                                    confidence += 40

                            # Check body patterns
                            for pattern in sig['body_patterns']:
                                if re.search(pattern, body, re.IGNORECASE):
                                    evidence.append(f"Body content matches pattern: {pattern} at {path}")
                                    confidence += 15

                            # Check response headers
                            for header_name, patterns in sig.get('header_patterns', {}).items():
                                header_val = headers.get(header_name, '')
                                for pattern in patterns:
                                    if re.search(pattern, header_val, re.IGNORECASE):
                                        evidence.append(f"Header {header_name}={header_val} matches {pattern}")
                                        confidence += 20

                            # Path responded (not 404/timeout) is itself weak evidence
                            if status == 200:
                                evidence.append(f"Path {path} returned 200 OK")
                                confidence += 10

                except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
                    continue

            # 2. Check SSL certificate CN (probe root path if we haven't yet)
            if not evidence:
                try:
                    async with session.get(base_url, allow_redirects=True) as resp:
                        body = await resp.text(errors='replace')
                        # Check body and title on root page too
                        title_match = re.search(r'<title>(.*?)</title>', body, re.IGNORECASE | re.DOTALL)
                        page_title = title_match.group(1).strip() if title_match else ''

                        for pattern in sig['title_patterns']:
                            if re.search(pattern, page_title, re.IGNORECASE):
                                evidence.append(f"Root page title matches: '{page_title}'")
                                confidence += 35

                        for pattern in sig['body_patterns']:
                            if re.search(pattern, body, re.IGNORECASE):
                                evidence.append(f"Root body matches pattern: {pattern}")
                                confidence += 10

                except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
                    pass

            # Cap confidence at 100
            confidence = min(confidence, 100)

            if confidence >= 25:
                portals.append({
                    'url': base_url,
                    'port': port,
                    'type': vpn_type,
                    'label': sig['label'],
                    'confidence': confidence,
                    'evidence': evidence[:10],  # Limit evidence items
                })

                if agent:
                    agent.report_progress(f"Detected {sig['label']} portal on {base_url} (confidence: {confidence}%)")

        return portals


def get_tool():
    return VpnDetectPortalTool()
