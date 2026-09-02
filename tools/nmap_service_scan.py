"""
Nmap Service Scan Tool
Performs service and version detection on a specific port
"""

import asyncio
import json
import re
import xml.etree.ElementTree as ET
from plugin_interface import ToolPlugin
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse

from lib.wrapper_helpers import resolve_targets as _resolve_targets


FTP_ANON_POSITIVE_RE = re.compile(
    r"anonymous\s+ftp\s+login\s+allowed\s*\(ftp\s+code\s+230\)",
    re.IGNORECASE,
)
FTP_LISTING_LIMIT = 20
FTP_LISTING_LINE_LIMIT = 240


class NmapServiceScanTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "nmap:service_scan"

    @property
    def description(self) -> str:
        return "Performs service and version detection on a specific port using Nmap"

    @property
    def schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "IP address, hostname, URL, or host:port to scan"
                },
                "targets": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Multiple IP addresses to scan (alternative to target, for workflow chaining)"
                },
                "port": {
                    "type": "integer",
                    "description": "Port number to scan"
                },
                "maxTargets": {
                    "type": "integer",
                    "description": "Maximum number of targets to scan from array (default: 20)",
                    "default": 20
                }
            },
            "oneOf": [
                {"required": ["target", "port"]},
                {"required": ["targets", "port"]}
            ]
        }

    @property
    def metadata(self):
        return {
            "category": "enumeration",
            "phase": 3,
            "domain": ["infra"],
            "input_type": ["ip", "hostname"],
            "output_type": ["ports", "services"],
            "chainable_after": ["system:dns_resolve", "nmap:host_discovery"],
            "chainable_before": ["nuclei:", "testssl:", "httpx:probe"],
        }

    async def execute(self, parameters: Dict[str, Any]) -> Any:
        agent = parameters.get('_agent')
        port = parameters.get('port')

        # Resolve targets list
        targets_list = _resolve_targets(parameters)
        if not targets_list:
            return {
                'success': False,
                'error': 'Either target or targets parameter is required',
                'output': {
                    'results': [],
                    'targets': [],
                    'total': 0,
                    'tool': 'nmap',
                    'scan_type': 'service_scan'
                },
                'raw_output': ''
            }

        normalized_targets = []
        derived_port = port
        for raw_target in targets_list:
            normalized_target, explicit_port = self._split_host_port(str(raw_target))
            normalized_targets.append(normalized_target)
            if derived_port is None and explicit_port is not None:
                derived_port = explicit_port

        port = int(derived_port or 80)
        targets_list = normalized_targets

        # Apply maxTargets limit
        max_targets = parameters.get('maxTargets', 20)
        if len(targets_list) > max_targets:
            print(f"[Nmap Service Scan] Limiting {len(targets_list)} targets to {max_targets}")
            targets_list = targets_list[:max_targets]

        if agent:
            agent.report_progress(
                current_operation=f"Starting service scan on port {port}",
                current_target=targets_list[0],
                items_processed=0,
                total_items=len(targets_list)
            )

        all_results = []
        all_raw = []
        all_findings = []

        for idx, target in enumerate(targets_list):
            try:
                process = await asyncio.create_subprocess_exec(
                    'nmap', '-Pn', '-p', str(port), '-sV', '-A', target, '-oX', '-',
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )

                try:
                    stdout, stderr = await asyncio.wait_for(
                        process.communicate(),
                        timeout=120  # 2 minutes max per target
                    )
                except asyncio.TimeoutError:
                    process.kill()
                    await process.wait()
                    if agent:
                        agent.append_output(f"[Nmap Service Scan] Timeout on {target}")
                    all_results.append({'target': target, 'port': port, 'service': None, 'error': 'timeout'})
                    continue

                stdout_text = stdout.decode('utf-8', errors='replace') if stdout else ''
                all_raw.append(stdout_text)

                if process.returncode != 0:
                    stderr_text = stderr.decode('utf-8', errors='replace') if stderr else ''
                    all_results.append({'target': target, 'port': port, 'service': None, 'error': stderr_text[:200]})
                    continue

                # Parse XML output
                service_info = self._parse_nmap_output(stdout_text, port)
                all_results.append({
                    'target': target,
                    'port': port,
                    'service': service_info
                })
                ftp_finding = self._build_ftp_anon_finding(target, port, service_info)
                if ftp_finding:
                    all_findings.append(ftp_finding)

                if agent:
                    agent.report_progress(
                        current_operation="Service scan",
                        current_target=target,
                        items_processed=idx + 1,
                        total_items=len(targets_list)
                    )
                    svc_name = service_info.get('name', 'unknown') if service_info else 'unknown'
                    agent.append_output(f"[Nmap Service Scan] {target}:{port} -> {svc_name}")

            except FileNotFoundError:
                return {
                    'success': False,
                    'error': 'Nmap not installed',
                    'output': {
                        'results': [],
                        'targets': [],
                        'total': 0,
                        'tool': 'nmap',
                        'scan_type': 'service_scan'
                    },
                    'raw_output': ''
                }
            except Exception as e:
                all_results.append({'target': target, 'port': port, 'service': None, 'error': str(e)})

        if agent:
            agent.report_progress(
                current_operation="Service scan completed",
                current_target=targets_list[0],
                items_processed=len(targets_list),
                total_items=len(targets_list)
            )

        raw_output = '\n'.join(all_raw)
        if len(raw_output) > 5 * 1024 * 1024:
            raw_output = raw_output[:5 * 1024 * 1024] + "\n... (truncated)"

        return {
            'success': True,
            'output': {
                'results': all_results,
                'targets': targets_list,
                'total': len(all_results),
                'tool': 'nmap',
                'scan_type': 'service_scan',
                'findings': all_findings,
            },
            'raw_output': raw_output
        }

    def _split_host_port(self, raw_target: str):
        """Return (host, port) for URL or host:port targets."""
        target = raw_target.strip()
        if not target:
            return raw_target, None

        try:
            parsed = urlparse(target if "://" in target else f"//{target}", scheme="http")
            host = parsed.hostname
            port = parsed.port
            if host:
                return host, port
        except ValueError:
            pass

        if ":" in target and target.count(":") == 1:
            host_part, port_part = target.rsplit(":", 1)
            if port_part.isdigit():
                return host_part, int(port_part)

        return target, None

    def _parse_nmap_output(self, xml_output: str, port: int) -> dict:
        """Parse Nmap XML output to extract service information"""
        service_info = {}

        try:
            root = ET.fromstring(xml_output)

            # Find the specific port
            for port_elem in root.findall('.//port'):
                if int(port_elem.get('portid')) == port:
                    service = port_elem.find('service')
                    if service is not None:
                        service_info = {
                            'name': service.get('name'),
                            'product': service.get('product'),
                            'version': service.get('version'),
                            'extrainfo': service.get('extrainfo'),
                            'ostype': service.get('ostype'),
                            'method': service.get('method'),
                            'conf': service.get('conf'),
                        }

                        # Get banner if available
                        script_output = port_elem.findall('.//script')
                        for script in script_output:
                            if script.get('id') == 'banner':
                                service_info['banner'] = script.get('output')
                            elif script.get('id') == 'ftp-anon':
                                ftp_anon = self._parse_ftp_anon_output(script.get('output'))
                                if ftp_anon:
                                    service_info['ftpAnon'] = ftp_anon
                    break
        except ET.ParseError as e:
            print(f"Error parsing Nmap XML: {e}")

        return service_info

    def _parse_ftp_anon_output(self, raw_output: Optional[str]) -> Optional[Dict[str, Any]]:
        """Retain only positive, bounded ftp-anon evidence from the NSE script."""
        output = str(raw_output or '')
        match = FTP_ANON_POSITIVE_RE.search(output)
        if not match:
            return None

        listing: List[str] = []
        for raw_line in output[match.end():].splitlines():
            line = self._sanitize_evidence_line(raw_line)
            if not line:
                continue
            listing.append(line)
            if len(listing) >= FTP_LISTING_LIMIT:
                break

        return {
            'verified': True,
            'replyCode': 230,
            'proof': 'Anonymous FTP login allowed (FTP code 230)',
            'listing': listing,
            'listingTruncated': len(
                [line for line in output[match.end():].splitlines() if line.strip()]
            ) > len(listing),
        }

    def _sanitize_evidence_line(self, raw_line: str) -> str:
        printable = ''.join(
            character if character.isprintable() or character == '\t' else ' '
            for character in str(raw_line or '')
        )
        return ' '.join(printable.split())[:FTP_LISTING_LINE_LIMIT]

    def _build_ftp_anon_finding(
        self,
        target: str,
        port: int,
        service_info: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        ftp_anon = service_info.get('ftpAnon') if isinstance(service_info, dict) else None
        if not isinstance(ftp_anon, dict) or ftp_anon.get('verified') is not True:
            return None

        endpoint = f"ftp://{target}:{port}/"
        listing = [str(line) for line in ftp_anon.get('listing', []) if str(line).strip()]
        request = (
            f"FTP CONNECT {target}:{port}\n"
            "USER anonymous\n"
            "PASS [REDACTED]\n"
            "LIST"
        )
        response_lines = [
            str(ftp_anon.get('proof') or '230 Anonymous FTP login allowed'),
            *listing,
        ]
        if ftp_anon.get('listingTruncated'):
            response_lines.append('... [bounded listing truncated]')
        response = '\n'.join(response_lines)
        transcript = [{
            'label': 'nmap-ftp-anon-read-only',
            'request': request,
            'response': response,
        }]

        return {
            'template-id': 'xasm-ftp-anonymous-access',
            'templateID': 'xasm-ftp-anonymous-access',
            'matched-at': endpoint,
            'matched': endpoint,
            'host': endpoint,
            'matcher-name': 'ftp-anon-nse-positive',
            'extracted-results': [
                'FTP reply code 230',
                f"bounded listing entries: {len(listing)}",
            ],
            'request': request,
            'response': response,
            'observedTranscript': transcript,
            'evidence': {
                'request': request,
                'response': response,
                'observedTranscript': transcript,
                'fallback': False,
                'verified': True,
                'proofLevel': 'runtime-read-only',
                'protocol': 'ftp',
                'port': port,
                'replyCode': 230,
                'listing': listing,
                'listingTruncated': bool(ftp_anon.get('listingTruncated')),
            },
            'info': {
                'name': 'Anonymous FTP Access Enabled',
                'severity': 'medium',
                'description': (
                    'The FTP service accepts an anonymous login and exposes a directory listing '
                    'without an authenticated account.'
                ),
                'remediation': (
                    'Disable anonymous FTP access unless it is explicitly required. If public '
                    'downloads are intended, expose only the minimum read-only content and prevent '
                    'uploads or access to sensitive files.'
                ),
                'classification': {
                    'cwe-id': ['CWE-284'],
                },
            },
        }


def get_tool():
    return NmapServiceScanTool()
