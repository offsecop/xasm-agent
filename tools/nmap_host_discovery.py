"""
Nmap Host Discovery Tool
Discovers live hosts in a network range
"""

import asyncio
import json
import xml.etree.ElementTree as ET
from plugin_interface import ToolPlugin
from typing import Dict, Any

from lib.wrapper_helpers import resolve_targets as _resolve_targets


class NmapHostDiscoveryTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "nmap:host_discovery"

    @property
    def description(self) -> str:
        return "Discovers live hosts in a network range using Nmap ping scan"

    @property
    def schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Network range in CIDR notation (e.g., 192.168.1.0/24)"
                },
                "targets": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Multiple network ranges to scan (alternative to target, for workflow chaining)"
                },
                "maxTargets": {
                    "type": "integer",
                    "description": "Maximum number of targets to scan from array (default: 20)",
                    "default": 20
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
            "category": "enumeration",
            "phase": 3,
            "domain": ["infra"],
            "input_type": ["ip", "hostname"],
            "output_type": ["ips", "ports"],
            "chainable_after": ["system:dns_resolve", "subfinder:"],
            "chainable_before": ["nmap:service_scan", "httpx:probe"],
        }

    async def execute(self, parameters: Dict[str, Any]) -> Any:
        agent = parameters.get('_agent')

        # Resolve targets list
        targets_list = _resolve_targets(parameters)
        if not targets_list:
            return {
                'success': False,
                'error': 'Either target or targets parameter is required',
                'output': {
                    'liveHosts': [],
                    'targets': [],
                    'totalHosts': 0,
                    'tool': 'nmap',
                    'scan_type': 'host_discovery'
                },
                'raw_output': ''
            }

        # Apply maxTargets limit
        max_targets = parameters.get('maxTargets', 20)
        if len(targets_list) > max_targets:
            print(f"[Nmap Host Discovery] Limiting {len(targets_list)} targets to {max_targets}")
            targets_list = targets_list[:max_targets]

        if agent:
            agent.report_progress(
                current_operation=f"Starting host discovery on {len(targets_list)} target(s)",
                current_target=targets_list[0],
                items_processed=0,
                total_items=len(targets_list)
            )

        all_live_hosts = []
        all_raw = []

        for idx, target in enumerate(targets_list):
            try:
                process = await asyncio.create_subprocess_exec(
                    'nmap', '-sn', '-n', target, '-oX', '-',
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )

                try:
                    stdout, stderr = await asyncio.wait_for(
                        process.communicate(),
                        timeout=300  # 5 minutes max per target
                    )
                except asyncio.TimeoutError:
                    process.kill()
                    await process.wait()
                    if agent:
                        agent.append_output(f"[Nmap Host Discovery] Timeout on {target}")
                    continue

                stdout_text = stdout.decode('utf-8', errors='replace') if stdout else ''
                all_raw.append(stdout_text)

                if process.returncode != 0:
                    stderr_text = stderr.decode('utf-8', errors='replace') if stderr else ''
                    print(f"[Nmap Host Discovery] Error scanning {target}: {stderr_text[:200]}")
                    continue

                # Parse XML output
                live_hosts = self._parse_nmap_output(stdout_text)
                all_live_hosts.extend(live_hosts)

                if agent:
                    agent.report_progress(
                        current_operation="Host discovery",
                        current_target=target,
                        items_processed=idx + 1,
                        total_items=len(targets_list)
                    )
                    agent.append_output(f"[Nmap Host Discovery] {target}: {len(live_hosts)} live hosts")

            except FileNotFoundError:
                return {
                    'success': False,
                    'error': 'Nmap not installed',
                    'output': {
                        'liveHosts': [],
                        'targets': [],
                        'totalHosts': 0,
                        'tool': 'nmap',
                        'scan_type': 'host_discovery'
                    },
                    'raw_output': ''
                }
            except Exception as e:
                print(f"[Nmap Host Discovery] Error on {target}: {e}")

        if agent:
            agent.report_progress(
                current_operation="Host discovery completed",
                current_target=targets_list[0],
                items_processed=len(targets_list),
                total_items=len(targets_list)
            )
            agent.append_output(f"[Nmap Host Discovery] Found {len(all_live_hosts)} total live hosts")

        # Build targets array for chaining (IP addresses of live hosts)
        live_ips = [h['ip'] for h in all_live_hosts if h.get('ip')]

        raw_output = '\n'.join(all_raw)
        if len(raw_output) > 5 * 1024 * 1024:
            raw_output = raw_output[:5 * 1024 * 1024] + "\n... (truncated)"

        return {
            'success': True,
            'output': {
                'liveHosts': all_live_hosts,
                'targets': live_ips,  # Alias for chaining to nmap:service_scan, httpx:probe
                'totalHosts': len(all_live_hosts),
                'tool': 'nmap',
                'scan_type': 'host_discovery'
            },
            'raw_output': raw_output
        }

    def _parse_nmap_output(self, xml_output: str) -> list:
        """Parse Nmap XML output to extract live hosts"""
        live_hosts = []

        try:
            root = ET.fromstring(xml_output)

            for host in root.findall('.//host'):
                status = host.find('status')
                if status is not None and status.get('state') == 'up':
                    address = host.find('address')
                    if address is not None:
                        ip = address.get('addr')
                        live_hosts.append({
                            'ip': ip,
                            'status': 'up'
                        })
        except ET.ParseError as e:
            print(f"Error parsing Nmap XML: {e}")

        return live_hosts


def get_tool():
    return NmapHostDiscoveryTool()
