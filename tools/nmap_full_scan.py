"""
Nmap Full Port + Service Scan Tool
Scans all 65535 TCP ports on a target with service version detection
"""

import asyncio
import json
import xml.etree.ElementTree as ET
from plugin_interface import ToolPlugin
from typing import Dict, Any

from lib.wrapper_helpers import resolve_targets as _resolve_targets


class NmapFullScanTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "nmap:full_scan"

    @property
    def description(self) -> str:
        return "Scans all 65535 TCP ports with service version detection (-sV) using Nmap"

    @property
    def schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "IP address to scan"
                },
                "targets": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Multiple IP addresses to scan (alternative to target, for workflow chaining)"
                },
                "maxTargets": {
                    "type": "integer",
                    "description": "Maximum number of targets to scan from array (default: 5)",
                    "default": 5
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
            "output_type": ["ports", "services"],
            "chainable_after": ["system:dns_resolve", "subfinder:"],
            "chainable_before": ["nuclei:", "testssl:", "httpx:probe"],
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
                    'results': [],
                    'openPorts': [],
                    'targets': [],
                    'totalPorts': 0,
                    'tool': 'nmap',
                    'scan_type': 'full_scan'
                },
                'raw_output': ''
            }

        # Apply maxTargets limit (low default since full scan is expensive)
        max_targets = parameters.get('maxTargets', 5)
        if len(targets_list) > max_targets:
            print(f"[Nmap Full Scan] Limiting {len(targets_list)} targets to {max_targets}")
            targets_list = targets_list[:max_targets]

        if agent:
            agent.report_progress(
                current_operation=f"Starting full port scan on {len(targets_list)} target(s)",
                current_target=targets_list[0],
                items_processed=0,
                total_items=len(targets_list)
            )

        all_open_ports = []
        all_results = []
        all_raw = []

        for idx, target in enumerate(targets_list):
            try:
                process = await asyncio.create_subprocess_exec(
                    'nmap', '-Pn', '-sV', '-p-', '--min-rate', '1000', target, '-oX', '-',
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )

                try:
                    stdout, stderr = await asyncio.wait_for(
                        process.communicate(),
                        timeout=900  # 15 minutes max per target
                    )
                except asyncio.TimeoutError:
                    process.kill()
                    await process.wait()
                    if agent:
                        agent.append_output(f"[Nmap Full Scan] Timeout on {target}")
                    all_results.append({'target': target, 'openPorts': [], 'error': 'timeout'})
                    continue

                stdout_text = stdout.decode('utf-8', errors='replace') if stdout else ''
                all_raw.append(stdout_text)

                if process.returncode != 0:
                    stderr_text = stderr.decode('utf-8', errors='replace') if stderr else ''
                    all_results.append({'target': target, 'openPorts': [], 'error': stderr_text[:200]})
                    continue

                # Parse XML output
                open_ports = self._parse_nmap_output(stdout_text)
                all_open_ports.extend(open_ports)
                all_results.append({
                    'target': target,
                    'openPorts': open_ports,
                    'totalPorts': len(open_ports)
                })

                if agent:
                    agent.report_progress(
                        current_operation="Full port scan",
                        current_target=target,
                        items_processed=idx + 1,
                        total_items=len(targets_list)
                    )
                    agent.append_output(f"[Nmap Full Scan] {target}: {len(open_ports)} open ports")

            except FileNotFoundError:
                return {
                    'success': False,
                    'error': 'Nmap not installed',
                    'output': {
                        'results': [],
                        'openPorts': [],
                        'targets': [],
                        'totalPorts': 0,
                        'tool': 'nmap',
                        'scan_type': 'full_scan'
                    },
                    'raw_output': ''
                }
            except Exception as e:
                all_results.append({'target': target, 'openPorts': [], 'error': str(e)})

        if agent:
            agent.report_progress(
                current_operation="Full port scan completed",
                current_target=targets_list[0],
                items_processed=len(targets_list),
                total_items=len(targets_list)
            )
            agent.append_output(f"[Nmap Full Scan] Total: {len(all_open_ports)} open ports across {len(targets_list)} target(s)")

        raw_output = '\n'.join(all_raw)
        if len(raw_output) > 5 * 1024 * 1024:
            raw_output = raw_output[:5 * 1024 * 1024] + "\n... (truncated)"

        return {
            'success': True,
            'output': {
                'results': all_results,
                'openPorts': all_open_ports,
                'targets': targets_list,
                'totalPorts': len(all_open_ports),
                'tool': 'nmap',
                'scan_type': 'full_scan'
            },
            'raw_output': raw_output
        }

    def _parse_nmap_output(self, xml_output: str) -> list:
        """Parse Nmap XML output to extract open ports with service info"""
        open_ports = []

        try:
            root = ET.fromstring(xml_output)

            for port in root.findall('.//port'):
                state = port.find('state')
                if state is not None and state.get('state') == 'open':
                    port_id = port.get('portid')
                    protocol = port.get('protocol')

                    # Extract service information
                    service_elem = port.find('service')
                    service_info = {}
                    if service_elem is not None:
                        service_info = {
                            'name': service_elem.get('name'),
                            'product': service_elem.get('product'),
                            'version': service_elem.get('version'),
                            'extrainfo': service_elem.get('extrainfo')
                        }

                    port_data = {
                        'port': int(port_id),
                        'protocol': protocol,
                        'state': 'open'
                    }

                    # Add service info if available
                    if service_info.get('name'):
                        port_data['service'] = service_info

                    open_ports.append(port_data)
        except ET.ParseError as e:
            print(f"Error parsing Nmap XML: {e}")

        return open_ports


def get_tool():
    return NmapFullScanTool()
