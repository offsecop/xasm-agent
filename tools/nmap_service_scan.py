"""
Nmap Service Scan Tool
Performs service and version detection on a specific port
"""

import asyncio
import json
import xml.etree.ElementTree as ET
from plugin_interface import ToolPlugin
from typing import Dict, Any


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
                    "description": "IP address to scan"
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
        port = parameters.get('port', 80)

        # Resolve targets list
        targets_list = self._resolve_targets(parameters)
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
                'scan_type': 'service_scan'
            },
            'raw_output': raw_output
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
                    break
        except ET.ParseError as e:
            print(f"Error parsing Nmap XML: {e}")

        return service_info


def get_tool():
    return NmapServiceScanTool()
