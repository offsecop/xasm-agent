"""
DNS Resolution tool
Resolves FQDNs to IP addresses
"""

import asyncio
import ipaddress
import json
from plugin_interface import ToolPlugin
from typing import Dict, Any


class DNSResolveTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "system:dns_resolve"

    @property
    def description(self) -> str:
        return "Resolves FQDN to IP addresses using dig"

    @property
    def schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "FQDN to resolve"
                },
                "targets": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Multiple FQDNs to resolve (alternative to target, for workflow chaining)"
                },
                "maxTargets": {
                    "type": "integer",
                    "description": "Maximum number of targets to resolve from array (default: 50)",
                    "default": 50
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
            "category": "discovery",
            "phase": 2,
            "domain": ["dns"],
            "input_type": ["fqdn"],
            "output_type": ["ips"],
            "chainable_after": ["subfinder:"],
            "chainable_before": ["nmap:", "httpx:probe", "shodan:host_lookup"],
        }

    async def execute(self, parameters: Dict[str, Any]) -> Any:
        agent = parameters.get('_agent')

        # Resolve targets list
        targets_list = self._resolve_targets(parameters)
        if not targets_list:
            # If targets was explicitly provided as empty (e.g., from a previous step
            # that found nothing), return success with 0 results instead of erroring.
            has_explicit_targets = 'targets' in parameters or 'target' in parameters
            if has_explicit_targets:
                print("[DNS Resolve] Received empty targets list from previous step — nothing to resolve")
                return {
                    'success': True,
                    'output': {
                        'results': [],
                        'ips': [],
                        'targets': [],
                        'total': 0,
                        'tool': 'dig',
                        'scan_type': 'dns_resolve'
                    },
                    'raw_output': ''
                }
            return {
                'success': False,
                'error': 'Either target or targets parameter is required',
                'output': {
                    'results': [],
                    'ips': [],
                    'targets': [],
                    'total': 0,
                    'tool': 'dig',
                    'scan_type': 'dns_resolve'
                },
                'raw_output': ''
            }

        # Apply maxTargets limit
        max_targets = parameters.get('maxTargets', 50)
        if len(targets_list) > max_targets:
            print(f"[DNS Resolve] Limiting {len(targets_list)} targets to {max_targets}")
            targets_list = targets_list[:max_targets]

        if agent:
            agent.report_progress(
                current_operation=f"Starting DNS resolution for {len(targets_list)} target(s)",
                current_target=targets_list[0],
                items_processed=0,
                total_items=len(targets_list)
            )

        all_results = []
        all_ips = []
        all_raw = []

        for idx, target in enumerate(targets_list):
            try:
                # Resolve A records (IPv4)
                process = await asyncio.create_subprocess_exec(
                    'dig', '+short', target,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )

                try:
                    stdout, stderr = await asyncio.wait_for(
                        process.communicate(),
                        timeout=30
                    )
                except asyncio.TimeoutError:
                    process.kill()
                    await process.wait()
                    all_results.append({'target': target, 'ips': [], 'error': 'timeout'})
                    continue

                stdout_text = stdout.decode('utf-8', errors='replace') if stdout else ''

                # Resolve AAAA records (IPv6)
                aaaa_text = ''
                try:
                    aaaa_process = await asyncio.create_subprocess_exec(
                        'dig', '+short', 'AAAA', target,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    aaaa_stdout, _ = await asyncio.wait_for(
                        aaaa_process.communicate(),
                        timeout=30
                    )
                    aaaa_text = aaaa_stdout.decode('utf-8', errors='replace') if aaaa_stdout else ''
                except (asyncio.TimeoutError, Exception):
                    pass

                combined_text = stdout_text + '\n' + aaaa_text
                all_raw.append(f"# {target}\n{combined_text}")

                if process.returncode != 0:
                    stderr_text = stderr.decode('utf-8', errors='replace') if stderr else ''
                    all_results.append({'target': target, 'ips': [], 'error': stderr_text})
                    continue

                # Parse IPs from both A and AAAA results
                ips = [line.strip() for line in combined_text.split('\n') if line.strip()]
                # Filter out non-IP results (like CNAME records)
                ips = [ip for ip in ips if self._is_ip(ip)]
                # Deduplicate while preserving order
                seen = set()
                unique_ips = []
                for ip in ips:
                    if ip not in seen:
                        seen.add(ip)
                        unique_ips.append(ip)
                ips = unique_ips
                all_ips.extend(ips)

                all_results.append({
                    'target': target,
                    'ips': ips
                })

                if agent:
                    agent.report_progress(
                        current_operation="DNS resolution",
                        current_target=target,
                        items_processed=idx + 1,
                        total_items=len(targets_list)
                    )

            except FileNotFoundError:
                return {
                    'success': False,
                    'error': 'dig command not found',
                    'output': {
                        'results': [],
                        'ips': [],
                        'targets': [],
                        'total': 0,
                        'tool': 'dig',
                        'scan_type': 'dns_resolve'
                    },
                    'raw_output': ''
                }
            except Exception as e:
                all_results.append({'target': target, 'ips': [], 'error': str(e)})

        if agent:
            agent.report_progress(
                current_operation="DNS resolution completed",
                current_target=targets_list[0],
                items_processed=len(targets_list),
                total_items=len(targets_list)
            )
            agent.append_output(f"[DNS Resolve] Resolved {len(targets_list)} target(s), found {len(all_ips)} IP(s)")

        raw_output = '\n'.join(all_raw)

        return {
            'success': True,
            'output': {
                'results': all_results,
                'ips': all_ips,
                'targets': all_ips,  # Alias for chaining to nmap/httpx
                'total': len(all_ips),
                'tool': 'dig',
                'scan_type': 'dns_resolve'
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

    def _is_ip(self, value: str) -> bool:
        """Check if value is an IP address (IPv4 or IPv6)"""
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False


def get_tool():
    return DNSResolveTool()
