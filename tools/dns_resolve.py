"""
DNS Resolution tool
Resolves FQDNs to IP addresses
"""

import ipaddress
import json
from plugin_interface import ToolPlugin
from lib.dns_async import resolve_records
from typing import Dict, Any
from urllib.parse import urlparse


class DNSResolveTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "system:dns_resolve"

    @property
    def description(self) -> str:
        return "Resolves FQDN to IP addresses"

    @property
    def schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "FQDN, hostname, URL, or host:port value to resolve"
                },
                "hostname": {
                    "type": "string",
                    "description": "Hostname alias for target"
                },
                "host": {
                    "type": "string",
                    "description": "Host alias for target"
                },
                "domain": {
                    "type": "string",
                    "description": "Domain alias for target"
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
                {"required": ["targets"]},
                {"required": ["hostname"]},
                {"required": ["host"]},
                {"required": ["domain"]}
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
            has_explicit_targets = any(k in parameters for k in ('targets', 'target', 'hostname', 'host', 'domain'))
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
                # Resolve A records (IPv4) — UDP with TCP fallback for
                # TCP-only / UDP-blocked resolver environments (use-vc).
                stdout_text, stderr_text, a_returncode = await self._dig_short(
                    target, timeout=30
                )
                if stderr_text == 'timeout' and not stdout_text.strip():
                    all_results.append({'target': target, 'ips': [], 'error': 'timeout'})
                    continue

                # Resolve AAAA records (IPv6) — best effort, same TCP fallback
                aaaa_text = ''
                try:
                    aaaa_text, _, _ = await self._dig_short(target, 'AAAA', timeout=30)
                except Exception:
                    pass

                combined_text = stdout_text + '\n' + aaaa_text
                all_raw.append(f"# {target}\n{combined_text}")

                if a_returncode != 0 and not stdout_text.strip():
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
        """Resolve target/targets parameter into a list.

        Intentionally diverges from `lib.wrapper_helpers.resolve_targets`: this
        tool accepts `target`, `hostname`, `host`, and `domain` keys (the canonical
        helper only accepts `target`), and applies `_normalize_hostname` to every
        result. Kept local for that reason — do not consolidate.
        """
        if 'targets' in parameters and parameters['targets']:
            targets_param = parameters['targets']
            if isinstance(targets_param, str):
                try:
                    targets = json.loads(targets_param)
                except json.JSONDecodeError:
                    targets = [targets_param]
            elif isinstance(targets_param, list):
                targets = targets_param
            else:
                targets = [str(targets_param)]
            return [self._normalize_hostname(str(t)) for t in targets if str(t).strip()]
        for key in ('target', 'hostname', 'host', 'domain'):
            if key in parameters and parameters[key]:
                return [self._normalize_hostname(str(parameters[key]))]
        return []

    def _normalize_hostname(self, raw_target: str) -> str:
        target = raw_target.strip()
        if not target:
            return raw_target
        try:
            parsed = urlparse(target if '://' in target else f'//{target}', scheme='http')
            if parsed.hostname:
                return parsed.hostname
        except ValueError:
            pass
        if ':' in target and target.count(':') == 1:
            host_part, port_part = target.rsplit(':', 1)
            if port_part.isdigit():
                return host_part
        return target

    def _is_ip(self, value: str) -> bool:
        """Check if value is an IP address (IPv4 or IPv6)"""
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    async def _dig_short(self, target, rrtype=None, timeout=30):
        """Resolve a name in-process (dnspython) — NO ``dig`` subprocess.

        Mirrors the prior ``dig +short`` contract, returning
        ``(stdout_text, stderr_text, returncode)`` so callers are unchanged.
        A non-existent name (NXDOMAIN) is an empty answer with rc 0 (not an
        error); only a resolver failure (SERVFAIL/timeout) returns rc 1. The
        shared resolver does the UDP-first/TCP-fallback for UDP-blocked hosts
        (see ``lib.dns_async``). ``timeout`` is accepted for call-site
        compatibility; the resolver enforces its own per-query lifetime.
        """
        records, status = await resolve_records(target, (rrtype or 'A'))
        if status in ('NOERROR', 'NXDOMAIN'):
            return '\n'.join(records), '', 0
        return '', 'timeout', 1


def get_tool():
    return DNSResolveTool()
