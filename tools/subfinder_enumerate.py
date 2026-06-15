"""
Subfinder Subdomain Enumeration Tool
Discovers subdomains for a given domain using multiple passive sources.
This is a DISCOVERY tool - returns discovered subdomains, not findings.
"""

import asyncio
import json
import os
import time
from plugin_interface import ToolPlugin
from typing import Dict, Any


class SubfinderEnumerateTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "subfinder:enumerate"

    @property
    def description(self) -> str:
        return "Enumerates subdomains for a domain using passive sources (crt.sh, waybackarchive, etc.). Returns a deduplicated list of discovered subdomains."

    @property
    def schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "Single domain to enumerate subdomains for (e.g., example.com)"
                },
                "domains": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Multiple domains to enumerate (alternative to domain)"
                },
                "allSources": {
                    "type": "boolean",
                    "description": "Use all available sources for comprehensive enumeration (slower but more thorough)",
                    "default": False
                },
                "createAssets": {
                    "type": "boolean",
                    "description": "Create FQDN assets during ingestion. Set false when using a validation/promotion workflow.",
                    "default": True
                }
            },
            "oneOf": [
                {"required": ["domain"]},
                {"required": ["domains"]}
            ]
        }

    @property
    def metadata(self):
        return {
            "category": "recon",
            "phase": 1,
            "domain": ["dns"],
            "input_type": ["domain"],
            "output_type": ["domains"],
            "chainable_after": [],
            "chainable_before": ["system:dns_resolve", "httpx:probe"],
        }

    async def execute(self, parameters: Dict[str, Any]) -> Any:
        agent = parameters.get('_agent')

        # Resolve target domains
        domains_list = []
        if 'domains' in parameters and parameters['domains']:
            domains_param = parameters['domains']
            if isinstance(domains_param, str):
                try:
                    domains_list = json.loads(domains_param)
                except json.JSONDecodeError:
                    domains_list = [domains_param]
            elif isinstance(domains_param, list):
                domains_list = domains_param
            else:
                domains_list = [str(domains_param)]
        elif 'domain' in parameters and parameters['domain']:
            domains_list = [parameters['domain']]

        if not domains_list:
            return {
                'success': False,
                'error': 'Either domain or domains parameter is required',
                'output': {
                    'subdomains': [],
                    'domain': None,
                    'total': 0,
                    'sources': {},
                    'tool': 'subfinder',
                    'scan_type': 'enumerate'
                },
                'raw_output': ''
            }

        all_sources = parameters.get('allSources', False)
        create_assets = parameters.get('createAssets', True)

        # If multiple domains, enumerate each and aggregate
        if len(domains_list) > 1:
            return await self._enumerate_multiple(domains_list, all_sources, create_assets, agent)

        # Single domain enumeration
        domain = domains_list[0]
        return await self._enumerate_single(domain, all_sources, create_assets, agent)

    async def _enumerate_single(self, domain: str, all_sources: bool, create_assets: bool, agent) -> Dict[str, Any]:
        """Enumerate subdomains for a single domain."""
        start_time = time.time()

        if agent:
            agent.report_progress(
                current_operation="Starting subfinder enumeration",
                current_target=domain,
                items_processed=0,
                total_items=None
            )

        # Build command
        cmd = ['subfinder', '-d', domain, '-silent', '-json']
        if all_sources:
            cmd.append('-all')

        print(f"[Subfinder] Starting enumeration for {domain}")
        print(f"[Subfinder] Command: {' '.join(cmd)}")
        print(f"[Subfinder] All sources: {all_sources}")

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=300  # 5 minutes
                )
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                elapsed = time.time() - start_time
                print(f"[Subfinder] Timeout after {elapsed:.1f}s for {domain}")
                if agent:
                    agent.append_output(f"[Subfinder] Timeout after {elapsed:.1f}s for {domain}")
                return {
                    'success': False,
                    'error': f'Subfinder timed out after 5 minutes for {domain}',
                    'output': {
                        'subdomains': [],
                        'domain': domain,
                        'total': 0,
                        'sources': {},
                        'tool': 'subfinder',
                    'scan_type': 'enumerate'
                    },
                    'raw_output': ''
                }

            # Decode and sanitize
            stdout_text = stdout.decode('utf-8', errors='replace').replace('\0', '') if stdout else ''
            stderr_text = stderr.decode('utf-8', errors='replace').replace('\0', '') if stderr else ''

            return_code = process.returncode
            elapsed = time.time() - start_time

            print(f"[Subfinder] Completed in {elapsed:.1f}s (return code: {return_code})")
            print(f"[Subfinder] Stdout size: {len(stdout_text)} bytes")

            if return_code != 0 and not stdout_text:
                print(f"[Subfinder] Failed: {stderr_text[:500]}")
                return {
                    'success': False,
                    'error': stderr_text or 'Subfinder failed',
                    'output': {
                        'subdomains': [],
                        'domain': domain,
                        'total': 0,
                        'sources': {},
                        'tool': 'subfinder',
                    'scan_type': 'enumerate'
                    },
                    'raw_output': stderr_text
                }

            # Parse JSON output line by line
            subdomains_set = set()
            sources_count = {}
            parse_errors = 0

            for line in stdout_text.strip().split('\n'):
                if not line.strip():
                    continue
                try:
                    line = line.replace('\0', '')
                    data = json.loads(line)
                    host = data.get('host', '').strip().lower()
                    source = data.get('source', 'unknown')

                    if host:
                        subdomains_set.add(host)
                        sources_count[source] = sources_count.get(source, 0) + 1
                except json.JSONDecodeError:
                    parse_errors += 1
                    # Some lines might be plain text subdomains (non-JSON fallback)
                    clean_line = line.strip().lower()
                    if clean_line and '.' in clean_line and ' ' not in clean_line:
                        subdomains_set.add(clean_line)

            subdomains = sorted(list(subdomains_set))

            print(f"[Subfinder] Found {len(subdomains)} unique subdomains for {domain}")
            print(f"[Subfinder] Sources: {sources_count}")
            if parse_errors > 0:
                print(f"[Subfinder] Parse errors: {parse_errors}")

            if agent:
                agent.report_progress(
                    current_operation="Subfinder enumeration completed",
                    current_target=domain,
                    items_processed=len(subdomains),
                    total_items=len(subdomains)
                )
                agent.append_output(f"[Subfinder] Discovered {len(subdomains)} subdomains for {domain}")
                # Show top sources
                if sources_count:
                    top_sources = sorted(sources_count.items(), key=lambda x: x[1], reverse=True)[:5]
                    sources_str = ', '.join(f"{s}: {c}" for s, c in top_sources)
                    agent.append_output(f"[Subfinder] Top sources: {sources_str}")

            # Limit raw output size
            raw_output = stdout_text
            if len(raw_output) > 5 * 1024 * 1024:
                lines = raw_output.split('\n')
                raw_output = '\n'.join(lines[:1000]) + f"\n... (truncated, total {len(lines)} lines)"

            return {
                'success': True,
                'output': {
                    'subdomains': subdomains,
                    'targets': subdomains,  # Alias for workflow chaining (httpx, katana, etc.)
                    'domains': subdomains,  # Alias for tools expecting 'domains'
                    'domain': domain,
                    'total': len(subdomains),
                    'sources': sources_count,
                    'tool': 'subfinder',
                    'scan_type': 'enumerate',
                    'createAssets': create_assets,
                },
                'raw_output': raw_output
            }

        except FileNotFoundError:
            return {
                'success': False,
                'error': 'Subfinder not installed. Install with: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest',
                'output': {
                    'subdomains': [],
                    'domain': domain,
                    'total': 0,
                    'sources': {},
                    'tool': 'subfinder',
                    'scan_type': 'enumerate'
                },
                'raw_output': ''
            }
        except Exception as e:
            print(f"[Subfinder] Exception: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'output': {
                    'subdomains': [],
                    'domain': domain,
                    'total': 0,
                    'sources': {},
                    'tool': 'subfinder',
                    'scan_type': 'enumerate'
                },
                'raw_output': ''
            }

    async def _enumerate_multiple(self, domains_list: list, all_sources: bool, create_assets: bool, agent) -> Dict[str, Any]:
        """Enumerate subdomains for multiple domains and aggregate results."""
        start_time = time.time()

        if agent:
            agent.report_progress(
                current_operation=f"Starting subfinder enumeration on {len(domains_list)} domains",
                current_target=domains_list[0],
                items_processed=0,
                total_items=len(domains_list)
            )
            agent.append_output(f"[Subfinder] Enumerating subdomains for {len(domains_list)} domains")

        # Write domains to temp file
        domains_file = f"/tmp/subfinder_domains_{int(time.time())}.txt"
        with open(domains_file, 'w') as f:
            f.write('\n'.join(domains_list))

        cmd = ['subfinder', '-dL', domains_file, '-silent', '-json']
        if all_sources:
            cmd.append('-all')

        print(f"[Subfinder] Enumerating {len(domains_list)} domains")
        print(f"[Subfinder] Command: {' '.join(cmd)}")

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=min(300 * len(domains_list), 3600)  # 5 min per domain, capped at 1 hour
                )
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                print(f"[Subfinder] Timeout for multi-domain enumeration")
                # Clean up temp file
                if os.path.exists(domains_file):
                    os.remove(domains_file)
                return {
                    'success': False,
                    'error': f'Subfinder timed out for {len(domains_list)} domains',
                    'output': {
                        'subdomains': [],
                        'domain': domains_list[0],
                        'total': 0,
                        'sources': {},
                        'tool': 'subfinder',
                    'scan_type': 'enumerate'
                    },
                    'raw_output': ''
                }

            # Clean up temp file
            if os.path.exists(domains_file):
                os.remove(domains_file)

            stdout_text = stdout.decode('utf-8', errors='replace').replace('\0', '') if stdout else ''

            # Parse results
            subdomains_set = set()
            sources_count = {}

            for line in stdout_text.strip().split('\n'):
                if not line.strip():
                    continue
                try:
                    line = line.replace('\0', '')
                    data = json.loads(line)
                    host = data.get('host', '').strip().lower()
                    source = data.get('source', 'unknown')

                    if host:
                        subdomains_set.add(host)
                        sources_count[source] = sources_count.get(source, 0) + 1
                except json.JSONDecodeError:
                    clean_line = line.strip().lower()
                    if clean_line and '.' in clean_line and ' ' not in clean_line:
                        subdomains_set.add(clean_line)

            subdomains = sorted(list(subdomains_set))
            elapsed = time.time() - start_time

            print(f"[Subfinder] Found {len(subdomains)} unique subdomains across {len(domains_list)} domains in {elapsed:.1f}s")

            if agent:
                agent.report_progress(
                    current_operation="Subfinder multi-domain enumeration completed",
                    current_target=domains_list[0],
                    items_processed=len(domains_list),
                    total_items=len(domains_list)
                )
                agent.append_output(f"[Subfinder] Discovered {len(subdomains)} unique subdomains across {len(domains_list)} domains")

            raw_output = stdout_text
            if len(raw_output) > 5 * 1024 * 1024:
                lines = raw_output.split('\n')
                raw_output = '\n'.join(lines[:1000]) + f"\n... (truncated, total {len(lines)} lines)"

            return {
                'success': True,
                'output': {
                    'subdomains': subdomains,
                    'targets': subdomains,  # Alias for workflow chaining
                    'domains': subdomains,  # Alias for tools expecting 'domains'
                    'domain': ', '.join(domains_list),
                    'total': len(subdomains),
                    'sources': sources_count,
                    'tool': 'subfinder',
                    'scan_type': 'enumerate',
                    'createAssets': create_assets,
                },
                'raw_output': raw_output
            }

        except FileNotFoundError:
            if os.path.exists(domains_file):
                os.remove(domains_file)
            return {
                'success': False,
                'error': 'Subfinder not installed. Install with: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest',
                'output': {
                    'subdomains': [],
                    'domain': ', '.join(domains_list),
                    'total': 0,
                    'sources': {},
                    'tool': 'subfinder',
                    'scan_type': 'enumerate'
                },
                'raw_output': ''
            }
        except Exception as e:
            if os.path.exists(domains_file):
                os.remove(domains_file)
            return {
                'success': False,
                'error': str(e),
                'output': {
                    'subdomains': [],
                    'domain': ', '.join(domains_list),
                    'total': 0,
                    'sources': {},
                    'tool': 'subfinder',
                    'scan_type': 'enumerate'
                },
                'raw_output': ''
            }


def get_tool():
    return SubfinderEnumerateTool()
