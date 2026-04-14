"""
Waybackurls URL Discovery Tool
Discovers historical URLs from the Wayback Machine for a given domain.
This is a DISCOVERY tool - returns discovered URLs, not vulnerability findings.
Useful for finding hidden endpoints, old parameters, and forgotten pages.
"""

import asyncio
import json
import time
from plugin_interface import ToolPlugin
from typing import Dict, Any


class WaybackurlsDiscoverTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "waybackurls:discover"

    @property
    def description(self) -> str:
        return "Discovers historical URLs from the Wayback Machine for a domain. Returns a deduplicated list of URLs found in web archives - useful for finding hidden endpoints, old parameters, and forgotten pages."

    @property
    def schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "Single domain to discover URLs for (e.g., example.com)"
                },
                "domains": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Multiple domains to discover URLs for (alternative to domain)"
                },
                "getDates": {
                    "type": "boolean",
                    "description": "Include the date each URL was archived",
                    "default": False
                },
                "noSubs": {
                    "type": "boolean",
                    "description": "Exclude subdomains from results (only return URLs for the exact domain)",
                    "default": False
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
            "domain": ["osint", "web"],
            "input_type": ["domain"],
            "output_type": ["urls"],
            "chainable_after": [],
            "chainable_before": ["katana:", "nuclei:", "sqlmap:"],
        }

    # Maximum URLs to return to prevent payload bloat
    MAX_URLS = 10000

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
                    'urls': [],
                    'targets': [],
                    'domain': None,
                    'total': 0,
                    'tool': 'waybackurls',
                    'scan_type': 'discover'
                },
                'raw_output': ''
            }

        get_dates = parameters.get('getDates', False)
        no_subs = parameters.get('noSubs', False)

        # If multiple domains, enumerate each and aggregate
        if len(domains_list) > 1:
            return await self._discover_multiple(domains_list, get_dates, no_subs, agent)

        # Single domain discovery
        domain = domains_list[0]
        return await self._discover_single(domain, get_dates, no_subs, agent)

    async def _discover_single(self, domain: str, get_dates: bool, no_subs: bool, agent) -> Dict[str, Any]:
        """Discover historical URLs for a single domain."""
        start_time = time.time()

        if agent:
            agent.report_progress(
                current_operation="Starting waybackurls discovery",
                current_target=domain,
                items_processed=0,
                total_items=None
            )

        # waybackurls reads domains from stdin
        # Build command flags
        flags = []
        if get_dates:
            flags.append("-dates")
        if no_subs:
            flags.append("-no-subs")

        cmd_display = f"waybackurls {' '.join(flags)}".strip() + f" < (stdin: {domain})"
        print(f"[Waybackurls] Starting URL discovery for {domain}")
        print(f"[Waybackurls] Command: {cmd_display}")
        print(f"[Waybackurls] Options: getDates={get_dates}, noSubs={no_subs}")

        try:
            # SEC-001 fix: Use create_subprocess_exec to avoid shell injection.
            # Domain is piped via stdin instead of interpolated into a shell command.
            process = await asyncio.create_subprocess_exec(
                "waybackurls", *flags,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            # Write domain to stdin and close it so waybackurls starts processing
            process.stdin.write(domain.encode('utf-8') + b'\n')
            await process.stdin.drain()
            process.stdin.close()
            await process.stdin.wait_closed()

            urls_set = set()
            raw_lines = []
            last_progress_update = time.time()
            progress_update_interval = 5.0
            line_buffer = b""

            try:
                async def read_output():
                    nonlocal line_buffer, last_progress_update

                    async def read_stderr():
                        """Read stderr in parallel"""
                        while True:
                            chunk = await process.stderr.read(1024)
                            if not chunk:
                                break
                            stderr_line = chunk.decode('utf-8', errors='replace').strip()
                            if stderr_line:
                                print(f"[Waybackurls] stderr: {stderr_line}")

                    stderr_task = asyncio.create_task(read_stderr())

                    try:
                        while True:
                            chunk = await process.stdout.read(4096)
                            if not chunk:
                                break

                            line_buffer += chunk
                            while b'\n' in line_buffer:
                                line, line_buffer = line_buffer.split(b'\n', 1)
                                line_str = line.decode('utf-8', errors='replace').strip().replace('\0', '')

                                if line_str:
                                    raw_lines.append(line_str)
                                    # Extract URL (may have date prefix if getDates is set)
                                    url = line_str
                                    if get_dates and ' ' in line_str:
                                        # Format: "YYYY-MM-DDTHH:MM:SSZ url"
                                        parts = line_str.split(' ', 1)
                                        if len(parts) == 2:
                                            url = parts[1].strip()

                                    if url and url.startswith(('http://', 'https://')):
                                        urls_set.add(url)

                                    # Progress reporting every 500 URLs
                                    if len(urls_set) % 500 == 0 and len(urls_set) > 0:
                                        current_time = time.time()
                                        if (current_time - last_progress_update) >= progress_update_interval:
                                            if agent:
                                                agent.report_progress(
                                                    current_operation="Discovering URLs from Wayback Machine",
                                                    current_target=domain,
                                                    items_processed=len(urls_set),
                                                    total_items=None
                                                )
                                                agent.append_output(
                                                    f"[Waybackurls] Progress: {len(urls_set)} unique URLs discovered..."
                                                )
                                            last_progress_update = current_time

                                    # Cap at max to prevent memory issues
                                    if len(urls_set) >= self.MAX_URLS:
                                        print(f"[Waybackurls] Reached {self.MAX_URLS} URL cap, stopping collection")
                                        if agent:
                                            agent.append_output(
                                                f"[Waybackurls] Reached {self.MAX_URLS} URL cap"
                                            )
                                        # BUG-002 fix: Kill process to prevent zombie
                                        process.kill()
                                        break

                            if len(urls_set) >= self.MAX_URLS:
                                break

                    finally:
                        stderr_task.cancel()
                        try:
                            await stderr_task
                        except asyncio.CancelledError:
                            pass

                    await process.wait()

                await asyncio.wait_for(read_output(), timeout=300)  # 5 minutes

            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                elapsed = time.time() - start_time
                print(f"[Waybackurls] Timeout after {elapsed:.1f}s for {domain}")
                if agent:
                    agent.append_output(f"[Waybackurls] Timeout after {elapsed:.1f}s, returning {len(urls_set)} partial URLs")

                urls = sorted(list(urls_set))
                if len(urls) > self.MAX_URLS:
                    urls = urls[:self.MAX_URLS]

                raw_output = self._build_raw_output(raw_lines)

                return {
                    'success': False,
                    'error': f'Waybackurls timed out after 5 minutes for {domain}',
                    'output': {
                        'urls': urls,
                        'targets': urls,  # Alias for workflow chaining
                        'domain': domain,
                        'total': len(urls),
                        'tool': 'waybackurls',
                    'scan_type': 'discover',
                        'partial': True
                    },
                    'raw_output': raw_output
                }

            elapsed = time.time() - start_time
            urls = sorted(list(urls_set))

            # Cap at MAX_URLS
            total_discovered = len(urls)
            if len(urls) > self.MAX_URLS:
                urls = urls[:self.MAX_URLS]
                print(f"[Waybackurls] Capped URLs from {total_discovered} to {self.MAX_URLS}")

            print(f"[Waybackurls] Discovered {total_discovered} unique URLs for {domain} in {elapsed:.1f}s")

            if agent:
                agent.report_progress(
                    current_operation="Waybackurls discovery completed",
                    current_target=domain,
                    items_processed=len(urls),
                    total_items=len(urls)
                )
                agent.append_output(f"[Waybackurls] Discovered {total_discovered} unique URLs for {domain}")

            raw_output = self._build_raw_output(raw_lines)

            return {
                'success': True,
                'output': {
                    'urls': urls,
                    'targets': urls,   # Alias for workflow chaining (dalfox, nuclei, etc.)
                    'domain': domain,
                    'total': len(urls),
                    'tool': 'waybackurls',
                    'scan_type': 'discover'
                },
                'raw_output': raw_output
            }

        except FileNotFoundError:
            return {
                'success': False,
                'error': 'waybackurls not installed. Install with: go install github.com/tomnomnom/waybackurls@latest',
                'output': {
                    'urls': [],
                    'targets': [],
                    'domain': domain,
                    'total': 0,
                    'tool': 'waybackurls',
                    'scan_type': 'discover'
                },
                'raw_output': ''
            }
        except Exception as e:
            print(f"[Waybackurls] Exception: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'output': {
                    'urls': [],
                    'targets': [],
                    'domain': domain,
                    'total': 0,
                    'tool': 'waybackurls',
                    'scan_type': 'discover'
                },
                'raw_output': ''
            }

    async def _discover_multiple(self, domains_list: list, get_dates: bool, no_subs: bool, agent) -> Dict[str, Any]:
        """Discover historical URLs for multiple domains and aggregate results."""
        start_time = time.time()

        if agent:
            agent.report_progress(
                current_operation=f"Starting waybackurls discovery on {len(domains_list)} domains",
                current_target=domains_list[0],
                items_processed=0,
                total_items=len(domains_list)
            )
            agent.append_output(f"[Waybackurls] Discovering URLs for {len(domains_list)} domains")

        # Build command flags
        flags = []
        if get_dates:
            flags.append("-dates")
        if no_subs:
            flags.append("-no-subs")

        cmd_display = f"waybackurls {' '.join(flags)}".strip() + f" < (stdin: {len(domains_list)} domains)"
        print(f"[Waybackurls] Discovering URLs for {len(domains_list)} domains")
        print(f"[Waybackurls] Command: {cmd_display}")

        try:
            # SEC-001 fix: Use create_subprocess_exec to avoid shell injection.
            # Domains are piped via stdin instead of using cat with a temp file.
            process = await asyncio.create_subprocess_exec(
                "waybackurls", *flags,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            # Write all domains to stdin (one per line) and close it
            stdin_data = '\n'.join(domains_list).encode('utf-8') + b'\n'
            process.stdin.write(stdin_data)
            await process.stdin.drain()
            process.stdin.close()
            await process.stdin.wait_closed()

            urls_set = set()
            raw_lines = []
            line_buffer = b""
            last_progress_update = time.time()
            progress_update_interval = 5.0

            try:
                async def read_output():
                    nonlocal line_buffer, last_progress_update

                    async def read_stderr():
                        while True:
                            chunk = await process.stderr.read(1024)
                            if not chunk:
                                break
                            stderr_line = chunk.decode('utf-8', errors='replace').strip()
                            if stderr_line:
                                print(f"[Waybackurls] stderr: {stderr_line}")

                    stderr_task = asyncio.create_task(read_stderr())

                    try:
                        while True:
                            chunk = await process.stdout.read(4096)
                            if not chunk:
                                break

                            line_buffer += chunk
                            while b'\n' in line_buffer:
                                line, line_buffer = line_buffer.split(b'\n', 1)
                                line_str = line.decode('utf-8', errors='replace').strip().replace('\0', '')

                                if line_str:
                                    raw_lines.append(line_str)
                                    url = line_str
                                    if get_dates and ' ' in line_str:
                                        parts = line_str.split(' ', 1)
                                        if len(parts) == 2:
                                            url = parts[1].strip()

                                    if url and url.startswith(('http://', 'https://')):
                                        urls_set.add(url)

                                    # Progress reporting every 500 URLs
                                    if len(urls_set) % 500 == 0 and len(urls_set) > 0:
                                        current_time = time.time()
                                        if (current_time - last_progress_update) >= progress_update_interval:
                                            if agent:
                                                agent.report_progress(
                                                    current_operation="Discovering URLs from Wayback Machine",
                                                    current_target=f"{len(domains_list)} domains",
                                                    items_processed=len(urls_set),
                                                    total_items=None
                                                )
                                                agent.append_output(
                                                    f"[Waybackurls] Progress: {len(urls_set)} unique URLs discovered..."
                                                )
                                            last_progress_update = current_time

                                    if len(urls_set) >= self.MAX_URLS:
                                        print(f"[Waybackurls] Reached {self.MAX_URLS} URL cap, stopping collection")
                                        if agent:
                                            agent.append_output(
                                                f"[Waybackurls] Reached {self.MAX_URLS} URL cap"
                                            )
                                        # BUG-002 fix: Kill process to prevent zombie
                                        process.kill()
                                        break

                            if len(urls_set) >= self.MAX_URLS:
                                break

                    finally:
                        stderr_task.cancel()
                        try:
                            await stderr_task
                        except asyncio.CancelledError:
                            pass

                    await process.wait()

                # 5 minutes per domain, capped
                await asyncio.wait_for(read_output(), timeout=min(300 * len(domains_list), 3600))

            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                print(f"[Waybackurls] Timeout for multi-domain discovery")

                urls = sorted(list(urls_set))
                if len(urls) > self.MAX_URLS:
                    urls = urls[:self.MAX_URLS]

                raw_output = self._build_raw_output(raw_lines)

                return {
                    'success': False,
                    'error': f'Waybackurls timed out for {len(domains_list)} domains',
                    'output': {
                        'urls': urls,
                        'targets': urls,
                        'domain': ', '.join(domains_list),
                        'total': len(urls),
                        'tool': 'waybackurls',
                    'scan_type': 'discover',
                        'partial': True
                    },
                    'raw_output': raw_output
                }

            elapsed = time.time() - start_time
            urls = sorted(list(urls_set))

            total_discovered = len(urls)
            if len(urls) > self.MAX_URLS:
                urls = urls[:self.MAX_URLS]
                print(f"[Waybackurls] Capped URLs from {total_discovered} to {self.MAX_URLS}")

            print(f"[Waybackurls] Discovered {total_discovered} unique URLs across {len(domains_list)} domains in {elapsed:.1f}s")

            if agent:
                agent.report_progress(
                    current_operation="Waybackurls multi-domain discovery completed",
                    current_target=domains_list[0],
                    items_processed=len(domains_list),
                    total_items=len(domains_list)
                )
                agent.append_output(f"[Waybackurls] Discovered {total_discovered} unique URLs across {len(domains_list)} domains")

            raw_output = self._build_raw_output(raw_lines)

            return {
                'success': True,
                'output': {
                    'urls': urls,
                    'targets': urls,   # Alias for workflow chaining
                    'domain': ', '.join(domains_list),
                    'total': len(urls),
                    'tool': 'waybackurls',
                    'scan_type': 'discover'
                },
                'raw_output': raw_output
            }

        except FileNotFoundError:
            return {
                'success': False,
                'error': 'waybackurls not installed. Install with: go install github.com/tomnomnom/waybackurls@latest',
                'output': {
                    'urls': [],
                    'targets': [],
                    'domain': ', '.join(domains_list),
                    'total': 0,
                    'tool': 'waybackurls',
                    'scan_type': 'discover'
                },
                'raw_output': ''
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'output': {
                    'urls': [],
                    'targets': [],
                    'domain': ', '.join(domains_list),
                    'total': 0,
                    'tool': 'waybackurls',
                    'scan_type': 'discover'
                },
                'raw_output': ''
            }

    def _build_raw_output(self, raw_lines: list) -> str:
        """Build raw output string from collected lines, limited to 5MB"""
        if not raw_lines:
            return ""
        raw_output = '\n'.join(raw_lines)
        # Limit to 5MB to prevent 413 errors
        if len(raw_output) > 5 * 1024 * 1024:
            raw_output = '\n'.join(raw_lines[:1000]) + f"\n... (truncated, total {len(raw_lines)} lines)"
        return raw_output


def get_tool():
    return WaybackurlsDiscoverTool()
