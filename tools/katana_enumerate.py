"""
Katana URL Enumeration Tool
Enumerates web application URLs and endpoints (lighter crawl)
"""

import asyncio
import json
from plugin_interface import ToolPlugin
from typing import Dict, Any
from tools._katana_common import add_katana_options, extend_katana_schema, get_auth_cookie, get_headers_file

from lib.wrapper_helpers import resolve_targets as _resolve_targets


class KatanaEnumerateTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "katana:enumerate"

    @property
    def description(self) -> str:
        return "Enumerates web application URLs and endpoints using Katana (quick enumeration mode). Supports authenticated crawling with cookies/headers."

    @property
    def schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": extend_katana_schema({
                "target": {
                    "type": "string",
                    "description": "Base URL to enumerate (e.g., http://example.com)"
                },
                "targets": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Multiple target URLs to enumerate (alternative to target, for workflow chaining)"
                },
                "depth": {
                    "type": "integer",
                    "description": "Enumeration depth",
                    "default": 2
                },
                "maxTargets": {
                    "type": "integer",
                    "description": "Maximum number of targets to enumerate from array (default: 10)",
                    "default": 10
                },
                "headers_file": {
                    "type": "string",
                    "description": "Path to headers file with Cookie header for authenticated crawling (e.g., /tmp/headers.txt)"
                },
                "cookie": {
                    "type": "string",
                    "description": "Cookie header value for direct injection (alternative to headers_file)"
                }
            }),
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
            "domain": ["web"],
            "input_type": ["url"],
            "output_type": ["urls"],
            "chainable_after": ["httpx:probe"],
            "chainable_before": ["nuclei:", "sqlmap:", "dalfox:", "gowitness:"],
        }

    async def execute(self, parameters: Dict[str, Any]) -> Any:
        depth = parameters.get('depth', 2)
        headers_file = get_headers_file(parameters)
        cookie = get_auth_cookie(parameters)
        agent = parameters.get('_agent')

        # Extract exclusion and rate limiting
        from tools._scope_utils import extract_exclusion_patterns, extract_rate_limit, filter_excluded_urls
        exclusion_url_patterns = extract_exclusion_patterns(parameters)
        rate_limit_config = extract_rate_limit(parameters)

        # Resolve targets list
        targets_list = _resolve_targets(parameters)
        if not targets_list:
            return {
                'success': False,
                'error': 'Either target or targets parameter is required',
                'output': {
                    'endpoints': [],
                    'urls': [],
                    'targets': [],
                    'totalEndpoints': 0,
                    'tool': 'katana',
                    'scan_type': 'enumerate'
                },
                'raw_output': ''
            }

        # Apply maxTargets limit
        max_targets = parameters.get('maxTargets', 10)
        if len(targets_list) > max_targets:
            targets_list = targets_list[:max_targets]

        if agent:
            operation_desc = f"Starting Katana enumeration on {len(targets_list)} target(s) (depth {depth})"
            if headers_file or cookie:
                operation_desc += " [authenticated]"
            agent.report_progress(
                current_operation=operation_desc,
                current_target=targets_list[0],
                items_processed=0,
                total_items=len(targets_list)
            )

        all_endpoints = []
        all_urls = []
        urls_set = set()
        all_raw = []

        for idx, target in enumerate(targets_list):
            try:
                # Build Katana command with optional authentication
                cmd = ['katana', '-u', target, '-d', str(depth), '-jsonl', '-silent', '-nc', '-no-scope']
                cmd = add_katana_options(cmd, parameters, rate_limit_config)

                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )

                try:
                    stdout, stderr = await asyncio.wait_for(
                        process.communicate(),
                        timeout=180  # 3 minutes max per target
                    )
                except asyncio.TimeoutError:
                    process.kill()
                    await process.wait()
                    if agent:
                        agent.append_output(f"[Katana Enumerate] Timeout on {target}")
                    continue

                stdout_text = stdout.decode('utf-8', errors='replace').replace('\0', '') if stdout else ''
                all_raw.append(f"# {target}\n{stdout_text}")

                if process.returncode != 0 and not stdout_text:
                    stderr_text = stderr.decode('utf-8', errors='replace') if stderr else ''
                    continue

                # Parse JSON output (one JSON object per line)
                target_endpoints = []
                for line in stdout_text.strip().split('\n'):
                    if line:
                        try:
                            data = json.loads(line)
                            request = data.get('request', {})
                            response = data.get('response', {})
                            endpoint_url = request.get('endpoint')

                            target_endpoints.append({
                                'url': endpoint_url,
                                'method': request.get('method', 'GET'),
                                'status_code': response.get('status_code'),
                                'content_length': response.get('headers', {}).get('content_length'),
                            })

                            # Deduplicated flat URL list
                            if endpoint_url and endpoint_url not in urls_set:
                                urls_set.add(endpoint_url)
                                all_urls.append(endpoint_url)
                        except json.JSONDecodeError:
                            continue

                all_endpoints.extend(target_endpoints)

                if agent:
                    agent.report_progress(
                        current_operation="Katana enumeration",
                        current_target=target,
                        items_processed=idx + 1,
                        total_items=len(targets_list)
                    )
                    agent.append_output(f"[Katana Enumerate] {target}: {len(target_endpoints)} endpoints")

            except FileNotFoundError:
                return {
                    'success': False,
                    'error': 'Katana not installed',
                    'output': {
                        'endpoints': [],
                        'urls': [],
                        'targets': [],
                        'totalEndpoints': 0,
                        'tool': 'katana',
                        'scan_type': 'enumerate'
                    },
                    'raw_output': ''
                }
            except Exception as e:
                pass

        # Apply exclusion filtering to all discovered URLs
        if exclusion_url_patterns:
            all_urls = filter_excluded_urls(all_urls, exclusion_url_patterns, "Katana Enumerate")
            filtered_set = set(all_urls)
            all_endpoints = [ep for ep in all_endpoints if ep.get('url') in filtered_set]

        # Report completion
        if agent:
            agent.report_progress(
                current_operation="Katana enumeration completed",
                current_target=targets_list[0],
                items_processed=len(targets_list),
                total_items=len(targets_list)
            )
            agent.append_output(f"[Katana Enumerate] Total: {len(all_endpoints)} endpoints, {len(all_urls)} unique URLs")

        raw_output = '\n'.join(all_raw)
        if len(raw_output) > 5 * 1024 * 1024:
            raw_output = raw_output[:5 * 1024 * 1024] + "\n... (truncated)"

        return {
            'success': True,
            'output': {
                'endpoints': all_endpoints,
                'urls': all_urls,
                'targets': all_urls,  # Alias for chaining to nuclei, dalfox, etc.
                'totalEndpoints': len(all_endpoints),
                'tool': 'katana',
                'scan_type': 'enumerate'
            },
            'raw_output': raw_output
        }

def get_tool():
    return KatanaEnumerateTool()
