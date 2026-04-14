"""
Arjun Parameter Discovery Tool
Discovers hidden GET/POST parameters on web endpoints using Arjun
Best for: Finding injectable parameters missed by crawlers
"""

import subprocess
import asyncio
import json
import re
import time
import os
import tempfile
import uuid
from urllib.parse import urlparse, urlencode
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
from plugin_interface import ToolPlugin
from typing import Dict, Any


class ArjunParameterDiscoveryTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "arjun:parameter_discovery"

    @property
    def description(self) -> str:
        return "Discovers hidden GET/POST parameters on web endpoints using Arjun. Enriches URLs with discovered parameters for downstream injection testing."

    @property
    def schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Single URL to discover parameters on (e.g., http://example.com/page)"
                },
                "targets": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Multiple target URLs (alternative to target, for workflow chaining)"
                },
                "maxTargets": {
                    "type": "integer",
                    "description": "Maximum number of targets to process (default: 20)",
                    "default": 20
                },
                "methods": {
                    "type": "string",
                    "description": "HTTP methods to test for parameters (GET, POST, JSON). Default: GET",
                    "default": "GET"
                },
                "headers_file": {
                    "type": "string",
                    "description": "Path to headers file for authenticated scanning"
                },
                "cookie": {
                    "type": "string",
                    "description": "Cookie header value for authenticated scanning"
                },
                "stable": {
                    "type": "boolean",
                    "description": "Only return stable/confirmed parameters (default: true)",
                    "default": True
                },
                "threads": {
                    "type": "integer",
                    "description": "Number of concurrent threads for Arjun (default: 5)",
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
            "domain": ["web"],
            "input_type": ["url"],
            "output_type": ["urls_with_params"],
            "chainable_after": ["katana:", "dirsearch:", "ffuf:", "waybackurls:"],
            "chainable_before": ["nuclei:", "sqlmap:", "dalfox:", "commix:"],
        }

    async def execute(self, parameters: Dict[str, Any]) -> Any:
        # Support both 'target' (single) and 'targets' (array) parameters
        targets_list = []

        if 'targets' in parameters and parameters['targets']:
            targets_param = parameters['targets']
            if isinstance(targets_param, str):
                try:
                    targets_list = json.loads(targets_param)
                except json.JSONDecodeError:
                    targets_list = [targets_param]
            elif isinstance(targets_param, list):
                targets_list = targets_param
            else:
                targets_list = [str(targets_param)]
        elif 'target' in parameters and parameters['target']:
            targets_list = [parameters['target']]

        if not targets_list:
            return {
                'success': False,
                'error': 'Either target or targets parameter is required',
                'urls': [],
                'totalUrls': 0,
                'parameters': {}
            }

        # Apply maxTargets limit
        max_targets = parameters.get('maxTargets', 20)
        if len(targets_list) > max_targets:
            print(f"[Arjun] Limiting {len(targets_list)} targets to {max_targets}")
            targets_list = targets_list[:max_targets]

        methods = parameters.get('methods', 'GET')
        headers_file = parameters.get('headers_file')
        cookie = parameters.get('cookie')
        stable = parameters.get('stable', True)
        threads = parameters.get('threads', 5)
        agent = parameters.get('_agent')

        try:
            execution_start = time.time()
            execution_metrics = {
                'start_time': execution_start,
                'process_pid': None,
                'execution_duration': 0,
                'memory_before': None,
            }

            if PSUTIL_AVAILABLE:
                try:
                    execution_metrics['memory_before'] = psutil.Process().memory_info().rss / 1024 / 1024
                except (psutil.NoSuchProcess, psutil.AccessDenied, Exception):
                    pass

            if agent:
                operation_desc = f"Starting Arjun parameter discovery on {len(targets_list)} target(s)"
                if headers_file or cookie:
                    operation_desc += " [authenticated]"
                agent.report_progress(
                    current_operation=operation_desc,
                    current_target=targets_list[0] if targets_list else "unknown",
                    items_processed=0,
                    total_items=len(targets_list)
                )
                agent.append_output(f"[Arjun] Discovering parameters with methods={methods}, threads={threads}")

            # Aggregate results from all targets
            all_urls = []
            all_parameters = {}
            errors = []

            for idx, target in enumerate(targets_list):
                if agent:
                    agent.report_progress(
                        current_operation=f"Parameter discovery {idx + 1}/{len(targets_list)}",
                        current_target=target,
                        items_processed=idx,
                        total_items=len(targets_list)
                    )

                result = await self._scan_single_target(
                    target=target,
                    methods=methods,
                    headers_file=headers_file,
                    cookie=cookie,
                    stable=stable,
                    threads=threads,
                    agent=agent,
                    execution_metrics=execution_metrics
                )

                if result.get('error'):
                    errors.append(f"{target}: {result['error']}")

                all_urls.extend(result.get('urls', []))
                if result.get('parameters'):
                    all_parameters.update(result['parameters'])

            execution_metrics['execution_duration'] = time.time() - execution_start

            if PSUTIL_AVAILABLE:
                try:
                    execution_metrics['memory_after'] = psutil.Process().memory_info().rss / 1024 / 1024
                except Exception:
                    pass

            if agent:
                agent.append_output(f"✓ Total: {len(all_urls)} enriched URLs from {len(targets_list)} targets")

            return {
                'success': True,
                'targets': targets_list,
                'urls': all_urls,
                'totalUrls': len(all_urls),
                'parameters': all_parameters,
                'errors': errors if errors else None,
                'execution_metrics': execution_metrics,
            }

        except FileNotFoundError:
            error_msg = 'Arjun not installed. Install with: pip install arjun'
            if agent:
                agent.append_output(f"❌ {error_msg}")
            return {
                'success': False,
                'error': error_msg,
                'targets': targets_list,
                'urls': [],
                'totalUrls': 0,
                'parameters': {}
            }
        except Exception as e:
            error_msg = str(e)
            if agent:
                agent.append_output(f"❌ Error: {error_msg}")
            return {
                'success': False,
                'error': error_msg,
                'targets': targets_list,
                'urls': [],
                'totalUrls': 0,
                'parameters': {}
            }

    async def _scan_single_target(
        self,
        target: str,
        methods: str,
        headers_file: str,
        cookie: str,
        stable: bool,
        threads: int,
        agent,
        execution_metrics: dict
    ) -> dict:
        """Scan a single target URL for hidden parameters"""
        cookie_headers_file = None
        try:
            output_file = f"/tmp/arjun_{uuid.uuid4().hex}.json"

            cmd = [
                'arjun',
                '-u', target,
                '-oJ', output_file,
                '-m', methods,
                '-t', str(threads),
            ]

            if stable:
                cmd.append('--stable')

            # Add authentication
            if headers_file and os.path.exists(headers_file):
                cmd.extend(['--headers', headers_file])
            elif cookie:
                # Arjun accepts --headers flag with a file, so create a temp headers file for cookie
                cookie_headers_file = f"/tmp/arjun_headers_{uuid.uuid4().hex}.txt"
                with open(cookie_headers_file, 'w') as f:
                    f.write(f"Cookie: {cookie}\n")
                cmd.extend(['--headers', cookie_headers_file])

            if agent:
                agent.append_output(f"  Running: {' '.join(cmd[:6])}...")

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            if execution_metrics.get('process_pid') is None:
                execution_metrics['process_pid'] = process.pid

            try:
                # 3 minute timeout per target
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=180
                )
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                if agent:
                    agent.append_output(f"  ⚠️ Timeout on: {target}")
                return {
                    'error': f'Timeout after 180s',
                    'target': target,
                    'urls': [],
                    'parameters': {}
                }

            enriched_urls = []
            param_map = {}

            try:
                if os.path.exists(output_file):
                    with open(output_file, 'r') as f:
                        content = f.read().strip()

                    if content:
                        # Arjun JSON output format (v2.2.x):
                        # {"http://example.com/page": {"method": "GET", "params": ["id", "cat"], "headers": {...}}}
                        # URL is the dict key, value contains method/params/headers
                        data = json.loads(content)

                        # Normalize to list of (url, entry) tuples
                        entries = []
                        if isinstance(data, dict):
                            # Check if it's the URL-keyed format (keys look like URLs)
                            first_key = next(iter(data), '')
                            if first_key.startswith('http://') or first_key.startswith('https://'):
                                # URL-keyed format: {"http://...": {"method": "GET", "params": [...]}}
                                for url_key, entry_val in data.items():
                                    entries.append((url_key, entry_val))
                            else:
                                # Legacy format: single {"url": "...", "params": [...]}
                                entries.append((data.get('url', target), data))
                        elif isinstance(data, list):
                            for item in data:
                                entries.append((item.get('url', target), item))

                        for url, entry in entries:
                            params = entry.get('params', [])
                            method = entry.get('method', methods)

                            if params:
                                # Build enriched URL with discovered params
                                parsed = urlparse(url)
                                param_string = '&'.join(f"{p}=" for p in params)

                                if parsed.query:
                                    enriched_url = f"{url}&{param_string}"
                                else:
                                    enriched_url = f"{url}?{param_string}"

                                enriched_urls.append(enriched_url)
                                param_map[url] = {
                                    'params': params,
                                    'method': method,
                                    'enriched_url': enriched_url
                                }

                                if agent:
                                    agent.append_output(f"  ✓ {url}: {len(params)} params found ({', '.join(params[:5])}{'...' if len(params) > 5 else ''})")
                            else:
                                if agent:
                                    agent.append_output(f"  - {url}: no parameters found")
                    else:
                        if agent:
                            agent.append_output(f"  - {target}: no output (empty response)")
                else:
                    # No output file - check stderr for useful info
                    stderr_text = stderr.decode('utf-8', errors='replace') if stderr else ''
                    if agent and stderr_text:
                        agent.append_output(f"  ⚠️ {target}: {stderr_text[:200]}")
                    elif agent:
                        agent.append_output(f"  - {target}: no parameters found")

            except json.JSONDecodeError as e:
                if agent:
                    agent.append_output(f"  ⚠️ {target}: Failed to parse output ({str(e)[:100]})")
            finally:
                # Cleanup temp files
                for f in [output_file]:
                    try:
                        if os.path.exists(f):
                            os.unlink(f)
                    except Exception:
                        pass
                # Cleanup cookie headers file if created
                if cookie_headers_file:
                    try:
                        if os.path.exists(cookie_headers_file):
                            os.unlink(cookie_headers_file)
                    except Exception:
                        pass

            return {
                'target': target,
                'urls': enriched_urls,
                'parameters': param_map,
            }

        except Exception as e:
            return {
                'error': str(e),
                'target': target,
                'urls': [],
                'parameters': {}
            }


def get_tool():
    return ArjunParameterDiscoveryTool()
