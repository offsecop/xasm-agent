"""
Dirsearch Quick Scan Tool
Fast directory brute force using dirsearch's built-in common wordlist
Best for: Quick reconnaissance, initial discovery
"""

import subprocess
import asyncio
import json
import re
import time
import os
import tempfile
from urllib.parse import urlparse, unquote
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
from plugin_interface import ToolPlugin
from typing import Dict, Any
from tools._dirsearch_base import (
    describe_wordlist_selection,
    filter_results,
    resolve_dirsearch_wordlist,
)

# Quick scan extensions - common web files only
QUICK_EXTENSIONS = "php,html,js"
DEFAULT_QUICK_TIMEOUT_SECONDS = 300
MIN_QUICK_TIMEOUT_SECONDS = 1
MAX_QUICK_TIMEOUT_SECONDS = 300


def coerce_quick_timeout_seconds(value: Any) -> int:
    """Return a caller-controlled, bounded wall-clock deadline."""
    try:
        timeout_seconds = int(value)
    except (TypeError, ValueError):
        timeout_seconds = DEFAULT_QUICK_TIMEOUT_SECONDS
    return max(MIN_QUICK_TIMEOUT_SECONDS, min(timeout_seconds, MAX_QUICK_TIMEOUT_SECONDS))


class DirsearchQuickTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "dirsearch:quick"

    @property
    def description(self) -> str:
        return "Quick directory brute force using dirsearch's built-in common wordlist. Best for fast reconnaissance."

    @property
    def schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Base URL to scan (e.g., http://example.com)"
                },
                "targets": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Multiple target URLs to scan (alternative to target)"
                },
                "extensions": {
                    "type": "string",
                    "description": f"File extensions to search (default: {QUICK_EXTENSIONS})"
                },
                "extraWordlist": {
                    "type": "string",
                    "description": "Optional extra wordlist path to merge with the quick dirsearch list"
                },
                "extraWordlists": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Optional extra wordlist paths to merge with the quick dirsearch list"
                },
                "includeFuzzWordlist": {
                    "type": "boolean",
                    "description": "Automatically include /app/wordlists/fuzz.txt when available (default: true)",
                    "default": True
                },
                "maxTargets": {
                    "type": "integer",
                    "description": "Maximum number of targets to scan from array (default: 10)",
                    "default": 10
                },
                "timeoutSeconds": {
                    "type": "integer",
                    "description": "Whole-tool wall-clock deadline in seconds (default: 300)",
                    "default": DEFAULT_QUICK_TIMEOUT_SECONDS,
                    "minimum": MIN_QUICK_TIMEOUT_SECONDS,
                    "maximum": MAX_QUICK_TIMEOUT_SECONDS
                },
                "headers_file": {
                    "type": "string",
                    "description": "Path to headers file for authenticated scanning"
                },
                "cookie": {
                    "type": "string",
                    "description": "Cookie header value for direct injection"
                },
                "authCookies": {
                    "type": "string",
                    "description": "Session cookies injected by authentication steps"
                },
                "authHeadersFile": {
                    "type": "string",
                    "description": "Headers file injected by authentication steps"
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
            "output_type": ["urls"],
            "chainable_after": ["httpx:probe"],
            "chainable_before": ["nuclei:", "katana:", "gowitness:"],
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
                'error': 'Either target or targets parameter is required',
                'endpoints': [],
                'urls': [],
                'totalEndpoints': 0
            }
        
        # Apply maxTargets limit
        max_targets = parameters.get('maxTargets', 10)
        if len(targets_list) > max_targets:
            print(f"[Dirsearch Quick] Limiting {len(targets_list)} targets to {max_targets}")
            targets_list = targets_list[:max_targets]
        
        extensions = parameters.get('extensions', QUICK_EXTENSIONS)
        from tools._scope_utils import extract_auth_cookie, extract_auth_headers_file
        headers_file = extract_auth_headers_file(parameters)
        cookie = extract_auth_cookie(parameters)
        agent = parameters.get('_agent')
        timeout_seconds = coerce_quick_timeout_seconds(parameters.get('timeoutSeconds'))

        # Apply exclusion filtering to targets
        from tools._scope_utils import extract_exclusion_patterns, extract_rate_limit, filter_excluded_urls
        exclusion_url_patterns = extract_exclusion_patterns(parameters)
        rate_limit_config = extract_rate_limit(parameters)
        if exclusion_url_patterns:
            targets_list = filter_excluded_urls(targets_list, exclusion_url_patterns, "Dirsearch Quick")

        try:
            execution_start = time.time()
            execution_monotonic_start = time.monotonic()
            deadline = execution_monotonic_start + timeout_seconds
            execution_metrics = {
                'start_time': execution_start,
                'process_pid': None,
                'execution_duration': 0,
                'elapsedMs': 0,
                'timeoutSeconds': timeout_seconds,
                'deadlineExceeded': False,
                'completedTargets': 0,
                'candidateCount': 0,
                'memory_before': psutil.Process().memory_info().rss / 1024 / 1024 if PSUTIL_AVAILABLE else None,
            }

            if agent:
                operation_desc = f"Starting quick dirsearch scan on {len(targets_list)} target(s)"
                if headers_file or cookie:
                    operation_desc += " [authenticated]"
                agent.report_progress(
                    current_operation=operation_desc,
                    current_target="target-batch",
                    items_processed=0,
                    total_items=len(targets_list)
                )

            wordlist_to_use, wordlist_info = resolve_dirsearch_wordlist(
                default_wordlist=None,
                parameters=parameters,
                tool_label="Dirsearch Quick",
                prefer_common_wordlist=True,
            )
            if agent:
                agent.append_output(
                    f"[Dirsearch Quick] Using {describe_wordlist_selection(wordlist_info)}"
                )

            # Aggregate results from all targets
            all_endpoints = []
            all_urls = []
            errors = []
            timed_out = False
            completed_targets = 0
            successful_targets = 0

            for idx, target in enumerate(targets_list):
                remaining_seconds = deadline - time.monotonic()
                if remaining_seconds <= 0:
                    timed_out = True
                    errors.append("configured wall-clock deadline exceeded before next target")
                    break
                if agent:
                    agent.report_progress(
                        current_operation=f"Quick scan target {idx + 1}/{len(targets_list)}",
                        current_target=f"target-{idx + 1}",
                        items_processed=idx,
                        total_items=len(targets_list)
                    )

                result = await self._scan_single_target(
                    target=target,
                    extensions=extensions,
                    headers_file=headers_file,
                    cookie=cookie,
                    wordlist=wordlist_to_use,
                    agent=agent,
                    execution_metrics=execution_metrics,
                    rate_limit_config=rate_limit_config,
                    timeout_seconds=remaining_seconds,
                )

                if result.get('error'):
                    errors.append(f"target {idx + 1}: {result['error']}")
                else:
                    successful_targets += 1
                
                all_endpoints.extend(result.get('endpoints', []))
                all_urls.extend(result.get('urls', []))
                completed_targets += 1
                if result.get('timedOut'):
                    timed_out = True
                    break

            execution_metrics['execution_duration'] = time.time() - execution_start
            execution_metrics['elapsedMs'] = int((time.monotonic() - execution_monotonic_start) * 1000)
            execution_metrics['deadlineExceeded'] = timed_out
            execution_metrics['completedTargets'] = completed_targets
            execution_metrics['candidateCount'] = len(all_endpoints)

            if PSUTIL_AVAILABLE:
                try:
                    execution_metrics['memory_after'] = psutil.Process().memory_info().rss / 1024 / 1024
                except Exception:
                    pass

            if agent:
                agent.append_output(f"✓ Total: {len(all_endpoints)} endpoints from {len(targets_list)} targets")

            return {
                # Reaching the configured quick-scan deadline is a bounded,
                # inspectable completion rather than an execution failure. The
                # partial/coverageComplete fields preserve the distinction for
                # callers without discarding endpoints already collected or
                # causing the required RECON_BRUTE phase to be skipped.
                'success': successful_targets > 0,
                'status': 'PARTIAL_TIMEOUT' if timed_out else ('COMPLETED' if successful_targets > 0 else 'FAILED'),
                'timedOut': timed_out,
                'partial': timed_out,
                'coverageComplete': not timed_out,
                'timeoutSeconds': timeout_seconds,
                'targets': targets_list,
                'target': targets_list[0] if targets_list else None,
                'endpoints': all_endpoints,
                'urls': all_urls,
                'totalEndpoints': len(all_endpoints),
                'errors': errors if errors else None,
                'execution_metrics': execution_metrics,
                'scan_type': 'quick'
            }

        except FileNotFoundError:
            error_msg = 'Dirsearch not installed. Install with: pip install dirsearch'
            if agent:
                agent.append_output(f"❌ {error_msg}")
            return {
                'error': error_msg,
                'targets': targets_list,
                'endpoints': [],
                'urls': [],
                'totalEndpoints': 0
            }
        except Exception as e:
            error_msg = str(e)
            if agent:
                agent.append_output(f"❌ Error: {error_msg}")
            return {
                'error': error_msg,
                'targets': targets_list,
                'endpoints': [],
                'urls': [],
                'totalEndpoints': 0
            }

    async def _scan_single_target(
        self,
        target: str,
        extensions: str,
        headers_file: str,
        cookie: str,
        wordlist: str,
        agent,
        execution_metrics: dict,
        rate_limit_config: dict = None,
        timeout_seconds: float = DEFAULT_QUICK_TIMEOUT_SECONDS,
    ) -> dict:
        """Scan a single target with dirsearch quick mode"""
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tmp_file:
                output_file = tmp_file.name

            # Determine thread count from rate limit config
            threads = str(rate_limit_config.get('concurrency', 30)) if rate_limit_config else '30'

            # Quick scan: use built-in wordlist (no -w flag), fewer threads for speed
            cmd = [
                'dirsearch',
                '-u', target,
                '-t', threads,           # Threads (configurable via rate limiting)
                '-i', '200,201,301,403',
                '--exclude-sizes=0B',
                '--random-agent',
                '-e', extensions,
                '-O', 'json',
                '-o', output_file,
                '-q'
            ]

            if wordlist and os.path.exists(wordlist):
                cmd.extend(['-w', wordlist])

            # Add authentication
            if headers_file and os.path.exists(headers_file):
                cmd.extend(['--headers-file', headers_file])
            elif cookie:
                cmd.extend(['--cookie', cookie])

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            if execution_metrics.get('process_pid') is None:
                execution_metrics['process_pid'] = process.pid

            timed_out = False
            stdout = b''
            stderr = b''
            scan_start = time.monotonic()
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=max(0.001, float(timeout_seconds)),
                )
            except asyncio.TimeoutError:
                timed_out = True
                process.kill()
                await process.wait()
                if agent:
                    agent.append_output("[Dirsearch Quick] configured deadline reached; preserving partial output")

            endpoints = []
            urls = []

            try:
                if os.path.exists(output_file):
                    with open(output_file, 'r') as f:
                        data = json.load(f)

                    results = data.get('results', [])

                    for item in results:
                        url = item.get('url')
                        status = item.get('status')
                        length = item.get('contentLength', item.get('content-length', item.get('length')))

                        if url:
                            endpoint = {
                                'url': url,
                                'status_code': status,
                                'content_length': length,
                                'method': 'GET'
                            }
                            endpoints.append(endpoint)

                    # Filter false positives
                    raw_count = len(endpoints)
                    endpoints, filter_stats = self._filter_results(endpoints)
                    urls = [ep['url'] for ep in endpoints]

                    if agent:
                        if filter_stats['filtered_count'] > 0:
                            agent.append_output(
                                f"  ✓ {len(endpoints)} endpoints "
                                f"({filter_stats['filtered_count']} false positives filtered: "
                                f"{filter_stats['filter_reasons']})"
                            )
                        else:
                            agent.append_output(f"  ✓ {len(endpoints)} endpoints")

            except json.JSONDecodeError:
                if agent:
                    agent.append_output("  ⚠️ Partial dirsearch output was not valid JSON")
            finally:
                try:
                    os.unlink(output_file)
                except Exception:
                    pass

            return_code = getattr(process, 'returncode', 0)
            process_error = None
            if not timed_out and return_code not in (0, None):
                detail = (stderr or stdout or b'dirsearch exited non-zero').decode('utf-8', errors='replace')
                process_error = f"dirsearch exited {return_code}: {detail[:300]}"

            return {
                'target': target,
                'endpoints': endpoints,
                'urls': urls,
                'totalEndpoints': len(endpoints),
                'timedOut': timed_out,
                'partial': timed_out,
                'elapsedMs': int((time.monotonic() - scan_start) * 1000),
                'error': process_error,
            }

        except Exception as e:
            return {
                'error': str(e),
                'target': target,
                'endpoints': [],
                'urls': [],
                'totalEndpoints': 0
            }

    def _filter_results(self, endpoints):
        return filter_results(endpoints)


def get_tool():
    return DirsearchQuickTool()
