"""
Dirsearch Comprehensive Scan Tool
Thorough directory brute force with extended extensions for deep discovery
Best for: Thorough enumeration, finding backup files, configuration leaks
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
    ensure_dicc_wordlist,
    filter_results,
    resolve_dirsearch_wordlist,
)

# Comprehensive extensions - includes backup and config files
COMPREHENSIVE_EXTENSIONS = "php,aspx,jsp,html,js,css,json,xml,zip,tar,gz,bkp,sql,bak,old,swp,config,conf,ini,log,txt"


class DirsearchComprehensiveTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "dirsearch:comprehensive"

    @property
    def description(self) -> str:
        return "Thorough directory brute force with dicc.txt and extended extensions. Finds backup files, configs, logs."

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
                    "description": f"File extensions to search (default: {COMPREHENSIVE_EXTENSIONS})"
                },
                "extraWordlist": {
                    "type": "string",
                    "description": "Optional extra wordlist path to merge with the comprehensive dirsearch wordlist"
                },
                "extraWordlists": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Optional extra wordlist paths to merge with the comprehensive dirsearch wordlist"
                },
                "includeFuzzWordlist": {
                    "type": "boolean",
                    "description": "Automatically include /app/wordlists/fuzz.txt when available (default: true)",
                    "default": True
                },
                "maxTargets": {
                    "type": "integer",
                    "description": "Maximum number of targets to scan from array (default: 5)",
                    "default": 5
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
        
        # Apply maxTargets limit (lower default for comprehensive scan)
        max_targets = parameters.get('maxTargets', 5)
        if len(targets_list) > max_targets:
            print(f"[Dirsearch Comprehensive] Limiting {len(targets_list)} targets to {max_targets}")
            targets_list = targets_list[:max_targets]
        
        extensions = parameters.get('extensions', COMPREHENSIVE_EXTENSIONS)
        from tools._scope_utils import extract_auth_cookie, extract_auth_headers_file
        headers_file = extract_auth_headers_file(parameters)
        cookie = extract_auth_cookie(parameters)
        agent = parameters.get('_agent')

        # Apply exclusion filtering to targets
        from tools._scope_utils import extract_exclusion_patterns, extract_rate_limit, filter_excluded_urls
        exclusion_url_patterns = extract_exclusion_patterns(parameters)
        rate_limit_config = extract_rate_limit(parameters)
        if exclusion_url_patterns:
            targets_list = filter_excluded_urls(targets_list, exclusion_url_patterns, "Dirsearch Comprehensive")

        try:
            execution_start = time.time()
            execution_metrics = {
                'start_time': execution_start,
                'process_pid': None,
                'execution_duration': 0,
                'memory_before': psutil.Process().memory_info().rss / 1024 / 1024 if PSUTIL_AVAILABLE else None,
            }

            if agent:
                operation_desc = f"Starting comprehensive dirsearch scan on {len(targets_list)} target(s)"
                if headers_file or cookie:
                    operation_desc += " [authenticated]"
                agent.report_progress(
                    current_operation=operation_desc,
                    current_target=targets_list[0] if targets_list else "unknown",
                    items_processed=0,
                    total_items=len(targets_list)
                )

            # Try to use dicc.txt as default
            wordlist_to_use = ensure_dicc_wordlist()
            wordlist_to_use, wordlist_info = resolve_dirsearch_wordlist(
                default_wordlist=wordlist_to_use,
                parameters=parameters,
                tool_label="Dirsearch Comprehensive",
            )
            if agent:
                agent.append_output(
                    "[Dirsearch Comprehensive] Using "
                    f"{describe_wordlist_selection(wordlist_info)} with extended extensions"
                )

            # Aggregate results from all targets
            all_endpoints = []
            all_urls = []
            errors = []

            for idx, target in enumerate(targets_list):
                if agent:
                    agent.report_progress(
                        current_operation=f"Comprehensive scan target {idx + 1}/{len(targets_list)}",
                        current_target=target,
                        items_processed=idx,
                        total_items=len(targets_list)
                    )

                result = await self._scan_single_target(
                    target=target,
                    wordlist=wordlist_to_use,
                    extensions=extensions,
                    headers_file=headers_file,
                    cookie=cookie,
                    agent=agent,
                    execution_metrics=execution_metrics,
                    rate_limit_config=rate_limit_config
                )

                if result.get('error'):
                    errors.append(f"{target}: {result['error']}")
                
                all_endpoints.extend(result.get('endpoints', []))
                all_urls.extend(result.get('urls', []))

            execution_metrics['execution_duration'] = time.time() - execution_start

            if PSUTIL_AVAILABLE:
                try:
                    execution_metrics['memory_after'] = psutil.Process().memory_info().rss / 1024 / 1024
                except Exception:
                    pass

            if agent:
                agent.append_output(f"✓ Total: {len(all_endpoints)} endpoints from {len(targets_list)} targets")

            return {
                'targets': targets_list,
                'target': targets_list[0] if targets_list else None,
                'endpoints': all_endpoints,
                'urls': all_urls,
                'totalEndpoints': len(all_endpoints),
                'errors': errors if errors else None,
                'execution_metrics': execution_metrics,
                'scan_type': 'comprehensive'
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
        wordlist: str,
        extensions: str,
        headers_file: str,
        cookie: str,
        agent,
        execution_metrics: dict,
        rate_limit_config: dict = None
    ) -> dict:
        """Scan a single target with comprehensive dirsearch mode"""
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tmp_file:
                output_file = tmp_file.name

            # Determine thread count from rate limit config
            threads = str(rate_limit_config.get('concurrency', 50)) if rate_limit_config else '50'

            # Comprehensive scan: use dicc.txt, extended extensions
            cmd = [
                'dirsearch',
                '-u', target,
                '-t', threads,           # Threads (configurable via rate limiting)
                '-i', '200,201,301,403',
                '--exclude-sizes=0B',
                '--random-agent',
                '-e', extensions,
                '--format=json',
                '-o', output_file,
                '--quiet'
            ]

            # Add wordlist if available
            if wordlist and os.path.exists(wordlist):
                cmd.extend(['-w', wordlist])

            # Add authentication
            if headers_file and os.path.exists(headers_file):
                cmd.extend(['--header-list', headers_file])
            elif cookie:
                cmd.extend(['--cookie', cookie])

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            if execution_metrics.get('process_pid') is None:
                execution_metrics['process_pid'] = process.pid

            try:
                # 15 minute timeout for comprehensive scan (more extensions = more time)
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=900
                )
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                if agent:
                    agent.append_output(f"⚠️ Comprehensive scan timeout: {target}")

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
                        length = item.get('content-length', item.get('length'))

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
                                f"  ✓ {target}: {len(endpoints)} endpoints "
                                f"({filter_stats['filtered_count']} false positives filtered: "
                                f"{filter_stats['filter_reasons']})"
                            )
                        else:
                            agent.append_output(f"  ✓ {target}: {len(endpoints)} endpoints")

            except json.JSONDecodeError:
                if agent:
                    agent.append_output(f"  ⚠️ {target}: Failed to parse output")
            finally:
                try:
                    os.unlink(output_file)
                except Exception:
                    pass

            return {
                'target': target,
                'endpoints': endpoints,
                'urls': urls,
                'totalEndpoints': len(endpoints)
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
    return DirsearchComprehensiveTool()
