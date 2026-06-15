"""
Katana Shallow Crawl Tool
Quick shallow crawl (depth 1) for large websites to discover top-level URLs and endpoints
Optimized for large sites like scanme.nmap.org
"""

import subprocess
import asyncio
import json
import time
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
from plugin_interface import ToolPlugin
from typing import Dict, Any
from tools._katana_common import add_katana_options, extend_katana_schema, get_auth_cookie, get_headers_file

class KatanaShallowCrawlTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "katana:shallow_crawl"

    @property
    def description(self) -> str:
        return "Katana crawl with depth 1 for large websites to discover top-level URLs and endpoints. Supports authenticated crawling with cookies/headers."

    @property
    def schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": extend_katana_schema({
                "url": {
                    "type": "string",
                    "description": "Base URL to crawl (e.g., http://example.com)"
                },
                "target": {
                    "type": "string",
                    "description": "Base URL to crawl (e.g., http://example.com) - alias for 'url'"
                },
                "depth": {
                    "type": "integer",
                    "description": "Crawl depth (default: 1 for shallow crawl)",
                    "default": 1
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
            "required": []
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
        # Accept both 'target' and 'url' for backward compatibility
        target = parameters.get('url') or parameters.get('target')

        if not target:
            return {
                'error': "Either 'target' or 'url' parameter is required for katana:shallow_crawl",
                'endpoints': [],
                'urls': [],
                'totalEndpoints': 0
            }

        # Default to depth 1 for shallow crawl, but allow override
        depth = parameters.get('depth', 1)
        headers_file = get_headers_file(parameters)  # Optional auth headers file
        cookie = get_auth_cookie(parameters)  # Optional cookie string
        agent = parameters.get('_agent')  # Get agent reference for progress

        # Extract exclusion and rate limiting
        from tools._scope_utils import extract_exclusion_patterns, extract_rate_limit, filter_excluded_urls
        exclusion_url_patterns = extract_exclusion_patterns(parameters)
        rate_limit_config = extract_rate_limit(parameters)

        try:
            # Execution metrics
            execution_start = time.time()
            execution_metrics = {
                'start_time': execution_start,
                'process_pid': None,
                'stdout_size': 0,
                'stderr_size': 0,
                'execution_duration': 0,
            }

            # Report initial progress
            if agent:
                operation_desc = f"Starting Katana shallow crawl (depth {depth})"
                if headers_file or cookie:
                    operation_desc += " [authenticated]"
                agent.report_progress(
                    current_operation=operation_desc,
                    current_target=target,
                    items_processed=0,
                    total_items=None
                )

            # Run Katana crawler with shallow depth and shorter timeout for large sites
            # -nc (no-color) prevents ANSI escape codes from corrupting JSONL output
            # -ct limits crawl duration to prevent excessive output (2 minutes max for shallow crawl)
            cmd = ['katana', '-u', target, '-d', str(depth), '-ct', '2m', '-jsonl', '-silent', '-nc']

            cmd = add_katana_options(cmd, parameters, rate_limit_config)

            try:
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                execution_metrics['process_pid'] = process.pid
            except Exception as e:
                raise

            # Shorter timeout for shallow crawl (2 minutes)
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=120  # 2 minutes - sufficient for shallow crawl
                )
            except asyncio.TimeoutError:
                execution_end = time.time()
                execution_metrics['execution_duration'] = execution_end - execution_start
                process.kill()
                await process.wait()
                # Try to parse partial output if available
                partial_stdout = b''
                try:
                    if process.stdout:
                        partial_stdout = await process.stdout.read() if hasattr(process.stdout, 'read') else b''
                except Exception:
                    pass

                if partial_stdout:
                    stdout_text = partial_stdout.decode('utf-8', errors='replace').replace('\0', '')
                    endpoints = []
                    urls = []
                    urls_set = set()
                    for line in stdout_text.strip().split('\n'):
                        if line:
                            try:
                                line = line.replace('\0', '')
                                data = json.loads(line)
                                if data.get('error'):
                                    continue
                                request = data.get('request', {})
                                endpoint_url = request.get('endpoint')
                                if endpoint_url:
                                    endpoints.append({
                                        'url': endpoint_url,
                                        'method': request.get('method', 'GET'),
                                        'status_code': data.get('response', {}).get('status_code'),
                                    })
                                    if endpoint_url not in urls_set:
                                        urls_set.add(endpoint_url)
                                        urls.append(endpoint_url)
                            except json.JSONDecodeError:
                                pass

                    return {
                        'error': f'Katana shallow crawl timed out after 2 minutes for {target} (partial results included)',
                        'endpoints': endpoints,
                        'urls': urls,
                        'totalEndpoints': len(endpoints),
                        'execution_metrics': execution_metrics,
                        'partial_results': True
                    }

                return {
                    'error': f'Katana shallow crawl timed out after 2 minutes for {target}',
                    'endpoints': [],
                    'urls': [],
                    'totalEndpoints': 0,
                    'execution_metrics': execution_metrics
                }

            execution_end = time.time()
            execution_metrics['execution_duration'] = execution_end - execution_start
            stdout_text = stdout.decode('utf-8', errors='replace').replace('\0', '') if stdout else ''
            stderr_text = stderr.decode('utf-8', errors='replace').replace('\0', '') if stderr else ''
            execution_metrics['stdout_size'] = len(stdout_text)
            execution_metrics['stderr_size'] = len(stderr_text)

            # Check return code
            return_code = await process.wait()
            was_killed = return_code == -9
            has_output = stdout_text and len(stdout_text.strip()) > 0

            execution_metrics['return_code'] = return_code
            execution_metrics['was_killed'] = was_killed

            if return_code != 0:
                execution_metrics['error_message'] = stderr_text[:1000]

                if was_killed and has_output:
                    pass  # Continue to parsing
                elif not has_output:
                    return {
                        'error': stderr_text or 'Katana shallow crawl failed',
                        'endpoints': [],
                        'urls': [],
                        'totalEndpoints': 0,
                        'execution_metrics': execution_metrics
                    }

            # Parse JSON output (one JSON object per line)
            endpoints = []
            urls = []
            urls_set = set()
            has_errors = False

            parse_errors = 0
            skipped_no_endpoint = 0
            for line in stdout_text.strip().split('\n'):
                if line:
                    try:
                        line = line.replace('\0', '')
                        data = json.loads(line)
                        if data.get('error'):
                            has_errors = True
                            error_msg = data.get('error', '')
                            if agent:
                                agent.append_output(f"[Katana Shallow] Connection error: {error_msg}")
                            continue

                        request = data.get('request', {})
                        response = data.get('response', {})
                        endpoint_url = request.get('endpoint')

                        if not endpoint_url:
                            skipped_no_endpoint += 1
                            continue

                        status_code = response.get('status_code')

                        endpoints.append({
                            'url': endpoint_url,
                            'method': request.get('method', 'GET'),
                            'status_code': status_code,
                            'content_length': response.get('headers', {}).get('content_length'),
                        })

                        if endpoint_url not in urls_set:
                            urls_set.add(endpoint_url)
                            urls.append(endpoint_url)
                    except json.JSONDecodeError:
                        parse_errors += 1

            # Apply exclusion filtering to discovered URLs
            if exclusion_url_patterns:
                urls = filter_excluded_urls(urls, exclusion_url_patterns, "Katana Shallow")
                urls_set_filtered = set(urls)
                endpoints = [ep for ep in endpoints if ep.get('url') in urls_set_filtered]

            execution_metrics['parse_errors'] = parse_errors
            execution_metrics['has_errors'] = has_errors
            execution_metrics['skipped_no_endpoint'] = skipped_no_endpoint

            if agent:
                agent.report_progress(
                    current_operation="Katana shallow crawl completed",
                    current_target=target,
                    items_processed=len(endpoints),
                    total_items=len(endpoints)
                )

            return {
                'endpoints': endpoints,
                'urls': urls,
                'totalEndpoints': len(endpoints),
                'execution_metrics': execution_metrics
            }

        except Exception as e:
            return {
                'error': str(e),
                'endpoints': [],
                'urls': [],
                'totalEndpoints': 0
            }


def get_tool():
    return KatanaShallowCrawlTool()
