"""
Katana Web Crawler Tool
Crawls web applications to discover URLs and endpoints
"""

import subprocess
import asyncio
import json
import re
import time
from urllib.parse import urlsplit, urlunsplit
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
from plugin_interface import ToolPlugin
from typing import Dict, Any
from lib import process_reaper
from tools._katana_common import add_katana_options, extend_katana_schema, get_auth_cookie, get_headers_file

KATANA_WATCHDOG_RESERVE_SECONDS = 30


def bounded_katana_timeout(parameters, requested_seconds):
    """Keep Katana's own timer strictly below the agent job watchdog.

    The runtime injects `_job_timeout_seconds`.  A single-target crawl used the
    same 180-second value for both timers, so cancellation raced Katana's own
    shutdown and the agent process exited before it could report a structured
    result.  Reserve enough time for pipe draining, JSON parsing, process-group
    teardown, and the completion POST (#1961).
    """
    try:
        requested = int(requested_seconds)
    except (TypeError, ValueError):
        requested = 180
    requested = max(30, min(requested, 600))

    try:
        job_timeout = float(parameters.get('_job_timeout_seconds') or 0)
    except (TypeError, ValueError, AttributeError):
        job_timeout = 0
    if job_timeout <= 0:
        return requested

    safe_ceiling = max(5, int(job_timeout) - KATANA_WATCHDOG_RESERVE_SECONDS)
    return min(requested, safe_ceiling)


def _canonical_origin(value):
    """Return the effective HTTP origin as (scheme, host, port)."""
    try:
        parsed = urlsplit(str(value or "").strip())
        scheme = parsed.scheme.lower()
        if scheme not in {"http", "https"} or not parsed.hostname:
            return None
        port = parsed.port or (443 if scheme == "https" else 80)
        return scheme, parsed.hostname.lower(), port
    except (TypeError, ValueError):
        return None


def is_same_origin_url(target, candidate):
    """Fail closed unless a discovered URL uses the exact authorized origin."""
    origin = _canonical_origin(target)
    return origin is not None and origin == _canonical_origin(candidate)


def exact_origin_scope_options(target):
    """Build Katana flags that prevent sibling-host and cross-port crawling."""
    origin = _canonical_origin(target)
    if origin is None:
        raise ValueError("Katana target must be an absolute HTTP(S) URL")

    scheme, hostname, port = origin
    url_host = f"[{hostname}]" if ":" in hostname else hostname
    default_port = 443 if scheme == "https" else 80
    port_pattern = f"(?::{port})?" if port == default_port else f":{port}"
    scope_regex = (
        rf"^{re.escape(scheme)}://{re.escape(url_host)}"
        rf"{port_pattern}(?:[/?#]|$)"
    )
    return ["-fs", "fqdn", "-cs", scope_regex]


def _canonical_observed_url(value):
    try:
        parsed = urlsplit(str(value or "").strip())
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return None
        host = parsed.hostname.lower()
        if ":" in host:
            host = f"[{host}]"
        port = parsed.port
        if port and not (
            (parsed.scheme.lower() == "http" and port == 80)
            or (parsed.scheme.lower() == "https" and port == 443)
        ):
            host = f"{host}:{port}"
        return urlunsplit(
            (parsed.scheme.lower(), host, parsed.path or "/", parsed.query, "")
        )
    except (TypeError, ValueError):
        return None


def is_successful_root_observation(target, endpoint, status_code):
    """True only when Katana observed a response for the requested root."""
    if isinstance(status_code, bool):
        return False
    try:
        normalized_status = int(status_code)
    except (TypeError, ValueError):
        return False
    return (
        100 <= normalized_status <= 599
        and _canonical_observed_url(target) is not None
        and _canonical_observed_url(target) == _canonical_observed_url(endpoint)
    )


def classify_katana_coverage(urls, *, has_errors=False, root_reachable=False):
    """Return an evidence verdict, not merely a process-exit verdict.

    A Katana process can exit zero while producing no usable response (for
    example after connection timeouts).  Conversely, a bounded crawl that
    observed at least one URL is useful even when another origin failed.
    """
    if urls:
        return (
            "CONFIRMED",
            "PARTIAL_URL_INVENTORY_OBSERVED" if has_errors else "URL_INVENTORY_OBSERVED",
        )
    if has_errors:
        return "INCOMPLETE", "CRAWL_ERRORS_WITHOUT_URL_EVIDENCE"
    if root_reachable:
        return "COMPLETE_NO_FINDING", "ROOT_REACHABLE_NO_URLS_DISCOVERED"
    return "INCOMPLETE", "NO_REACHABILITY_OR_URL_EVIDENCE"

class KatanaCrawlTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "katana:crawl_depth2"

    @property
    def description(self) -> str:
        return "Crawls web applications to discover URLs and endpoints using Katana. Supports authenticated crawling with cookies/headers."

    @property
    def schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": extend_katana_schema({
                "target": {
                    "type": "string",
                    "description": "Base URL to crawl (e.g., http://example.com)"
                },
                "targets": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Multiple target URLs to crawl (alternative to target, for workflow chaining)"
                },
                "depth": {
                    "type": "integer",
                    "description": "Crawl depth",
                    "default": 2
                },
                "max_urls": {
                    "type": "integer",
                    "description": "Maximum number of URLs to crawl (prevents excessive output)",
                    "default": 1000
                },
                "crawlTimeoutSeconds": {
                    "type": "integer",
                    "description": "Maximum Katana crawl duration in seconds",
                    "default": 180
                },
                "maxTargets": {
                    "type": "integer",
                    "description": "Maximum number of targets to crawl from array (default: 10)",
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
        # Support both 'target' (single) and 'targets' (array) parameters
        # For chained workflows like Dirsearch -> Katana
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
        elif 'url' in parameters and parameters['url']:
            targets_list = [parameters['url']]

        if not targets_list:
            return {
                'error': 'Either target or targets parameter is required',
                'endpoints': [],
                'urls': [],
                'totalEndpoints': 0,
                'coverageStatus': 'INCOMPLETE',
                'coverageReason': 'TARGET_REQUIRED',
                'rootReachable': False,
            }

        # Apply maxTargets limit
        max_targets = int(parameters.get('maxTargets', 10) or 10)
        if len(targets_list) > max_targets:
            targets_list = targets_list[:max_targets]

        depth = parameters.get('depth', 2)
        max_urls = int(parameters.get('max_urls', 1000) or 1000)  # Limit URLs to prevent excessive output
        headers_file = get_headers_file(parameters)  # Optional auth headers file
        cookie = get_auth_cookie(parameters)  # Optional cookie string
        agent = parameters.get('_agent')  # Get agent reference for progress

        # Extract exclusion and rate limiting
        from tools._scope_utils import extract_exclusion_patterns, extract_rate_limit, filter_excluded_urls
        exclusion_url_patterns = extract_exclusion_patterns(parameters)
        rate_limit_config = extract_rate_limit(parameters)

        # If multiple targets, crawl each and aggregate results
        if len(targets_list) > 1:
            return await self._crawl_multiple_targets(
                targets_list=targets_list,
                depth=depth,
                max_urls=max_urls,
                headers_file=headers_file,
                cookie=cookie,
                agent=agent,
                parameters=parameters
            )

        # Single target - use existing logic
        target = targets_list[0]


        try:
            crawl_timeout_seconds = bounded_katana_timeout(
                parameters,
                parameters.get('crawlTimeoutSeconds') or parameters.get('crawlTimeout') or 180,
            )

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
                operation_desc = f"Starting Katana crawl (depth {depth})"
                if headers_file or cookie:
                    operation_desc += " [authenticated]"
                agent.report_progress(
                    current_operation=f"{operation_desc} (limit {crawl_timeout_seconds}s)",
                    current_target=target,
                    items_processed=0,
                    total_items=None
                )

            # Run Katana crawler using asyncio for proper timeout handling
            # -nc (no-color) prevents ANSI escape codes from corrupting JSONL output
            # -ct limits crawl duration to prevent excessive output.
            cmd = ['katana', '-u', target, '-d', str(depth), '-ct', f'{crawl_timeout_seconds}s', '-jsonl', '-silent', '-nc']
            cmd.extend(exact_origin_scope_options(target))

            cmd = add_katana_options(cmd, parameters, rate_limit_config)
            if rate_limit_config:
                print(f"[Katana] Rate limit: {rate_limit_config['rateLimit']} req/s")

            try:
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    start_new_session=True,
                )
                process_reaper.register_group(process)
                execution_metrics['process_pid'] = process.pid
            except Exception as e:
                raise

            # Add timeout: katana should complete in 3 minutes max for small sites
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=crawl_timeout_seconds + 20
                )
            except asyncio.TimeoutError:
                # Katana has its own bounded crawl timer, but a stalled child may
                # outlive it.  The child is a process-group leader, so tear down
                # only that group and never signal the agent's group (#1961).
                execution_end = time.time()
                execution_metrics['execution_duration'] = execution_end - execution_start
                await process_reaper.terminate_group(process)
                # Try to parse partial output if available
                partial_stdout = b''
                try:
                    if process.stdout:
                        partial_stdout = await process.stdout.read() if hasattr(process.stdout, 'read') else b''
                except Exception:
                    pass

                # If we have partial output, try to parse it
                if partial_stdout:
                    stdout_text = partial_stdout.decode('utf-8', errors='replace').replace('\0', '')
                    endpoints = []
                    urls = []
                    urls_set = set()
                    root_reachable = False
                    for line in stdout_text.strip().split('\n'):
                        if line:
                            try:
                                line = line.replace('\0', '')
                                data = json.loads(line)
                                if data.get('error'):
                                    continue
                                request = data.get('request', {})
                                response = data.get('response', {})
                                endpoint_url = request.get('endpoint')
                                if endpoint_url and is_same_origin_url(target, endpoint_url):
                                    status_code = response.get('status_code')
                                    if is_successful_root_observation(
                                        target, endpoint_url, status_code
                                    ):
                                        root_reachable = True
                                    endpoints.append({
                                        'url': endpoint_url,
                                        'method': request.get('method', 'GET'),
                                        'status_code': status_code,
                                    })
                                    if endpoint_url not in urls_set:
                                        urls_set.add(endpoint_url)
                                        urls.append(endpoint_url)
                                        if len(urls) >= max_urls:
                                            break
                            except json.JSONDecodeError:
                                pass

                    return {
                        'error': f'Katana crawl timed out after {crawl_timeout_seconds} seconds for {target} (partial results included)',
                        'endpoints': endpoints,
                        'urls': urls,
                        'totalEndpoints': len(endpoints),
                        'coverageStatus': 'CONFIRMED' if urls else 'INCOMPLETE',
                        'coverageReason': 'TIMEOUT_WITH_PARTIAL_URL_EVIDENCE' if urls else 'TIMEOUT_WITHOUT_URL_EVIDENCE',
                        'rootReachable': root_reachable,
                        'execution_metrics': execution_metrics,
                        'partial_results': True
                    }

                return {
                    'error': f'Katana crawl timed out after {crawl_timeout_seconds} seconds for {target}',
                    'endpoints': [],
                    'urls': [],
                    'totalEndpoints': 0,
                    'coverageStatus': 'INCOMPLETE',
                    'coverageReason': 'TIMEOUT_WITHOUT_URL_EVIDENCE',
                    'rootReachable': False,
                    'execution_metrics': execution_metrics
                }

            execution_end = time.time()
            execution_metrics['execution_duration'] = execution_end - execution_start
            # Decode with error handling and sanitize null bytes (consistent with nuclei tools)
            stdout_text = stdout.decode('utf-8', errors='replace').replace('\0', '') if stdout else ''
            stderr_text = stderr.decode('utf-8', errors='replace').replace('\0', '') if stderr else ''
            execution_metrics['stdout_size'] = len(stdout_text)
            execution_metrics['stderr_size'] = len(stderr_text)

            # Check return code
            return_code = await process.wait()

            # Special handling for killed processes (-9 = SIGKILL, often due to memory limits)
            was_killed = return_code == -9
            has_output = stdout_text and len(stdout_text.strip()) > 0

            execution_metrics['return_code'] = return_code
            execution_metrics['was_killed'] = was_killed

            if return_code != 0:
                execution_metrics['error_message'] = stderr_text[:1000]

                if was_killed and has_output:
                    pass  # Continue to parsing section below
                elif not has_output:
                    return {
                        'error': stderr_text or 'Katana failed',
                        'endpoints': [],
                        'urls': [],
                        'totalEndpoints': 0,
                        'coverageStatus': 'INCOMPLETE',
                        'coverageReason': 'PROCESS_FAILED_WITHOUT_URL_EVIDENCE',
                        'rootReachable': False,
                        'execution_metrics': execution_metrics
                    }
                # else: has_output but not killed - continue parsing (might be warnings but valid output)

            # Parse JSON output (one JSON object per line)
            endpoints = []
            urls = []  # Flat list of URLs for easy consumption by other tools
            urls_set = set()  # Track unique URLs to prevent duplicates
            has_errors = False
            root_reachable = False

            parse_errors = 0
            skipped_no_endpoint = 0
            for line in stdout_text.strip().split('\n'):
                if line:
                    try:
                        line = line.replace('\0', '')
                        data = json.loads(line)
                        # Check for error entries - Katana outputs error JSON when connection fails
                        if data.get('error'):
                            has_errors = True
                            error_msg = data.get('error', '')
                            if agent:
                                agent.append_output(f"[Katana] Connection error: {error_msg}")
                            continue

                        # Katana JSONL format has nested structure
                        request = data.get('request', {})
                        response = data.get('response', {})
                        endpoint_url = request.get('endpoint')

                        if not endpoint_url:
                            skipped_no_endpoint += 1
                            continue
                        if not is_same_origin_url(target, endpoint_url):
                            has_errors = True
                            skipped_no_endpoint += 1
                            continue
                        status_code = response.get('status_code')
                        if is_successful_root_observation(target, endpoint_url, status_code):
                            root_reachable = True

                        endpoints.append({
                            'url': endpoint_url,
                            'method': request.get('method', 'GET'),
                            'status_code': status_code,
                            'content_length': response.get('headers', {}).get('content_length'),
                        })

                        # KEEP FULL URLs WITH QUERY PARAMS - Nuclei needs them to test properly
                        if endpoint_url:
                            if endpoint_url not in urls_set:
                                urls_set.add(endpoint_url)
                                urls.append(endpoint_url)
                                if len(urls) >= max_urls:
                                    break
                    except json.JSONDecodeError as e:
                        parse_errors += 1
                        continue

            # If we have errors and no valid endpoints, report the issue
            if has_errors and len(endpoints) == 0:
                if agent:
                    agent.append_output("[Katana] Warning: Connection failed, no endpoints discovered")

            # Apply exclusion filtering to discovered URLs
            if exclusion_url_patterns:
                urls = filter_excluded_urls(urls, exclusion_url_patterns, "Katana")
                endpoints = [ep for ep in endpoints if ep.get('url') in set(urls)]

            # Report completion
            if agent:
                agent.report_progress(
                    current_operation="Katana crawl completed",
                    current_target=target,
                    items_processed=len(endpoints),
                    total_items=len(endpoints)
                )
                agent.append_output(f"[Katana] Discovered {len(urls)} unique URLs (query params preserved)")

            # Limit raw_output size to prevent 413 errors (max 10MB)
            raw_output_limited = stdout_text
            if len(stdout_text) > 10 * 1024 * 1024:  # 10MB
                lines = stdout_text.split('\n')
                raw_output_limited = '\n'.join(lines[:1000]) + f"\n... (truncated, total {len(lines)} lines, {len(stdout_text)} bytes)"
            elif len(stdout_text.split('\n')) > 1000:
                lines = stdout_text.split('\n')
                raw_output_limited = '\n'.join(lines[:1000]) + f"\n... (truncated, total {len(lines)} lines)"

            execution_metrics['parse_errors'] = parse_errors
            execution_metrics['skipped_no_endpoint'] = skipped_no_endpoint
            execution_metrics['has_errors'] = has_errors

            coverage_status, coverage_reason = classify_katana_coverage(
                urls,
                has_errors=has_errors or return_code != 0,
                root_reachable=root_reachable,
            )

            # Build return value
            result = {
                'success': True,
                'target': target,
                'endpoints': endpoints,
                'urls': urls,  # Flat array for workflow chaining
                'totalEndpoints': len(endpoints),
                'coverageStatus': coverage_status,
                'coverageReason': coverage_reason,
                'rootReachable': root_reachable,
                'raw_output': raw_output_limited,  # Limited to prevent 413 errors
                'execution_metrics': execution_metrics
            }

            # Add warning if process was killed but we still have results
            if was_killed and len(endpoints) > 0:
                result['warning'] = f'Process was killed (return code -9) but {len(endpoints)} endpoints were successfully parsed from captured output. Results may be incomplete.'

            # #600 — return a DICT (NOT a list). Every consumer of katana output
            # expects a dict with top-level urls/endpoints: workflow chaining
            # ({{json stepN.output.urls}}), ingestion processKatanaOutput
            # (reads output.urls/output.endpoints), and the backend
            # normalizeToolOutputShape. The prior BUG-264 list shape was wrapped
            # into `error` by normalizeToolOutputShape, dropping output.urls and
            # breaking both the DAST handoff and katana asset ingestion.
            return result
        except FileNotFoundError:
            return {
                'error': 'Katana not installed. Install with: go install github.com/projectdiscovery/katana/cmd/katana@latest',
                'endpoints': [],
                'urls': [],
                'totalEndpoints': 0,
                'coverageStatus': 'INCOMPLETE',
                'coverageReason': 'KATANA_NOT_INSTALLED',
                'rootReachable': False,
            }
        except Exception as e:
            return {
                'error': str(e),
                'endpoints': [],
                'urls': [],
                'totalEndpoints': 0,
                'coverageStatus': 'INCOMPLETE',
                'coverageReason': 'KATANA_EXECUTION_ERROR',
                'rootReachable': False,
            }

    async def _crawl_multiple_targets(
        self,
        targets_list: list,
        depth: int,
        max_urls: int,
        headers_file: str,
        cookie: str,
        agent,
        parameters: Dict[str, Any]
    ) -> dict:
        """Crawl multiple targets and return an aggregated dict.

        #600 — returns a DICT with top-level deduped urls/endpoints (so workflow
        chaining {{json stepN.output.urls}}, ingestion, and the backend
        normalizeToolOutputShape all see output.urls), keeping the per-target
        breakdown under `perTarget`. Previously returned a bare list, which the
        backend wrapped into `error`, dropping output.urls.
        """
        if agent:
            agent.report_progress(
                current_operation=f"Starting Katana crawl on {len(targets_list)} targets",
                current_target=targets_list[0],
                items_processed=0,
                total_items=len(targets_list)
            )
            agent.append_output(f"[Katana] Crawling {len(targets_list)} targets (depth: {depth})")

        results = []
        total_soft_budget = bounded_katana_timeout(
            parameters,
            max(30, len(targets_list) * 130),
        )
        soft_deadline = time.monotonic() + total_soft_budget

        for idx, target in enumerate(targets_list):
            if agent:
                agent.report_progress(
                    current_operation=f"Crawling target {idx + 1}/{len(targets_list)}",
                    current_target=target,
                    items_processed=idx,
                    total_items=len(targets_list)
                )

            remaining_budget = int(soft_deadline - time.monotonic())
            if remaining_budget <= 10:
                results.append({
                    'target': target,
                    'error': f'{target}: agent watchdog margin exhausted before crawl',
                    'endpoints': [],
                    'urls': [],
                    'totalEndpoints': 0,
                    'coverageStatus': 'INCOMPLETE',
                    'coverageReason': 'AGENT_WATCHDOG_MARGIN_EXHAUSTED',
                    'rootReachable': False,
                })
                if agent:
                    agent.append_output(
                        f"  [Katana] {target}: skipped to preserve agent watchdog margin"
                    )
                continue

            target_timeout = min(120, max(5, remaining_budget - 10))

            # Build command for this target.  The communicate timeout retains a
            # five-second group-teardown margin inside the aggregate budget.
            cmd = [
                'katana', '-u', target, '-d', str(depth),
                '-ct', f'{target_timeout}s', '-jsonl', '-silent', '-nc'
            ]
            cmd.extend(exact_origin_scope_options(target))

            # Add rate limiting
            from tools._scope_utils import extract_rate_limit
            rl = extract_rate_limit(parameters)
            cmd = add_katana_options(cmd, parameters, rl)

            try:
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    start_new_session=True,
                )
                process_reaper.register_group(process)

                timed_out = False
                try:
                    # Per-target timeout is bounded by the aggregate watchdog margin.
                    stdout, stderr = await asyncio.wait_for(
                        process.communicate(),
                        timeout=target_timeout + 5
                    )
                except asyncio.TimeoutError:
                    timed_out = True
                    await process_reaper.terminate_group(process)
                    stdout = b''
                    stderr = b''
                    try:
                        if process.stdout:
                            stdout = await process.stdout.read()
                    except Exception:
                        pass
                    try:
                        if process.stderr:
                            stderr = await process.stderr.read()
                    except Exception:
                        pass

                stdout_text = stdout.decode('utf-8', errors='replace').replace('\0', '') if stdout else ''

                # Parse results for this target
                target_endpoints = []
                target_urls = []
                urls_set = set()
                target_has_errors = timed_out
                target_root_reachable = False
                for line in stdout_text.strip().split('\n'):
                    if line:
                        try:
                            line = line.replace('\0', '')
                            data = json.loads(line)
                            if data.get('error'):
                                target_has_errors = True
                                continue
                            request = data.get('request', {})
                            response = data.get('response', {})
                            endpoint_url = request.get('endpoint')

                            if endpoint_url:
                                if not is_same_origin_url(target, endpoint_url):
                                    target_has_errors = True
                                    continue
                                status_code = response.get('status_code')
                                if is_successful_root_observation(target, endpoint_url, status_code):
                                    target_root_reachable = True
                                target_endpoints.append({
                                    'url': endpoint_url,
                                    'method': request.get('method', 'GET'),
                                    'status_code': response.get('status_code'),
                                })
                                if endpoint_url not in urls_set:
                                    urls_set.add(endpoint_url)
                                    target_urls.append(endpoint_url)
                        except json.JSONDecodeError:
                            continue

                # Apply exclusion filtering
                from tools._scope_utils import extract_exclusion_patterns, filter_excluded_urls
                excl = extract_exclusion_patterns(parameters)
                if excl:
                    target_urls = filter_excluded_urls(target_urls, excl, "Katana")
                    target_endpoints = [ep for ep in target_endpoints if ep.get('url') in set(target_urls)]

                target_coverage, target_coverage_reason = classify_katana_coverage(
                    target_urls,
                    has_errors=target_has_errors or process.returncode not in (0, None),
                    root_reachable=target_root_reachable,
                )

                result = {
                    'target': target,
                    'endpoints': target_endpoints,
                    'urls': target_urls,
                    'totalEndpoints': len(target_endpoints),
                    'coverageStatus': target_coverage,
                    'coverageReason': target_coverage_reason,
                    'rootReachable': target_root_reachable,
                }
                if timed_out:
                    result['error'] = f'{target}: timeout'
                    result['partialResults'] = bool(target_urls)
                results.append(result)
                if agent:
                    suffix = " (partial timeout result)" if timed_out else ""
                    agent.append_output(
                        f"  [Katana] {target}: {len(target_endpoints)} endpoints{suffix}"
                    )

            except Exception as e:
                results.append({
                    'target': target,
                    'error': str(e),
                    'endpoints': [],
                    'urls': [],
                    'totalEndpoints': 0,
                    'coverageStatus': 'INCOMPLETE',
                    'coverageReason': 'KATANA_EXECUTION_ERROR',
                    'rootReachable': False,
                })
                if agent:
                    agent.append_output(f"  [Katana] {target}: {str(e)}")

        # #600 — aggregate per-target results into a DICT with top-level
        # deduped urls/endpoints so downstream chaining + ingestion +
        # normalizeToolOutputShape all see output.urls. `perTarget` keeps the
        # per-target breakdown; per-target errors are surfaced without dropping
        # the aggregated data.
        all_urls = []
        seen_urls = set()
        all_endpoints = []
        per_target_errors = []
        for r in results:
            for u in (r.get('urls') or []):
                if u not in seen_urls:
                    seen_urls.add(u)
                    all_urls.append(u)
            all_endpoints.extend(r.get('endpoints') or [])
            if r.get('error'):
                per_target_errors.append(r['error'])
            elif r.get('coverageStatus') == 'INCOMPLETE':
                per_target_errors.append(
                    f"{r.get('target')}: {r.get('coverageReason') or 'INCOMPLETE'}"
                )

        if agent:
            agent.append_output(
                f"[Katana] Total: {len(all_endpoints)} endpoints from {len(targets_list)} targets"
            )

        coverage_status, coverage_reason = classify_katana_coverage(
            all_urls,
            has_errors=bool(per_target_errors) or any(
                r.get('coverageStatus') == 'INCOMPLETE' for r in results
            ),
            root_reachable=any(bool(r.get('rootReachable')) for r in results),
        )

        aggregated = {
            'success': True,
            'targets': targets_list,
            'urls': all_urls,
            'endpoints': all_endpoints,
            'totalEndpoints': len(all_endpoints),
            'perTarget': results,
            'coverageStatus': coverage_status,
            'coverageReason': coverage_reason,
            'rootReachable': any(bool(r.get('rootReachable')) for r in results),
        }
        if per_target_errors:
            aggregated['partialErrors'] = per_target_errors
        return aggregated


def get_tool():
    return KatanaCrawlTool()
