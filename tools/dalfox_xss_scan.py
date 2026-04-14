"""
Dalfox XSS Scanner Tool
Cross-Site Scripting (XSS) vulnerability detection using Dalfox.
Scans URL parameters for reflected, stored, and DOM-based XSS vulnerabilities.
IMPORTANT: Target URLs must include query parameters (e.g., ?q=test) for XSS testing.
"""

import asyncio
import json
import os
import time
from datetime import datetime
from plugin_interface import ToolPlugin
from typing import Dict, Any


class DalfoxXssScanTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "dalfox:xss_scan"

    @property
    def description(self) -> str:
        return "XSS vulnerability scanner - tests URL parameters for reflected, stored, and DOM-based Cross-Site Scripting. Targets MUST have query parameters (e.g. ?q=test&page=1)"

    @property
    def schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Single target URL with parameters (e.g., http://example.com/search?q=test)"
                },
                "targets": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Multiple target URLs with parameters to scan (alternative to target)"
                },
                "authUsername": {
                    "type": "string",
                    "description": "Username for HTTP basic authentication",
                    "x-hidden": True
                },
                "authPassword": {
                    "type": "string",
                    "description": "Password for HTTP basic authentication",
                    "x-hidden": True
                },
                "authCookies": {
                    "type": "string",
                    "description": "Session cookies (format: 'name1=value1; name2=value2')",
                    "x-hidden": True
                },
                "authHeaders": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Custom HTTP headers for authentication (format: 'Header: Value')",
                    "x-hidden": True
                },
                "maxTargets": {
                    "type": "integer",
                    "description": "Maximum number of targets to scan from array (default: 50)",
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
            "category": "exploit-test",
            "phase": 5,
            "domain": ["web"],
            "input_type": ["url_with_params"],
            "output_type": ["findings"],
            "chainable_after": ["katana:", "waybackurls:"],
            "chainable_before": [],
        }

    async def execute(self, parameters: Dict[str, Any]) -> Any:
        """Execute Dalfox XSS scan"""
        target = parameters.get("target")
        targets = parameters.get("targets")
        job_id = parameters.get("_job_id", "unknown")
        agent = parameters.get("_agent")

        # Extract authentication parameters
        auth_username = parameters.get("authUsername")
        auth_password = parameters.get("authPassword")
        auth_cookies = parameters.get("authCookies")
        auth_headers = parameters.get("authHeaders", [])

        # Extract exclusion patterns and rate limiting
        from tools._scope_utils import extract_exclusion_patterns, extract_rate_limit, filter_excluded_urls
        exclusion_url_patterns = extract_exclusion_patterns(parameters)
        rate_limit_config = extract_rate_limit(parameters)

        if not target and not targets:
            return {"success": False, "error": "Either 'target' or 'targets' required"}

        try:
            import base64

            output_dir = "/tmp/agent_outputs"
            os.makedirs(output_dir, exist_ok=True)

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

            target_file = None
            scan_target = target if target else f"{len(targets) if targets else 0} targets"

            if targets:
                # Handle case where targets might be a JSON string instead of array
                if isinstance(targets, str):
                    try:
                        targets = json.loads(targets)
                    except json.JSONDecodeError:
                        targets = [targets]
                if not isinstance(targets, list):
                    targets = [targets]

                # Apply maxTargets limit
                max_targets = parameters.get('maxTargets', 50)
                if len(targets) > max_targets:
                    print(f"[Dalfox] Limiting {len(targets)} targets to {max_targets}")
                    targets = targets[:max_targets]

                # Filter to only URLs with query parameters (XSS needs params to test)
                urls_with_params = [u for u in targets if '?' in u and '=' in u]
                urls_without_params = [u for u in targets if '?' not in u or '=' not in u]

                if urls_without_params:
                    print(f"[Dalfox] Skipping {len(urls_without_params)} URLs without query parameters (XSS testing requires params)")

                if urls_with_params:
                    # Apply exclusion filtering
                    if exclusion_url_patterns:
                        urls_with_params = filter_excluded_urls(urls_with_params, exclusion_url_patterns, "Dalfox")
                    print(f"[Dalfox] Scanning {len(urls_with_params)} URLs with query parameters")
                    targets = urls_with_params
                else:
                    return {
                        "success": False,
                        "error": f"No URLs with query parameters found. Dalfox XSS testing requires URLs with parameters (e.g., ?q=test). All {len(urls_without_params)} provided URLs lack query parameters.",
                        "output": {
                            "findings": [],
                            "total_findings": 0,
                            "findings_delivered": 0,
                            "target": scan_target,
                            "targets": targets,
                            "tool": "dalfox",
                            "scan_type": "xss",
                            "skipped_urls": urls_without_params
                        },
                        "raw_output": ""
                    }

                target_file = f"{output_dir}/dalfox_targets_{job_id[:8]}_{timestamp}.txt"
                with open(target_file, 'w') as f:
                    f.write('\n'.join(targets))
                print(f"[Dalfox] Scanning {len(targets)} target URLs for XSS")
            else:
                if '?' not in target or '=' not in target:
                    print(f"[Dalfox] WARNING: Target '{target}' has no query parameters. XSS testing works best with URLs like ?q=test")
                print(f"[Dalfox] Scanning {target}")

            # Compute total_targets AFTER all target resolution/filtering
            total_targets = len(targets) if targets else 1

            # Build dalfox command
            if targets:
                cmd = [
                    "dalfox", "file", target_file,
                    "--format", "json",
                    "--silence"
                ]
            else:
                cmd = [
                    "dalfox", "url", target,
                    "--format", "json",
                    "--silence"
                ]

            # Apply rate limiting (dalfox uses --delay in milliseconds and --worker)
            if rate_limit_config:
                if rate_limit_config.get('rateLimit'):
                    delay_ms = max(1, int(1000 / rate_limit_config['rateLimit']))
                    cmd.extend(["--delay", str(delay_ms)])
                if rate_limit_config.get('concurrency'):
                    cmd.extend(["--worker", str(rate_limit_config['concurrency'])])
                print(f"[Dalfox] Rate limit: {rate_limit_config.get('rateLimit')} req/s")

            # Also apply exclusion for single target
            if target and not targets and exclusion_url_patterns:
                from tools._scope_utils import filter_excluded_urls as _feu
                if not _feu([target], exclusion_url_patterns, ""):
                    return {
                        "success": True,
                        "output": {
                            "findings": [], "total_findings": 0, "findings_delivered": 0,
                            "target": target, "targets": [target], "tool": "dalfox",
                            "scan_type": "xss", "note": "Target excluded by exclusion patterns"
                        },
                        "raw_output": ""
                    }

            # Add authentication options
            auth_used = False
            if auth_username and auth_password:
                auth_str = f"{auth_username}:{auth_password}"
                auth_b64 = base64.b64encode(auth_str.encode()).decode()
                cmd.extend(["--header", f"Authorization: Basic {auth_b64}"])
                print(f"[Dalfox] Using HTTP Basic Authentication (user: {auth_username})")
                auth_used = True

            if auth_cookies:
                cmd.extend(["--cookie", auth_cookies])
                print(f"[Dalfox] Using session cookies (***REDACTED***)")
                auth_used = True

            if auth_headers:
                for header in auth_headers:
                    if header and header.strip():
                        cmd.extend(["--header", header])
                        print(f"[Dalfox] Added custom header")
                auth_used = True

            if auth_used:
                print(f"[Dalfox] Authenticated XSS scan mode enabled")
            else:
                print(f"[Dalfox] Public/unauthenticated XSS scan mode")

            # Report initial progress
            if agent:
                agent.report_progress(
                    current_operation="Starting Dalfox XSS scan",
                    current_target=scan_target,
                    items_processed=0,
                    total_items=total_targets
                )

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            findings = []
            line_buffer = b""
            last_progress_update = time.time()
            progress_update_interval = 5.0
            start_time = time.time()

            # 30 minute timeout for XSS scanning
            try:
                async def read_output():
                    nonlocal line_buffer, last_progress_update

                    async def read_stderr():
                        """Read stderr in parallel to capture errors"""
                        while True:
                            chunk = await process.stderr.read(1024)
                            if not chunk:
                                break
                            stderr_line = chunk.decode('utf-8', errors='replace').strip()
                            if stderr_line:
                                print(f"[Dalfox] stderr: {stderr_line}")

                    # Start reading stderr in background
                    stderr_task = asyncio.create_task(read_stderr())

                    try:
                        while True:
                            chunk = await process.stdout.read(1024)
                            if not chunk:
                                break

                            line_buffer += chunk
                            while b'\n' in line_buffer:
                                line, line_buffer = line_buffer.split(b'\n', 1)
                                # Decode with error handling and sanitize null bytes
                                line_str = line.decode('utf-8', errors='replace').strip().replace('\0', '')

                                if line_str:
                                    try:
                                        finding = json.loads(line_str)
                                        findings.append(finding)

                                        # Report progress with finding details
                                        if agent:
                                            agent.report_progress(
                                                current_operation="XSS parameter fuzzing",
                                                current_target=scan_target,
                                                items_processed=len(findings),
                                                total_items=total_targets
                                            )
                                            # Stream finding details
                                            finding_type = finding.get('type', 'Unknown')
                                            finding_severity = finding.get('severity', 'unknown')
                                            finding_param = finding.get('param', 'N/A')
                                            finding_poc = finding.get('data', finding.get('poc', 'N/A'))
                                            # Truncate long PoC URLs for output
                                            if len(str(finding_poc)) > 200:
                                                finding_poc = str(finding_poc)[:200] + "..."
                                            agent.append_output(
                                                f"[Dalfox] Found XSS: type={finding_type}, "
                                                f"severity={finding_severity}, param={finding_param}"
                                            )
                                    except json.JSONDecodeError:
                                        # Not a JSON finding line, skip
                                        pass

                            # Periodic progress update even if no findings yet
                            current_time = time.time()
                            elapsed = current_time - start_time
                            if agent and (current_time - last_progress_update) >= progress_update_interval:
                                agent.report_progress(
                                    current_operation="XSS parameter fuzzing",
                                    current_target=scan_target,
                                    items_processed=len(findings),
                                    total_items=total_targets
                                )
                                if len(findings) == 0:
                                    agent.append_output(f"[Dalfox] Scanning in progress... ({int(elapsed)}s elapsed)")
                                last_progress_update = current_time

                    finally:
                        stderr_task.cancel()
                        try:
                            await stderr_task
                        except asyncio.CancelledError:
                            pass

                    await process.wait()

                await asyncio.wait_for(read_output(), timeout=1800)  # 30 minutes

            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                # Cleanup target file
                if target_file and os.path.exists(target_file):
                    try:
                        os.remove(target_file)
                    except Exception:
                        pass

                print(f"[Dalfox] Scan timed out after 30 minutes, returning {len(findings)} partial findings")

                # Strip heavy fields and build raw output from partial findings
                partial_stripped = self._strip_findings(findings)

                raw_output_sanitized = self._build_raw_output(partial_stripped)

                total_found = len(partial_stripped)
                if len(partial_stripped) > 2000:
                    partial_stripped = partial_stripped[:2000]

                return {
                    "success": False,
                    "error": f"Dalfox XSS scan timed out after 30 minutes for {scan_target}",
                    "output": {
                        "findings": partial_stripped,
                        "total_findings": total_found,
                        "findings_delivered": len(partial_stripped),
                        "target": target if target else f"{len(targets)} targets",
                        "targets": targets if targets else [target],
                        "tool": "dalfox",
                        "scan_type": "xss",
                        "partial": True
                    },
                    "raw_output": raw_output_sanitized
                }

            # Cleanup target file
            if target_file and os.path.exists(target_file):
                try:
                    os.remove(target_file)
                except Exception as e:
                    print(f"[Dalfox] Warning: Could not delete target file: {e}")

            print(f"[Dalfox] Found {len(findings)} total XSS findings")

            # Strip heavy fields from findings
            findings_stripped = self._strip_findings(findings)

            # Build raw output
            raw_output_sanitized = self._build_raw_output(findings_stripped)

            # Cap findings at 2000 to keep payload under 10MB
            total_found = len(findings_stripped)
            if len(findings_stripped) > 2000:
                findings_stripped = findings_stripped[:2000]
                print(f"[Dalfox] Capped findings from {total_found} to 2000 for delivery")

            # Final progress report
            if agent:
                agent.report_progress(
                    current_operation="Dalfox XSS scan completed",
                    current_target=scan_target,
                    items_processed=total_found,
                    total_items=total_found
                )

            return {
                "success": True,
                "output": {
                    "findings": findings_stripped,
                    "total_findings": total_found,
                    "findings_delivered": len(findings_stripped),
                    "target": target if target else f"{len(targets)} targets",
                    "targets": targets if targets else [target],
                    "tool": "dalfox",
                    "scan_type": "xss"
                },
                "raw_output": raw_output_sanitized
            }
        except FileNotFoundError:
            return {
                "success": False,
                "error": "Dalfox not installed. Install with: go install github.com/hahwul/dalfox/v2@latest",
                "output": {
                    "findings": [],
                    "total_findings": 0,
                    "findings_delivered": 0,
                    "target": parameters.get("target", ""),
                    "targets": [],
                    "tool": "dalfox",
                    "scan_type": "xss"
                },
                "raw_output": ""
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Error running Dalfox: {str(e)}",
                "output": {
                    "findings": [],
                    "total_findings": 0,
                    "findings_delivered": 0,
                    "target": parameters.get("target", ""),
                    "targets": [],
                    "tool": "dalfox",
                    "scan_type": "xss"
                },
                "raw_output": ""
            }

    def _strip_findings(self, findings: list) -> list:
        """Strip heavy fields from findings and sanitize null bytes"""
        stripped = []
        for finding in findings:
            f = dict(finding)
            # Dalfox findings are typically lightweight, but strip any large fields
            f.pop("raw_request", None)
            f.pop("raw_response", None)
            f.pop("response", None)
            f.pop("request", None)
            # Sanitize null bytes
            f_str = json.dumps(f).replace('\0', '')
            stripped.append(json.loads(f_str))
        return stripped

    def _build_raw_output(self, findings: list) -> str:
        """Build raw output string from findings, limited to 5MB"""
        if not findings:
            return ""
        raw_lines = [json.dumps(f) for f in findings]
        raw_output = '\n'.join(raw_lines)
        # Limit to 5MB to prevent 413 errors
        if len(raw_output) > 5 * 1024 * 1024:
            raw_output = '\n'.join(raw_lines[:1000]) + f"\n... (truncated, total {len(raw_lines)} lines)"
        return raw_output


def get_tool():
    return DalfoxXssScanTool()
