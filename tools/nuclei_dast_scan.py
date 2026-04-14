"""
Nuclei DAST Scan
Dynamic Application Security Testing using nuclei's fuzzing engine.
Actively fuzzes URL parameters, headers, and form fields to detect SQLi, XSS,
SSTI, SSRF, LFI, CRLF injection, and other input-based vulnerabilities.
IMPORTANT: Target URLs must include query parameters (e.g., ?id=1) for fuzzing to work.
"""

import asyncio
import json
import os
from plugin_interface import ToolPlugin


class NucleiDastScanTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "nuclei:dast_scan"

    @property
    def description(self) -> str:
        return "DAST fuzzing scan - actively tests URL parameters for SQLi, XSS, SSTI, SSRF, LFI, command injection. Targets MUST have query parameters (e.g. ?id=1&name=test)"

    @property
    def schema(self):
        return {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Single target URL with parameters (e.g., http://example.com/page.php?id=1)"
                },
                "targets": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Multiple target URLs with parameters to fuzz (alternative to target)"
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
                    "description": "Custom HTTP headers for authentication",
                    "x-hidden": True
                },
                "maxTargets": {
                    "type": "integer",
                    "description": "Maximum number of targets to scan from array (default: 100)",
                    "default": 100
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
            "category": "vuln-scan",
            "phase": 4,
            "domain": ["web"],
            "input_type": ["url"],
            "output_type": ["findings"],
            "chainable_after": ["httpx:probe", "katana:"],
            "chainable_before": [],
        }

    async def execute(self, parameters: dict):
        """Execute Nuclei DAST scan with fuzzing templates"""
        target = parameters.get("target")
        targets = parameters.get("targets")
        job_id = parameters.get("_job_id", "unknown")
        agent = parameters.get("_agent")

        # Extract authentication parameters
        auth_username = parameters.get("authUsername")
        auth_password = parameters.get("authPassword")
        auth_cookies = parameters.get("authCookies")
        auth_headers = parameters.get("authHeaders", [])

        # Extract exclusion patterns
        exclusion_patterns = parameters.get("exclusionPatterns") or parameters.get("exclusionRules")
        exclusion_url_patterns = []
        if exclusion_patterns and isinstance(exclusion_patterns, dict):
            exclusion_url_patterns = exclusion_patterns.get("urlPatterns", [])

        if not target and not targets:
            return {"success": False, "error": "Either 'target' or 'targets' required"}

        try:
            import os
            import time
            import base64
            from datetime import datetime

            output_dir = "/tmp/agent_outputs"
            os.makedirs(output_dir, exist_ok=True)

            # Generate timestamp for unique filenames
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
                max_targets = parameters.get('maxTargets', 100)
                if len(targets) > max_targets:
                    print(f"[Nuclei DAST] Limiting {len(targets)} targets to {max_targets}")
                    targets = targets[:max_targets]

                # Filter to only URLs with query parameters (DAST needs params to fuzz)
                urls_with_params = [u for u in targets if '?' in u and '=' in u]
                urls_without_params = [u for u in targets if '?' not in u or '=' not in u]

                if urls_without_params:
                    print(f"[Nuclei DAST] Skipping {len(urls_without_params)} URLs without query parameters (DAST requires params to fuzz)")
                if urls_with_params:
                    print(f"[Nuclei DAST] Scanning {len(urls_with_params)} URLs with query parameters")
                    targets = urls_with_params
                else:
                    print(f"[Nuclei DAST] WARNING: No URLs with query parameters found. DAST fuzzing requires URLs like ?id=1&name=test")
                    print(f"[Nuclei DAST] Proceeding with all {len(targets)} URLs (global matchers only)")

                target_file = f"{output_dir}/targets_{job_id[:8]}_{timestamp}.txt"
                with open(target_file, 'w') as f:
                    f.write('\n'.join(targets))
                scan_target = f"{len(targets)} targets"
                print(f"[Nuclei DAST] Fuzzing {len(targets)} target URLs")
            else:
                if '?' not in target or '=' not in target:
                    print(f"[Nuclei DAST] WARNING: Target '{target}' has no query parameters. DAST works best with URLs like ?id=1")
                print(f"[Nuclei DAST] Fuzzing {target}")

            # BUG: nuclei -u flag doesn't work reliably in Docker containers
            # Always use -l with a temp file for consistent results
            if not target_file:
                target_file = f"{output_dir}/targets_{job_id[:8]}_{timestamp}.txt"
                with open(target_file, 'w') as f:
                    f.write(target)

            # Compute total_targets AFTER all target resolution/filtering
            total_targets = len(targets) if targets else 1

            cmd = [
                "nuclei",
                "-l", target_file,
                "-dast",
                "-t", os.environ.get('NUCLEI_DAST_TEMPLATES', '/root/nuclei-templates/dast/'),  # DAST vuln templates
                "-jsonl",
                "-silent",
                "-no-mhe",
                "-timeout", "15",
                "-no-color"
            ]

            # Add authentication headers if provided
            auth_used = False
            if auth_username and auth_password:
                auth_str = f"{auth_username}:{auth_password}"
                auth_b64 = base64.b64encode(auth_str.encode()).decode()
                cmd.extend(["-H", f"Authorization: Basic {auth_b64}"])
                print(f"[Nuclei DAST] Using HTTP Basic Authentication (user: {auth_username})")
                auth_used = True

            if auth_cookies:
                cmd.extend(["-H", f"Cookie: {auth_cookies}"])
                print(f"[Nuclei DAST] Using session cookies (***REDACTED***)")
                auth_used = True

            if auth_headers:
                for header in auth_headers:
                    if header and header.strip():
                        cmd.extend(["-H", header])
                        print(f"[Nuclei DAST] Added custom header")
                auth_used = True

            if auth_used:
                print(f"[Nuclei DAST] Authenticated DAST scan mode enabled")
            else:
                print(f"[Nuclei DAST] Public/unauthenticated DAST scan mode")

            # Write exclusion patterns to temp file for nuclei -exclude-targets
            exclude_file = None
            if exclusion_url_patterns:
                exclude_file = f"{output_dir}/exclude_{job_id[:8]}_{timestamp}.txt"
                with open(exclude_file, 'w') as f:
                    f.write('\n'.join(exclusion_url_patterns))
                cmd.extend(["-exclude-targets", exclude_file])
                print(f"[Nuclei DAST] Excluding {len(exclusion_url_patterns)} URL patterns")

            # Apply rate limiting
            from tools._scope_utils import extract_rate_limit
            rate_limit_config = extract_rate_limit(parameters)
            if rate_limit_config:
                cmd.extend(["-rl", str(rate_limit_config["rateLimit"])])
                cmd.extend(["-c", str(rate_limit_config["concurrency"])])
                print(f"[Nuclei DAST] Rate limit: {rate_limit_config['rateLimit']} req/s, concurrency: {rate_limit_config['concurrency']}")

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            findings = []
            line_buffer = b""
            last_progress_update = time.time()
            progress_update_interval = 5.0  # Update progress every 5 seconds
            start_time = time.time()

            # DAST fuzzing scans can be slow with many parameters, 90 minutes max
            try:
                async def read_output():
                    nonlocal line_buffer, last_progress_update

                    async def read_stderr():
                        """Read stderr in parallel to capture errors"""
                        stderr_buffer = []
                        while True:
                            chunk = await process.stderr.read(1024)
                            if not chunk:
                                break
                            stderr_line = chunk.decode('utf-8', errors='replace').strip()
                            if stderr_line:
                                stderr_buffer.append(stderr_line)
                                print(f"[Nuclei DAST] stderr: {stderr_line}")

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

                                        # Report progress with finding count
                                        if agent:
                                            items_processed = len(findings)
                                            agent.report_progress(
                                                current_operation="DAST fuzzing parameters",
                                                current_target=scan_target,
                                                items_processed=items_processed,
                                                total_items=total_targets
                                            )
                                            # Stream output
                                            finding_name = finding.get('info', {}).get('name', 'Unknown')
                                            finding_severity = finding.get('info', {}).get('severity', 'unknown').upper()
                                            finding_url = finding.get('matched-at', 'N/A')
                                            agent.append_output(f"[Nuclei DAST] Found: {finding_name} ({finding_severity}) at {finding_url}")
                                    except json.JSONDecodeError:
                                        # Not a JSON finding, might be progress output
                                        pass

                            # Periodic progress update even if no findings yet
                            current_time = time.time()
                            elapsed = current_time - start_time
                            if agent and (current_time - last_progress_update) >= progress_update_interval:
                                agent.report_progress(
                                    current_operation="DAST fuzzing parameters",
                                    current_target=scan_target,
                                    items_processed=len(findings),
                                    total_items=total_targets
                                )
                                if len(findings) == 0:
                                    agent.append_output(f"[Nuclei DAST] Scanning in progress... ({int(elapsed)}s elapsed)")
                                last_progress_update = current_time

                    finally:
                        stderr_task.cancel()
                        try:
                            await stderr_task
                        except asyncio.CancelledError:
                            pass

                    await process.wait()

                await asyncio.wait_for(read_output(), timeout=5400)  # 90 minutes

            except asyncio.TimeoutError:
                # Kill the process if it times out
                process.kill()
                await process.wait()
                # Cleanup temp files
                if target_file and os.path.exists(target_file):
                    try:
                        os.remove(target_file)
                    except Exception:
                        pass
                if exclude_file and os.path.exists(exclude_file):
                    try:
                        os.remove(exclude_file)
                    except Exception:
                        pass

                print(f"[Nuclei DAST] Scan timed out after 90 minutes, returning {len(findings)} partial findings")

                # Strip heavy fields and build raw output from partial findings
                partial_stripped = []
                for finding in findings:
                    f = dict(finding)
                    f.pop("response", None)
                    f.pop("request", None)
                    f.pop("curl-command", None)
                    f_str = json.dumps(f).replace('\0', '')
                    partial_stripped.append(json.loads(f_str))

                raw_output_sanitized = ""
                if partial_stripped:
                    raw_lines = [json.dumps(f) for f in partial_stripped]
                    raw_output_sanitized = "\n".join(raw_lines)
                    if len(raw_output_sanitized) > 10 * 1024 * 1024:
                        raw_output_sanitized = '\n'.join(raw_lines[:1000]) + f"\n... (truncated, total {len(raw_lines)} lines)"

                total_found = len(partial_stripped)
                if len(partial_stripped) > 2000:
                    partial_stripped = partial_stripped[:2000]

                return {
                    "success": False,
                    "error": f"Nuclei DAST scan timed out after 90 minutes for {scan_target}",
                    "output": {
                        "findings": partial_stripped,
                        "total_findings": total_found,
                        "findings_delivered": len(partial_stripped),
                        "target": target if target else f"{len(targets)} targets",
                        "targets": targets if targets else [target],
                        "tool": "nuclei",
                        "scan_type": "dast",
                        "partial": True
                    },
                    "raw_output": raw_output_sanitized
                }

            if target_file and os.path.exists(target_file):
                try:
                    os.remove(target_file)
                except Exception as e:
                    print(f"[Nuclei DAST] Warning: Could not delete target file: {e}")

            if exclude_file and os.path.exists(exclude_file):
                try:
                    os.remove(exclude_file)
                except Exception as e:
                    print(f"[Nuclei DAST] Warning: Could not delete exclude file: {e}")

            print(f"[Nuclei DAST] Found {len(findings)} total findings")

            # Strip heavy fields (request/response/curl-command) from findings
            # to reduce payload size. DAST generates thousands of findings with
            # full HTTP bodies that can exceed 80MB total.
            findings_stripped = []
            for finding in findings:
                f = dict(finding)
                f.pop("response", None)
                f.pop("request", None)
                f.pop("curl-command", None)
                # Sanitize null bytes
                f_str = json.dumps(f).replace('\0', '')
                findings_stripped.append(json.loads(f_str))

            # Build raw output from stripped findings
            raw_output_sanitized = ""
            if findings_stripped:
                raw_lines = [json.dumps(f) for f in findings_stripped]
                raw_output_sanitized = '\n'.join(raw_lines)
                # Limit to 5MB to prevent 413 errors
                if len(raw_output_sanitized) > 5 * 1024 * 1024:
                    raw_output_sanitized = '\n'.join(raw_lines[:1000]) + f"\n... (truncated, total {len(raw_lines)} lines)"

            # Cap findings at 2000 to keep payload under 10MB
            total_found = len(findings_stripped)
            if len(findings_stripped) > 2000:
                findings_stripped = findings_stripped[:2000]
                print(f"[Nuclei DAST] Capped findings from {total_found} to 2000 for delivery")

            return {
                "success": True,
                "output": {
                    "findings": findings_stripped,
                    "total_findings": total_found,
                    "findings_delivered": len(findings_stripped),
                    "target": target if target else f"{len(targets)} targets",
                    "targets": targets if targets else [target],
                    "tool": "nuclei",
                    "scan_type": "dast"
                },
                "raw_output": raw_output_sanitized
            }
        except FileNotFoundError:
            return {"success": False, "error": "Nuclei not installed or -dast flag not supported (requires nuclei v3.3.0+)"}
        except Exception as e:
            return {"success": False, "error": str(e)}


def get_tool():
    return NucleiDastScanTool()
