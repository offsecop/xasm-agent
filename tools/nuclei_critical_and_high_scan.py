"""
Nuclei Critical and High Severity Scan
Scans for both CRITICAL and HIGH severity vulnerabilities
"""

import asyncio
import json
from plugin_interface import ToolPlugin


class NucleiCriticalAndHighScanTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "nuclei:critical_and_high_scan"

    @property
    def description(self) -> str:
        return "Scans for CRITICAL and HIGH severity vulnerabilities using Nuclei"

    @property
    def schema(self):
        return {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Single target URL (e.g., http://example.com)"
                },
                "targets": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Multiple target URLs to scan (alternative to target)"
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
                "authHeadersFile": {
                    "type": "string",
                    "description": "Path to file containing HTTP headers (from scripted_browser_login step)"
                },
                "secretsFile": {
                    "type": "string",
                    "description": "Path to Nuclei secrets YAML file (from scripted_browser_login step)"
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
        """Execute Nuclei critical and high severity scan"""
        target = parameters.get("target")
        targets = parameters.get("targets")
        job_id = parameters.get("_job_id", "unknown")
        agent = parameters.get("_agent")  # Get agent reference for progress reporting

        # Extract authentication parameters
        auth_username = parameters.get("authUsername")
        auth_password = parameters.get("authPassword")
        auth_cookies = parameters.get("authCookies")
        auth_headers = parameters.get("authHeaders", [])
        auth_headers_file = parameters.get("authHeadersFile")  # Phase 2: Auth files from scripted_browser_login
        secrets_file = parameters.get("secretsFile")  # Phase 2: Nuclei secrets file

        # Extract exclusion patterns and rate limiting
        from tools._scope_utils import extract_exclusion_patterns, extract_rate_limit
        exclusion_url_patterns = extract_exclusion_patterns(parameters)
        rate_limit_config = extract_rate_limit(parameters)

        if not target and not targets:
            return {"success": False, "error": "Either 'target' or 'targets' required"}

        try:
            import os
            import time
            import base64
            from datetime import datetime

            output_dir = "/tmp/agent_outputs"
            os.makedirs(output_dir, exist_ok=True)

            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            target_file = None

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
                    print(f"[Nuclei Critical+High] Limiting {len(targets)} targets to {max_targets}")
                    targets = targets[:max_targets]

                target_file = f"{output_dir}/targets_{job_id[:8]}_{timestamp}.txt"
                with open(target_file, 'w') as f:
                    f.write('\n'.join(targets))
                print(f"[Nuclei Critical+High] Scanning {len(targets)} targets")
                scan_target = f"{len(targets)} targets"
            else:
                print(f"[Nuclei Critical+High] Scanning {target}")
                scan_target = target

            # BUG: nuclei -u flag doesn't work reliably in Docker containers
            # Always use -l with a temp file for consistent results
            if not target_file:
                target_file = f"{output_dir}/targets_{job_id[:8]}_{timestamp}.txt"
                with open(target_file, 'w') as f:
                    f.write(target)

            # Compute target_count AFTER all target resolution/filtering
            target_count = len(targets) if targets else 1

            # Report initial progress
            if agent:
                agent.report_progress(
                    current_operation="Starting Nuclei CRITICAL+HIGH scan",
                    current_target=scan_target,
                    items_processed=0,
                    total_items=target_count
                )

            cmd = [
                "nuclei",
                "-l", target_file,
                "-severity", "critical,high",
                "-jsonl",
                "-silent",
                "-no-mhe",
                "-timeout", "15",
                "-no-color"
            ]

            # Add authentication headers if provided
            auth_used = False

            # Phase 2: Check for auth files from scripted_browser_login first
            if auth_headers_file and os.path.exists(auth_headers_file):
                print(f"[Nuclei Critical+High] Using auth headers file from previous step: {auth_headers_file}")
                with open(auth_headers_file, 'r') as f:
                    file_headers = [line.strip() for line in f if line.strip()]
                    for header in file_headers:
                        cmd.extend(["-H", header])
                        print(f"[Nuclei Critical+High] Added header from file: {header[:50]}...")
                auth_used = True

            # Phase 2: Check for Nuclei secrets file
            if secrets_file and os.path.exists(secrets_file):
                print(f"[Nuclei Critical+High] Using Nuclei secrets file: {secrets_file}")
                cmd.extend(["-secret-file", secrets_file])
                auth_used = True

            # Fallback to inline auth parameters (Phase 1 compatibility)
            if auth_username and auth_password:
                auth_str = f"{auth_username}:{auth_password}"
                auth_b64 = base64.b64encode(auth_str.encode()).decode()
                cmd.extend(["-H", f"Authorization: Basic {auth_b64}"])
                print(f"[Nuclei Critical+High] Using HTTP Basic Authentication (user: {auth_username})")
                auth_used = True

            if auth_cookies:
                cmd.extend(["-H", f"Cookie: {auth_cookies}"])
                print(f"[Nuclei Critical+High] Using session cookies (***REDACTED***)")
                auth_used = True

            if auth_headers:
                for header in auth_headers:
                    if header and header.strip():
                        cmd.extend(["-H", header])
                        print(f"[Nuclei Critical+High] Added custom header")
                auth_used = True

            if auth_used:
                print(f"[Nuclei Critical+High] Authenticated scan mode enabled")
            else:
                print(f"[Nuclei Critical+High] Public/unauthenticated scan mode")

            # Write exclusion patterns to temp file for nuclei -exclude-targets
            exclude_file = None
            if exclusion_url_patterns:
                exclude_file = f"{output_dir}/exclude_{job_id[:8]}_{timestamp}.txt"
                with open(exclude_file, 'w') as f:
                    f.write('\n'.join(exclusion_url_patterns))
                cmd.extend(["-exclude-targets", exclude_file])
                print(f"[Nuclei Critical+High] Excluding {len(exclusion_url_patterns)} URL patterns")

            # Apply rate limiting
            if rate_limit_config:
                cmd.extend(["-rl", str(rate_limit_config["rateLimit"])])
                cmd.extend(["-c", str(rate_limit_config["concurrency"])])
                print(f"[Nuclei Critical+High] Rate limit: {rate_limit_config['rateLimit']} req/s, concurrency: {rate_limit_config['concurrency']}")

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            # Stream output for progress reporting
            findings = []
            line_buffer = b''
            last_progress_update = time.time()
            progress_update_interval = 5.0  # Update progress every 5 seconds
            start_time = time.time()

            # Add timeout: critical+high scans should complete in 60 minutes max
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
                                print(f"[Nuclei Critical+High] stderr: {stderr_line}")
                    
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
                                            agent.report_progress(
                                                current_operation="Scanning for CRITICAL/HIGH vulnerabilities",
                                                current_target=scan_target,
                                                items_processed=len(findings),
                                                total_items=target_count
                                            )
                                            # Stream output
                                            agent.append_output(f"[Nuclei] Found: {finding.get('info', {}).get('name', 'Unknown')} ({finding.get('info', {}).get('severity', 'unknown').upper()})")
                                    except Exception:
                                        pass
                            
                            # Periodic progress update even if no findings yet
                            current_time = time.time()
                            elapsed = current_time - start_time
                            if agent and (current_time - last_progress_update) >= progress_update_interval:
                                agent.report_progress(
                                    current_operation="Scanning for CRITICAL/HIGH vulnerabilities",
                                    current_target=scan_target,
                                    items_processed=len(findings),
                                    total_items=target_count
                                )
                                if len(findings) == 0:
                                    agent.append_output(f"[Nuclei Critical+High] Scanning in progress... ({int(elapsed)}s elapsed)")
                                last_progress_update = current_time
                    
                    finally:
                        stderr_task.cancel()
                        try:
                            await stderr_task
                        except asyncio.CancelledError:
                            pass

                    await process.wait()

                await asyncio.wait_for(read_output(), timeout=3600)  # 60 minutes

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

                print(f"[Nuclei Critical+High] Scan timed out after 60 minutes, returning {len(findings)} partial findings")
                
                # Sanitize partial findings
                findings_sanitized = []
                for finding in findings:
                    finding_str = json.dumps(finding)
                    finding_str = finding_str.replace('\0', '')
                    findings_sanitized.append(json.loads(finding_str))
                
                return {
                    "success": False,
                    "error": f"Nuclei critical+high scan timed out after 60 minutes for {scan_target}",
                    "output": {
                        "findings": findings_sanitized,
                        "total_findings": len(findings_sanitized),
                        "target": target if target else f"{len(targets)} targets",
                        "targets": targets if targets else [target],
                        "tool": "nuclei",
                        "scan_type": "critical_and_high",
                        "partial": True
                    },
                    "raw_output": ""
                }

            if target_file and os.path.exists(target_file):
                try:
                    os.remove(target_file)
                except Exception as e:
                    print(f"[Nuclei Critical+High] Warning: Could not delete target file: {e}")

            if exclude_file and os.path.exists(exclude_file):
                try:
                    os.remove(exclude_file)
                except Exception as e:
                    print(f"[Nuclei Critical+High] Warning: Could not delete exclude file: {e}")

            print(f"[Nuclei Critical+High] Found {len(findings)} CRITICAL/HIGH findings")

            # Sanitize findings to remove null bytes
            findings_sanitized = []
            for finding in findings:
                finding_str = json.dumps(finding)
                finding_str = finding_str.replace('\0', '')
                findings_sanitized.append(json.loads(finding_str))

            # Report completion
            if agent:
                agent.report_progress(
                    current_operation="Nuclei scan completed",
                    current_target=scan_target,
                    items_processed=len(findings_sanitized),
                    total_items=len(findings_sanitized)
                )

            return {
                "success": True,
                "output": {
                    "findings": findings_sanitized,
                    "total_findings": len(findings_sanitized),
                    "target": target if target else f"{len(targets)} targets",
                    "targets": targets if targets else [target],
                    "tool": "nuclei",
                    "scan_type": "critical_and_high"
                },
                "raw_output": ""  # Already streamed
            }
        except FileNotFoundError:
            return {"success": False, "error": "Nuclei not installed"}
        except Exception as e:
            return {"success": False, "error": str(e)}


def get_tool():
    return NucleiCriticalAndHighScanTool()
