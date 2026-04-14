"""
Nuclei Informational Severity Scan
Scans only for INFORMATIONAL severity vulnerabilities using -s info flag
"""

import asyncio
import json
import time
from urllib.parse import urlparse
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
import os
from plugin_interface import ToolPlugin


class NucleiInfoScanTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "nuclei:info_scan"

    @property
    def description(self) -> str:
        return "Scans for INFORMATIONAL severity vulnerabilities only using Nuclei (-s info)"

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
        """Execute Nuclei informational severity scan using -s info flag"""
        target = parameters.get("target")
        targets = parameters.get("targets")
        job_id = parameters.get("_job_id", "unknown")  # Job ID passed by agent
        agent = parameters.get("_agent")  # Get agent reference for progress reporting

        # Extract authentication parameters
        auth_username = parameters.get("authUsername")
        auth_password = parameters.get("authPassword")
        auth_cookies = parameters.get("authCookies")
        auth_headers = parameters.get("authHeaders", [])

        # Log target info (without exposing secrets)
        print(f"[Nuclei Info] target: {target}, targets count: {len(targets) if isinstance(targets, list) else ('1' if targets else '0')}")

        # Extract exclusion patterns and rate limiting
        from tools._scope_utils import extract_exclusion_patterns, extract_rate_limit
        exclusion_url_patterns = extract_exclusion_patterns(parameters)
        rate_limit_config = extract_rate_limit(parameters)

        if not target and not targets:
            return {"success": False, "error": "Either 'target' or 'targets' required"}

        try:
            import base64
            from datetime import datetime

            # INVESTIGATION: Execution metrics
            execution_start = time.time()
            execution_metrics = {
                'start_time': execution_start,
                'process_pid': None,
                'target_file_path': None,
                'target_file_line_count': 0,
                'target_file_size': 0,
                'command_executed': None,
                'stdout_size': 0,
                'stderr_size': 0,
                'execution_duration': 0,
                'findings_count': 0,
                'memory_before': psutil.Process().memory_info().rss / 1024 / 1024 if PSUTIL_AVAILABLE else None,  # MB
                'cpu_before': psutil.cpu_percent(interval=0.1) if PSUTIL_AVAILABLE else None,
            }

            # Create output directory if it doesn't exist
            output_dir = "/tmp/agent_outputs"
            os.makedirs(output_dir, exist_ok=True)

            # Generate output filename with job ID and timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"{output_dir}/nuclei_{job_id[:8]}_{timestamp}.jsonl"
            
            print(f"[Nuclei Info] ========== EXECUTION START ==========")
            print(f"[Nuclei Info] Start time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(execution_start))}")
            if PSUTIL_AVAILABLE:
                print(f"[Nuclei Info] Memory before: {execution_metrics['memory_before']:.2f} MB")
                print(f"[Nuclei Info] CPU before: {execution_metrics['cpu_before']:.2f}%")
            else:
                print(f"[Nuclei Info] Memory/CPU metrics unavailable (psutil not installed)")

            # Handle multiple targets
            target_file = None
            scan_target = target
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
                    print(f"[Nuclei Info] Limiting {len(targets)} targets to {max_targets}")
                    targets = targets[:max_targets]

                target_file = f"{output_dir}/targets_{job_id[:8]}_{timestamp}.txt"

                # INVESTIGATION ENHANCEMENT - Detailed target file logging
                print(f"[Nuclei Info] ========== TARGET FILE CREATION ==========")
                print(f"[Nuclei Info] Writing {len(targets)} targets to file: {target_file}")
                print(f"[Nuclei Info] First 5 targets to write:")
                for i, t in enumerate(targets[:5]):
                    print(f"[Nuclei Info]   [{i+1}] {t}")
                
                with open(target_file, 'w') as f:
                    f.write('\n'.join(targets))
                    f.flush()
                
                # Read back to verify - CRITICAL VALIDATION
                with open(target_file, 'r') as f:
                    content = f.read()
                    line_count = len(content.strip().split('\n')) if content.strip() else 0
                    file_size = os.path.getsize(target_file)
                    execution_metrics['target_file_path'] = target_file
                    execution_metrics['target_file_line_count'] = line_count
                    execution_metrics['target_file_size'] = file_size
                    
                    print(f"[Nuclei Info] Verification: target file has {line_count} lines")
                    print(f"[Nuclei Info] Target file size: {file_size} bytes")
                    print(f"[Nuclei Info] Expected: {len(targets)} lines")
                    
                    # CRITICAL: Validate file integrity before execution
                    if line_count != len(targets):
                        error_msg = f"Target file line count mismatch! Expected {len(targets)}, got {line_count}"
                        print(f"[Nuclei Info] ❌ ERROR: {error_msg}")
                        # Try to read file content for debugging
                        file_lines = content.strip().split('\n')
                        print(f"[Nuclei Info] File content (first 10 lines):")
                        for i, line in enumerate(file_lines[:10]):
                            print(f"[Nuclei Info]   [{i+1}] {line}")
                        print(f"[Nuclei Info] File content (last 5 lines):")
                        for i, line in enumerate(file_lines[-5:]):
                            print(f"[Nuclei Info]   [{len(file_lines)-4+i}] {line}")
                        
                        # Still proceed but log the issue
                        execution_metrics['target_file_validation_error'] = error_msg
                    else:
                        print(f"[Nuclei Info] ✓ Target file validation passed")
                    
                    print(f"[Nuclei Info] First 5 lines from file:")
                    for i, line in enumerate(content.strip().split('\n')[:5]):
                        print(f"[Nuclei Info]   [{i+1}] {line}")
                    
                    # Additional validation: check for empty lines or invalid URLs
                    file_lines = content.strip().split('\n')
                    empty_lines = sum(1 for line in file_lines if not line.strip())
                    if empty_lines > 0:
                        print(f"[Nuclei Info] ⚠️ WARNING: Found {empty_lines} empty lines in target file")
                        execution_metrics['target_file_empty_lines'] = empty_lines
                
                scan_target = f"{len(targets)} targets"
                print(f"[Nuclei Info] Scanning {len(targets)} targets with -s info")
                print(f"[Nuclei Info] Targets file: {target_file}")
            else:
                print(f"[Nuclei Info] Scanning {target} with -s info")

            print(f"[Nuclei Info] Output file: {output_file}")

            # Build command - remove -o flag to stream from stdout, we'll write to file ourselves
            # NOTE: -silent is REQUIRED to keep stdout clean for JSONL parsing
            # BUG: nuclei -u flag doesn't work reliably in Docker containers
            # Always use -l with a temp file for consistent results
            if not target_file:
                target_file = f"{output_dir}/targets_{job_id[:8]}_{timestamp}.txt"
                with open(target_file, 'w') as f:
                    f.write(target)

            # Compute total_targets AFTER all target resolution/filtering
            total_targets = len(targets) if targets else 1

            # Report initial progress
            if agent:
                agent.report_progress(
                    current_operation="Starting Nuclei INFO scan",
                    current_target=scan_target,
                    items_processed=0,
                    total_items=total_targets
                )

            cmd = [
                "nuclei",
                "-l", target_file,
                "-severity", "info",
                "-jsonl",
                "-silent",  # Required for clean JSONL output
                "-no-mhe",
                "-timeout", "15",
                "-no-color"  # Always use -no-color to avoid ANSI escape issues
                # Note: Removed -o flag to enable stdout streaming
            ]

            # Add authentication headers if provided
            auth_used = False
            if auth_username and auth_password:
                auth_str = f"{auth_username}:{auth_password}"
                auth_b64 = base64.b64encode(auth_str.encode()).decode()
                cmd.extend(["-H", f"Authorization: Basic {auth_b64}"])
                print(f"[Nuclei Info] Using HTTP Basic Authentication (user: {auth_username})")
                auth_used = True

            if auth_cookies:
                cmd.extend(["-H", f"Cookie: {auth_cookies}"])
                print(f"[Nuclei Info] Using session cookies (***REDACTED***)")
                auth_used = True

            if auth_headers:
                for header in auth_headers:
                    if header and header.strip():
                        cmd.extend(["-H", header])
                        print(f"[Nuclei Info] Added custom header")
                auth_used = True

            if auth_used:
                print(f"[Nuclei Info] Authenticated scan mode enabled")
            else:
                print(f"[Nuclei Info] Public/unauthenticated scan mode")

            # Write exclusion patterns to temp file for nuclei -exclude-targets
            exclude_file = None
            if exclusion_url_patterns:
                exclude_file = f"{output_dir}/exclude_{job_id[:8]}_{timestamp}.txt"
                with open(exclude_file, 'w') as f:
                    f.write('\n'.join(exclusion_url_patterns))
                cmd.extend(["-exclude-targets", exclude_file])
                print(f"[Nuclei Info] Excluding {len(exclusion_url_patterns)} URL patterns")

            # Apply rate limiting
            if rate_limit_config:
                cmd.extend(["-rl", str(rate_limit_config["rateLimit"])])
                cmd.extend(["-c", str(rate_limit_config["concurrency"])])
                print(f"[Nuclei Info] Rate limit: {rate_limit_config['rateLimit']} req/s, concurrency: {rate_limit_config['concurrency']}")

            execution_metrics['command_executed'] = ' '.join(cmd)
            print(f"[Nuclei Info] Command: {execution_metrics['command_executed']}")

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            execution_metrics['process_pid'] = process.pid
            print(f"[Nuclei Info] Process created: PID {process.pid}")

            # Stream output for progress reporting (like nuclei_high_scan)
            findings = []
            processed_targets = set()
            line_buffer = b''
            stderr_buffer = []
            last_progress_update = 0
            progress_update_interval = 30  # Update progress every 30 seconds

            def _get_target_key(url: str) -> str:
                try:
                    parsed = urlparse(url)
                    if parsed.netloc:
                        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                    return url
                except Exception:
                    return url

            # Add timeout: info scans should complete in 60 minutes max
            try:
                async def read_output():
                    nonlocal line_buffer, last_progress_update, stderr_buffer
                    import time
                    start_time = time.time()
                    
                    # Open output file for writing findings as we discover them
                    output_fd = open(output_file, 'w', encoding='utf-8')
                    
                    async def read_stderr():
                        """Read stderr in parallel to capture errors"""
                        while True:
                            chunk = await process.stderr.read(1024)
                            if not chunk:
                                break
                            stderr_line = chunk.decode('utf-8', errors='replace').strip()
                            if stderr_line:
                                stderr_buffer.append(stderr_line)
                                print(f"[Nuclei Info] stderr: {stderr_line}")
                    
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
                                        
                                        matched_url = (
                                            finding.get('matched-at')
                                            or finding.get('matched')
                                            or finding.get('host')
                                        )
                                        if matched_url:
                                            processed_targets.add(_get_target_key(matched_url))
                                        
                                        # Write to output file immediately
                                        output_fd.write(line_str + '\n')
                                        output_fd.flush()

                                        # Report progress with finding count
                                        if agent:
                                            items_processed = len(processed_targets) if processed_targets else len(findings)
                                            items_processed = min(items_processed, total_targets)
                                            agent.report_progress(
                                                current_operation="Scanning for INFORMATIONAL vulnerabilities",
                                                current_target=scan_target,
                                                items_processed=items_processed,
                                                total_items=total_targets
                                            )
                                            # Stream output
                                            finding_name = finding.get('info', {}).get('name', 'Unknown')
                                            finding_url = finding.get('matched-at', 'N/A')
                                            agent.append_output(f"[Nuclei Info] Found: {finding_name} at {finding_url}")
                                    except json.JSONDecodeError:
                                        # Not a JSON finding, might be progress output
                                        pass
                            
                            # Periodic progress update even if no findings yet
                            current_time = time.time()
                            elapsed = current_time - start_time
                            if agent and (current_time - last_progress_update) >= progress_update_interval:
                                if len(findings) > 0:
                                    items_processed = len(processed_targets) if processed_targets else len(findings)
                                    items_processed = min(items_processed, total_targets)
                                    agent.report_progress(
                                        current_operation=f"Scanning... Found {len(findings)} findings so far",
                                        current_target=scan_target,
                                        items_processed=items_processed,
                                        total_items=total_targets
                                    )
                                else:
                                    agent.report_progress(
                                        current_operation=f"Scanning... ({int(elapsed)}s elapsed)",
                                        current_target=scan_target,
                                        items_processed=0,
                                        total_items=total_targets
                                    )
                                last_progress_update = current_time
                        
                        # Wait for stderr to finish
                        await stderr_task
                        return_code = await process.wait()
                        execution_metrics['return_code'] = return_code
                        
                        # Check for errors in stderr
                        if stderr_buffer:
                            error_text = '\n'.join(stderr_buffer)
                            # Check for common error patterns
                            if 'error' in error_text.lower() or 'failed' in error_text.lower():
                                print(f"[Nuclei Info] ⚠️ WARNING: Errors detected in stderr:")
                                for line in stderr_buffer[:5]:  # First 5 error lines
                                    print(f"[Nuclei Info]   {line}")
                                execution_metrics['stderr_errors'] = stderr_buffer
                    finally:
                        output_fd.close()

                await asyncio.wait_for(read_output(), timeout=3600)  # 60 minutes
                
                # Calculate execution metrics after completion
                execution_end = time.time()
                execution_metrics['execution_duration'] = execution_end - execution_start
                execution_metrics['findings_count'] = len(findings)
                execution_metrics['unique_targets_processed'] = len(processed_targets)
                execution_metrics['stderr_size'] = len('\n'.join(stderr_buffer)) if stderr_buffer else 0

            except asyncio.TimeoutError:
                # Kill the process if it times out
                execution_end = time.time()
                execution_metrics['execution_duration'] = execution_end - execution_start
                print(f"[Nuclei Info] ========== TIMEOUT ==========")
                print(f"[Nuclei Info] Execution duration: {execution_metrics['execution_duration']:.2f}s")
                print(f"[Nuclei Info] Timeout after 3600s (60 minutes)")
                print(f"[Nuclei Info] ⚠️ WARNING: Execution timed out - partial findings: {len(findings)}")
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

                # Sanitize findings (even if empty)
                findings_sanitized = []
                for finding in findings:
                    finding_str = json.dumps(finding)
                    finding_str = finding_str.replace('\0', '')
                    findings_sanitized.append(json.loads(finding_str))
                
                print(f"[Nuclei Info] Returning {len(findings_sanitized)} partial findings from incomplete execution")
                
                return {
                    "success": False,
                    "error": f"Nuclei info scan timed out after 60 minutes for {scan_target} (partial results included)",
                    "output": {
                        "findings": findings_sanitized,
                        "total_findings": len(findings_sanitized),
                        "target": target if target else f"{len(targets)} targets",
                        "targets": targets if targets else [target],
                        "tool": "nuclei",
                        "scan_type": "info",
                        "partial": True
                    },
                    "raw_output": "",
                    "execution_metrics": execution_metrics
                }

            print(f"[Nuclei Info] ========== EXECUTION COMPLETE ==========")
            print(f"[Nuclei Info] Execution duration: {execution_metrics['execution_duration']:.2f}s")
            print(f"[Nuclei Info] Findings count: {len(findings)}")
            print(f"[Nuclei Info] Stderr size: {execution_metrics['stderr_size']} bytes")
            print(f"[Nuclei Info] Found {len(findings)} INFORMATIONAL findings")

            # Report final results
            if agent:
                items_processed = len(processed_targets) if processed_targets else len(findings)
                items_processed = min(items_processed, total_targets if total_targets else items_processed or 1)
                final_total = total_targets if total_targets else max(items_processed, 1)
                agent.report_progress(
                    current_operation=f"Completed: Found {len(findings)} findings",
                    current_target=scan_target,
                    items_processed=items_processed,
                    total_items=final_total
                )

            # Cleanup target file after scan
            if target_file and os.path.exists(target_file):
                try:
                    os.remove(target_file)
                    print(f"[Nuclei Info] Cleaned up target file: {target_file}")
                except Exception as e:
                    print(f"[Nuclei Info] Warning: Could not delete target file: {e}")

            if exclude_file and os.path.exists(exclude_file):
                try:
                    os.remove(exclude_file)
                except Exception as e:
                    print(f"[Nuclei Info] Warning: Could not delete exclude file: {e}")

            # Return flat structure that ingestion expects
            # Sanitize null bytes from raw output before returning
            # Note: stdout/stderr are now captured during streaming, so we use stderr_buffer
            raw_output_sanitized = ""  # Output was streamed and written to file
            
            error_sanitized = ""
            if stderr_buffer:
                error_sanitized = '\n'.join(stderr_buffer).replace('\0', '')

            # Limit raw_output size to prevent 413 errors (max 10MB)
            # Also sanitize null bytes which PostgreSQL cannot store
            raw_output_limited = raw_output_sanitized
            if len(raw_output_limited) > 10 * 1024 * 1024:  # 10MB
                lines = raw_output_limited.split('\n')
                raw_output_limited = '\n'.join(lines[:1000]) + f"\n... (truncated, total {len(lines)} lines, {len(raw_output_limited)} bytes)"
            elif len(raw_output_limited.split('\n')) > 1000:
                lines = raw_output_limited.split('\n')
                raw_output_limited = '\n'.join(lines[:1000]) + f"\n... (truncated, total {len(lines)} lines)"

            # Sanitize findings to remove null bytes
            findings_sanitized = []
            for finding in findings:
                finding_str = json.dumps(finding)
                finding_str = finding_str.replace('\0', '')
                findings_sanitized.append(json.loads(finding_str))

            # Store stderr buffer in metrics for investigation
            execution_metrics['stderr_buffer'] = stderr_buffer
            execution_metrics['findings_count'] = len(findings_sanitized)
            
            return {
                "success": True,
                "output": {
                    "findings": findings_sanitized,
                    "total_findings": len(findings_sanitized),
                    "findings_delivered": len(findings_sanitized),
                    "target": target if target else f"{len(targets)} targets",
                    "targets": targets if targets else [target],
                    "tool": "nuclei",
                    "scan_type": "info",
                    "output_file": output_file,
                },
                "raw_output": raw_output_limited,
                "execution_metrics": execution_metrics
            }
        except FileNotFoundError:
            return {
                "success": False,
                "error": "Nuclei not installed. Please install: https://github.com/projectdiscovery/nuclei",
                "output": {
                    "findings": [],
                    "total_findings": 0,
                    "findings_delivered": 0,
                    "target": parameters.get("target", ""),
                    "targets": [],
                    "tool": "nuclei",
                    "scan_type": "info"
                },
                "raw_output": ""
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Error running Nuclei info scan: {str(e)}",
                "output": {
                    "findings": [],
                    "total_findings": 0,
                    "findings_delivered": 0,
                    "target": parameters.get("target", ""),
                    "targets": [],
                    "tool": "nuclei",
                    "scan_type": "info"
                },
                "raw_output": ""
            }


def get_tool():
    return NucleiInfoScanTool()

