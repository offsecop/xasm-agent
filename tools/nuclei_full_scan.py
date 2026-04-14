"""
Nuclei Full Scan
Scans with all severity levels and templates.
Runs each template category sequentially to avoid OOM in memory-constrained containers.
"""

import asyncio
import json
from plugin_interface import ToolPlugin


# Template categories to scan sequentially (each run stays within 1GB memory)
TEMPLATE_CATEGORIES = [
    "http/technologies/",
    "http/exposed-panels/",
    "http/misconfiguration/",
    "http/vulnerabilities/",
    "http/cves/",
    "http/exposures/",
]


class NucleiFullScanTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "nuclei:full_scan"

    @property
    def description(self) -> str:
        return "Full comprehensive scan with all Nuclei templates (all severities)"

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
        """Execute Nuclei full scan using sequential batches per template category."""
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
                    print(f"[Nuclei Full] Limiting {len(targets)} targets to {max_targets}")
                    targets = targets[:max_targets]

                target_file = f"{output_dir}/targets_{job_id[:8]}_{timestamp}.txt"
                with open(target_file, 'w') as f:
                    f.write('\n'.join(targets))
                print(f"[Nuclei Full] Scanning {len(targets)} targets")
                scan_target = f"{len(targets)} targets"
            else:
                print(f"[Nuclei Full] Scanning {target} with all templates")

            # BUG: nuclei -u flag doesn't work reliably in Docker containers
            # Always use -l with a temp file for consistent results
            if not target_file:
                target_file = f"{output_dir}/targets_{job_id[:8]}_{timestamp}.txt"
                with open(target_file, 'w') as f:
                    f.write(target)

            # Compute total_targets AFTER all target resolution/filtering
            total_targets = len(targets) if targets else 1

            # Build common args (auth headers, exclusions, etc.)
            common_extra_args = []

            # Authentication headers
            auth_used = False
            if auth_username and auth_password:
                auth_str = f"{auth_username}:{auth_password}"
                auth_b64 = base64.b64encode(auth_str.encode()).decode()
                common_extra_args.extend(["-H", f"Authorization: Basic {auth_b64}"])
                print(f"[Nuclei Full] Using HTTP Basic Authentication (user: {auth_username})")
                auth_used = True

            if auth_cookies:
                common_extra_args.extend(["-H", f"Cookie: {auth_cookies}"])
                print(f"[Nuclei Full] Using session cookies (***REDACTED***)")
                auth_used = True

            if auth_headers:
                for header in auth_headers:
                    if header and header.strip():
                        common_extra_args.extend(["-H", header])
                        print(f"[Nuclei Full] Added custom header")
                auth_used = True

            if auth_used:
                print(f"[Nuclei Full] Authenticated scan mode enabled")
            else:
                print(f"[Nuclei Full] Public/unauthenticated scan mode")

            # Write exclusion patterns to temp file for nuclei -exclude-targets
            exclude_file = None
            if exclusion_url_patterns:
                exclude_file = f"{output_dir}/exclude_{job_id[:8]}_{timestamp}.txt"
                with open(exclude_file, 'w') as f:
                    f.write('\n'.join(exclusion_url_patterns))
                common_extra_args.extend(["-exclude-targets", exclude_file])
                print(f"[Nuclei Full] Excluding {len(exclusion_url_patterns)} URL patterns")

            # Rate limiting from config (overrides defaults)
            rl_val = "50"
            c_val = "10"
            bs_val = "10"
            if rate_limit_config:
                rl_val = str(rate_limit_config["rateLimit"])
                c_val = str(rate_limit_config["concurrency"])
                print(f"[Nuclei Full] Rate limit: {rl_val} req/s, concurrency: {c_val}")

            # ================================================================
            # SEQUENTIAL BATCH EXECUTION per template category
            # Each category runs as a separate nuclei subprocess to stay
            # within the 1GB container memory limit.
            # ================================================================
            all_findings = []
            start_time = time.time()
            category_results = {}

            for cat_idx, category in enumerate(TEMPLATE_CATEGORIES):
                cat_label = category.rstrip('/').split('/')[-1]
                print(f"[Nuclei Full] [{cat_idx+1}/{len(TEMPLATE_CATEGORIES)}] Scanning category: {cat_label}")

                if agent:
                    agent.report_progress(
                        current_operation=f"Scanning category {cat_idx+1}/{len(TEMPLATE_CATEGORIES)}: {cat_label}",
                        current_target=scan_target,
                        items_processed=len(all_findings),
                        total_items=total_targets
                    )
                    agent.append_output(
                        f"[Nuclei Full] Starting batch {cat_idx+1}/{len(TEMPLATE_CATEGORIES)}: {cat_label} "
                        f"({len(all_findings)} findings so far)"
                    )

                cmd = [
                    "nuclei",
                    "-l", target_file,
                    "-t", category,
                    "-jsonl",
                    "-silent",
                    "-no-color",
                    "-no-mhe",
                    "-timeout", "15",
                    "-c", c_val,
                    "-bs", bs_val,
                    "-rl", rl_val,
                ] + common_extra_args

                batch_findings = []

                try:
                    process = await asyncio.create_subprocess_exec(
                        *cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )

                    line_buffer = b""
                    last_progress_update = time.time()

                    async def read_batch_output():
                        nonlocal line_buffer, last_progress_update

                        async def read_stderr():
                            while True:
                                chunk = await process.stderr.read(1024)
                                if not chunk:
                                    break
                                stderr_line = chunk.decode('utf-8', errors='replace').strip()
                                if stderr_line:
                                    print(f"[Nuclei Full] [{cat_label}] stderr: {stderr_line}")

                        stderr_task = asyncio.create_task(read_stderr())

                        try:
                            while True:
                                chunk = await process.stdout.read(1024)
                                if not chunk:
                                    break

                                line_buffer += chunk
                                while b'\n' in line_buffer:
                                    line, line_buffer = line_buffer.split(b'\n', 1)
                                    line_str = line.decode('utf-8', errors='replace').strip().replace('\0', '')

                                    if line_str:
                                        try:
                                            finding = json.loads(line_str)
                                            batch_findings.append(finding)

                                            if agent:
                                                total_so_far = len(all_findings) + len(batch_findings)
                                                finding_name = finding.get('info', {}).get('name', 'Unknown')
                                                finding_severity = finding.get('info', {}).get('severity', 'unknown').upper()
                                                finding_url = finding.get('matched-at', 'N/A')
                                                agent.append_output(
                                                    f"[Nuclei Full] Found: {finding_name} ({finding_severity}) at {finding_url}"
                                                )
                                                agent.report_progress(
                                                    current_operation=f"Scanning {cat_label} ({total_so_far} findings total)",
                                                    current_target=scan_target,
                                                    items_processed=total_so_far,
                                                    total_items=total_targets
                                                )
                                        except json.JSONDecodeError:
                                            pass

                                # Periodic progress update
                                current_time = time.time()
                                if agent and (current_time - last_progress_update) >= 10.0:
                                    elapsed = current_time - start_time
                                    total_so_far = len(all_findings) + len(batch_findings)
                                    agent.report_progress(
                                        current_operation=f"Scanning {cat_label} ({total_so_far} findings total)",
                                        current_target=scan_target,
                                        items_processed=total_so_far,
                                        total_items=total_targets
                                    )
                                    if len(batch_findings) == 0:
                                        agent.append_output(
                                            f"[Nuclei Full] [{cat_label}] Scanning... ({int(elapsed)}s elapsed)"
                                        )
                                    last_progress_update = current_time
                        finally:
                            stderr_task.cancel()
                            try:
                                await stderr_task
                            except asyncio.CancelledError:
                                pass

                        await process.wait()

                    # 20 minutes timeout per category
                    await asyncio.wait_for(read_batch_output(), timeout=1200)

                except asyncio.TimeoutError:
                    print(f"[Nuclei Full] [{cat_label}] Timed out after 20 minutes, got {len(batch_findings)} partial findings")
                    try:
                        process.kill()
                        await process.wait()
                    except Exception:
                        pass
                except Exception as e:
                    print(f"[Nuclei Full] [{cat_label}] Error: {e}")

                category_results[cat_label] = len(batch_findings)
                all_findings.extend(batch_findings)
                print(f"[Nuclei Full] [{cat_label}] Completed: {len(batch_findings)} findings (total so far: {len(all_findings)})")

            # Cleanup temp files
            if target_file and os.path.exists(target_file):
                try:
                    os.remove(target_file)
                except Exception as e:
                    print(f"[Nuclei Full] Warning: Could not delete target file: {e}")

            if exclude_file and os.path.exists(exclude_file):
                try:
                    os.remove(exclude_file)
                except Exception as e:
                    print(f"[Nuclei Full] Warning: Could not delete exclude file: {e}")

            elapsed = time.time() - start_time
            print(f"[Nuclei Full] All categories completed in {int(elapsed)}s: {len(all_findings)} total findings")
            print(f"[Nuclei Full] Category breakdown: {json.dumps(category_results)}")

            if agent:
                agent.report_progress(
                    current_operation="Scan complete",
                    current_target=scan_target,
                    items_processed=len(all_findings),
                    total_items=total_targets
                )
                agent.append_output(
                    f"[Nuclei Full] Completed: {len(all_findings)} findings in {int(elapsed)}s"
                )

            # Build raw output from findings
            raw_output_sanitized = ""
            if all_findings:
                raw_lines = [json.dumps(f) for f in all_findings]
                raw_output_sanitized = '\n'.join(raw_lines)
                # Limit to 10MB to prevent 413 errors
                if len(raw_output_sanitized) > 10 * 1024 * 1024:
                    raw_output_sanitized = '\n'.join(raw_lines[:1000]) + f"\n... (truncated, total {len(raw_lines)} lines)"

            # Sanitize findings to remove null bytes
            findings_sanitized = []
            for finding in all_findings:
                finding_str = json.dumps(finding)
                finding_str = finding_str.replace('\0', '')
                findings_sanitized.append(json.loads(finding_str))

            return {
                "success": True,
                "output": {
                    "findings": findings_sanitized,
                    "total_findings": len(findings_sanitized),
                    "target": target if target else f"{len(targets)} targets",
                    "targets": targets if targets else [target],
                    "tool": "nuclei",
                    "scan_type": "full",
                    "category_results": category_results,
                    "elapsed_seconds": int(elapsed)
                },
                "raw_output": raw_output_sanitized
            }
        except FileNotFoundError:
            return {"success": False, "error": "Nuclei not installed"}
        except Exception as e:
            return {"success": False, "error": str(e)}


def get_tool():
    return NucleiFullScanTool()
