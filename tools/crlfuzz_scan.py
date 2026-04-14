"""
CRLFuzz CRLF Injection Scanner Tool
Tests for CRLF injection vulnerabilities in HTTP headers.
CRLF injection (CWE-93) allows attackers to inject carriage return and line feed
characters into HTTP headers, potentially leading to HTTP response splitting,
cache poisoning, or cross-site scripting.
"""

import asyncio
import json
import os
import time
from datetime import datetime
from plugin_interface import ToolPlugin
from typing import Dict, Any


class CrlfuzzScanTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "crlfuzz:scan"

    @property
    def description(self) -> str:
        return "CRLF injection vulnerability scanner - tests HTTP headers for carriage return/line feed injection (CWE-93)"

    @property
    def schema(self) -> Dict[str, Any]:
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
                "concurrency": {
                    "type": "integer",
                    "description": "Number of concurrent requests (default: 25)"
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

    async def execute(self, parameters: Dict[str, Any]) -> Any:
        """Execute CRLFuzz CRLF injection scan"""
        target = parameters.get("target")
        targets = parameters.get("targets")
        job_id = parameters.get("_job_id", "unknown")
        agent = parameters.get("_agent")

        concurrency = parameters.get("concurrency", 25)

        if not target and not targets:
            return {"success": False, "error": "Either 'target' or 'targets' required"}

        try:
            output_dir = "/tmp/agent_outputs"
            os.makedirs(output_dir, exist_ok=True)

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

            target_file = None
            scan_target = target if target else f"{len(targets) if targets else 0} targets"
            total_targets = 1

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
                    print(f"[CRLFuzz] Limiting {len(targets)} targets to {max_targets}")
                    targets = targets[:max_targets]

                total_targets = len(targets)
                target_file = f"{output_dir}/crlfuzz_targets_{job_id[:8]}_{timestamp}.txt"
                with open(target_file, "w") as f:
                    f.write("\n".join(targets))
                print(f"[CRLFuzz] Scanning {total_targets} targets for CRLF injection")
                scan_target = f"{total_targets} targets"
            else:
                print(f"[CRLFuzz] Scanning {target} for CRLF injection")

            # Build crlfuzz command
            if targets:
                cmd = [
                    "crlfuzz",
                    "-l", target_file,
                    "-c", str(concurrency),
                    "-s"  # Silent mode
                ]
            else:
                cmd = [
                    "crlfuzz",
                    "-u", target,
                    "-c", str(concurrency),
                    "-s"  # Silent mode
                ]

            print(f"[CRLFuzz] Concurrency: {concurrency}")

            # Report initial progress
            if agent:
                agent.report_progress(
                    current_operation="Starting CRLFuzz CRLF injection scan",
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

            # 20 minute timeout for CRLF scanning
            try:
                async def read_output():
                    nonlocal line_buffer, last_progress_update

                    async def read_stderr():
                        """Read stderr in parallel to capture errors"""
                        while True:
                            chunk = await process.stderr.read(1024)
                            if not chunk:
                                break
                            stderr_line = chunk.decode("utf-8", errors="replace").strip()
                            if stderr_line:
                                print(f"[CRLFuzz] stderr: {stderr_line}")

                    # Start reading stderr in background
                    stderr_task = asyncio.create_task(read_stderr())

                    try:
                        while True:
                            chunk = await process.stdout.read(1024)
                            if not chunk:
                                break

                            line_buffer += chunk
                            while b"\n" in line_buffer:
                                line, line_buffer = line_buffer.split(b"\n", 1)
                                # Decode with error handling and sanitize null bytes
                                line_str = line.decode("utf-8", errors="replace").strip().replace("\0", "")

                                if line_str:
                                    # crlfuzz outputs vulnerable URLs one per line
                                    finding = {
                                        "url": line_str,
                                        "vulnerable": True,
                                        "severity": "HIGH",
                                        "cwe": "CWE-93",
                                        "vulnerability": "CRLF Injection",
                                        "description": f"CRLF injection vulnerability detected at {line_str}. "
                                                       f"The server does not properly sanitize carriage return (CR) "
                                                       f"and line feed (LF) characters in HTTP headers, potentially "
                                                       f"allowing HTTP response splitting attacks."
                                    }
                                    findings.append(finding)

                                    # Report progress with finding details
                                    if agent:
                                        agent.report_progress(
                                            current_operation="CRLF injection testing",
                                            current_target=scan_target,
                                            items_processed=len(findings),
                                            total_items=total_targets
                                        )
                                        agent.append_output(
                                            f"[CRLFuzz] VULNERABLE: {line_str} (CWE-93: CRLF Injection)"
                                        )

                            # Periodic progress update even if no findings yet
                            current_time = time.time()
                            elapsed = current_time - start_time
                            if agent and (current_time - last_progress_update) >= progress_update_interval:
                                agent.report_progress(
                                    current_operation="CRLF injection testing",
                                    current_target=scan_target,
                                    items_processed=len(findings),
                                    total_items=total_targets
                                )
                                if len(findings) == 0:
                                    agent.append_output(
                                        f"[CRLFuzz] Scanning in progress... ({int(elapsed)}s elapsed)"
                                    )
                                last_progress_update = current_time

                    finally:
                        stderr_task.cancel()
                        try:
                            await stderr_task
                        except asyncio.CancelledError:
                            pass

                    await process.wait()

                await asyncio.wait_for(read_output(), timeout=1200)  # 20 minutes

            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                # Cleanup target file
                if target_file and os.path.exists(target_file):
                    try:
                        os.remove(target_file)
                    except Exception:
                        pass

                print(f"[CRLFuzz] Scan timed out after 20 minutes, returning {len(findings)} partial findings")

                raw_output_sanitized = self._build_raw_output(findings)

                total_found = len(findings)
                if len(findings) > 2000:
                    findings = findings[:2000]

                return {
                    "success": False,
                    "error": f"CRLFuzz scan timed out after 20 minutes for {scan_target}",
                    "output": {
                        "findings": findings,
                        "total_findings": total_found,
                        "findings_delivered": len(findings),
                        "target": target if target else f"{total_targets} targets",
                        "targets": targets if targets else [target],
                        "tool": "crlfuzz",
                        "scan_type": "crlf_injection",
                        "partial": True
                    },
                    "raw_output": raw_output_sanitized
                }

            # Cleanup target file
            if target_file and os.path.exists(target_file):
                try:
                    os.remove(target_file)
                except Exception as e:
                    print(f"[CRLFuzz] Warning: Could not delete target file: {e}")

            # Check if process failed (e.g., binary error, dependency issue)
            if process.returncode != 0 and len(findings) == 0:
                error_msg = f"CRLFuzz exited with code {process.returncode}"
                return {
                    "success": False,
                    "error": error_msg,
                    "output": {
                        "findings": [],
                        "total_findings": 0,
                        "findings_delivered": 0,
                        "target": target if target else f"{total_targets} targets",
                        "targets": targets if targets else [target],
                        "tool": "crlfuzz",
                        "scan_type": "crlf_injection"
                    },
                    "raw_output": ""
                }

            print(f"[CRLFuzz] Found {len(findings)} CRLF injection vulnerabilities")

            # Build raw output
            raw_output_sanitized = self._build_raw_output(findings)

            # Cap findings at 2000
            total_found = len(findings)
            if len(findings) > 2000:
                findings = findings[:2000]
                print(f"[CRLFuzz] Capped findings from {total_found} to 2000 for delivery")

            # Final progress report
            if agent:
                agent.report_progress(
                    current_operation="CRLFuzz scan completed",
                    current_target=scan_target,
                    items_processed=total_found,
                    total_items=total_found
                )

            return {
                "success": True,
                "output": {
                    "findings": findings,
                    "total_findings": total_found,
                    "findings_delivered": len(findings),
                    "target": target if target else f"{total_targets} targets",
                    "targets": targets if targets else [target],
                    "tool": "crlfuzz",
                    "scan_type": "crlf_injection"
                },
                "raw_output": raw_output_sanitized
            }
        except FileNotFoundError:
            return {
                "success": False,
                "error": "crlfuzz not installed. Install with: go install github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest",
                "output": {
                    "findings": [],
                    "total_findings": 0,
                    "findings_delivered": 0,
                    "target": parameters.get("target", ""),
                    "targets": [],
                    "tool": "crlfuzz",
                    "scan_type": "crlf_injection"
                },
                "raw_output": ""
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Error running CRLFuzz: {str(e)}",
                "output": {
                    "findings": [],
                    "total_findings": 0,
                    "findings_delivered": 0,
                    "target": parameters.get("target", ""),
                    "targets": [],
                    "tool": "crlfuzz",
                    "scan_type": "crlf_injection"
                },
                "raw_output": ""
            }

    def _build_raw_output(self, findings: list) -> str:
        """Build raw output string from findings, limited to 5MB"""
        if not findings:
            return ""
        raw_lines = [json.dumps(f) for f in findings]
        raw_output = "\n".join(raw_lines)
        # Limit to 5MB to prevent 413 errors
        if len(raw_output) > 5 * 1024 * 1024:
            raw_output = "\n".join(raw_lines[:1000]) + f"\n... (truncated, total {len(raw_lines)} lines)"
        return raw_output


def get_tool():
    return CrlfuzzScanTool()
