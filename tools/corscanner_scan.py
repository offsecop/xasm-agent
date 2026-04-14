"""
CORScanner CORS Misconfiguration Scanner Tool
Detects CORS misconfigurations and vulnerabilities in web applications.
Checks for dangerous Access-Control-Allow-Origin patterns that could
allow unauthorized cross-origin access to sensitive data.
"""

import asyncio
import json
import os
import re
import time
from datetime import datetime
from plugin_interface import ToolPlugin
from typing import Dict, Any


class CorscannerScanTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "corscanner:scan"

    @property
    def description(self) -> str:
        return "CORS misconfiguration scanner - detects dangerous Access-Control-Allow-Origin patterns including wildcard with credentials, origin reflection, null origin, and prefix match vulnerabilities"

    @property
    def schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Single target URL to scan for CORS misconfigurations (e.g., http://example.com)"
                },
                "targets": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Multiple target URLs to scan (alternative to target)"
                },
                "verbose": {
                    "type": "boolean",
                    "description": "Enable verbose output for detailed CORS analysis",
                    "default": False
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

    # Severity mapping for CORS misconfiguration types
    SEVERITY_MAP = {
        "reflect_origin": "HIGH",
        "prefix_match": "MEDIUM",
        "suffix_match": "MEDIUM",
        "not_escape_dot": "MEDIUM",
        "null_origin": "HIGH",
        "third_party": "MEDIUM",
        "wildcard": "CRITICAL",
        "include_match": "MEDIUM",
    }

    async def execute(self, parameters: Dict[str, Any]) -> Any:
        """Execute CORScanner CORS misconfiguration scan"""
        target = parameters.get("target")
        targets = parameters.get("targets")
        verbose = parameters.get("verbose", False)
        job_id = parameters.get("_job_id", "unknown")
        agent = parameters.get("_agent")

        if not target and not targets:
            return {"success": False, "error": "Either 'target' or 'targets' required"}

        try:
            output_dir = "/tmp/agent_outputs"
            os.makedirs(output_dir, exist_ok=True)

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

            target_file = None
            scan_target = target if target else f"{len(targets)} targets"
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
                    print(f"[CORScanner] Limiting {len(targets)} targets to {max_targets}")
                    targets = targets[:max_targets]

                total_targets = len(targets)
                target_file = f"{output_dir}/corscanner_targets_{job_id[:8]}_{timestamp}.txt"
                with open(target_file, 'w') as f:
                    f.write('\n'.join(targets))
                print(f"[CORScanner] Scanning {len(targets)} target URLs for CORS misconfigurations")
            else:
                print(f"[CORScanner] Scanning {target}")

            # Build CORScanner command
            corscanner_path = os.environ.get('CORSCANNER_PATH', '/opt/CORScanner/cors_scan.py')
            cmd = ["python3", corscanner_path]

            if targets:
                cmd.extend(["-i", target_file])
            else:
                cmd.extend(["-u", target])

            if verbose:
                cmd.append("-v")

            print(f"[CORScanner] Command: {' '.join(cmd)}")

            # Report initial progress
            if agent:
                agent.report_progress(
                    current_operation="Starting CORScanner CORS scan",
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
            raw_lines = []
            line_buffer = b""
            last_progress_update = time.time()
            progress_update_interval = 5.0
            start_time = time.time()

            # 15 minute timeout for CORS scanning
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
                                print(f"[CORScanner] stderr: {stderr_line}")

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
                                    raw_lines.append(line_str)
                                    finding = self._parse_corscanner_line(line_str)
                                    if finding:
                                        findings.append(finding)

                                        # Report progress with finding details
                                        if agent:
                                            agent.report_progress(
                                                current_operation="CORS misconfiguration scanning",
                                                current_target=scan_target,
                                                items_processed=len(findings),
                                                total_items=total_targets
                                            )
                                            agent.append_output(
                                                f"[CORScanner] Found CORS issue: type={finding.get('type', 'unknown')}, "
                                                f"severity={finding.get('severity', 'unknown')}, "
                                                f"url={finding.get('url', 'N/A')}"
                                            )

                                # Periodic progress update even if no findings yet
                                current_time = time.time()
                                elapsed = current_time - start_time
                                if agent and (current_time - last_progress_update) >= progress_update_interval:
                                    agent.report_progress(
                                        current_operation="CORS misconfiguration scanning",
                                        current_target=scan_target,
                                        items_processed=len(findings),
                                        total_items=total_targets
                                    )
                                    if len(findings) == 0:
                                        agent.append_output(f"[CORScanner] Scanning in progress... ({int(elapsed)}s elapsed)")
                                    last_progress_update = current_time

                    finally:
                        stderr_task.cancel()
                        try:
                            await stderr_task
                        except asyncio.CancelledError:
                            pass

                    await process.wait()

                await asyncio.wait_for(read_output(), timeout=900)  # 15 minutes

            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                # Cleanup target file
                if target_file and os.path.exists(target_file):
                    try:
                        os.remove(target_file)
                    except Exception:
                        pass

                print(f"[CORScanner] Scan timed out after 15 minutes, returning {len(findings)} partial findings")

                raw_output_sanitized = self._build_raw_output(raw_lines)

                total_found = len(findings)
                if len(findings) > 2000:
                    findings = findings[:2000]

                return {
                    "success": False,
                    "error": f"CORScanner scan timed out after 15 minutes for {scan_target}",
                    "output": {
                        "findings": findings,
                        "total_findings": total_found,
                        "findings_delivered": len(findings),
                        "target": target if target else f"{len(targets)} targets",
                        "targets": targets if targets else [target],
                        "tool": "corscanner",
                        "scan_type": "cors",
                        "partial": True
                    },
                    "raw_output": raw_output_sanitized
                }

            # Cleanup target file
            if target_file and os.path.exists(target_file):
                try:
                    os.remove(target_file)
                except Exception as e:
                    print(f"[CORScanner] Warning: Could not delete target file: {e}")

            # Check if process failed (e.g., script not found, dependency error)
            if process.returncode != 0 and len(findings) == 0:
                error_msg = "\n".join(raw_lines[-10:]) if raw_lines else f"CORScanner exited with code {process.returncode}"
                return {
                    "success": False,
                    "error": error_msg,
                    "output": {
                        "findings": [],
                        "total_findings": 0,
                        "findings_delivered": 0,
                        "target": target if target else f"{len(targets)} targets",
                        "targets": targets if targets else [target],
                        "tool": "corscanner",
                        "scan_type": "cors"
                    },
                    "raw_output": "\n".join(raw_lines)
                }

            print(f"[CORScanner] Found {len(findings)} total CORS misconfiguration findings")

            # Build raw output
            raw_output_sanitized = self._build_raw_output(raw_lines)

            # Cap findings at 2000 to keep payload under 10MB
            total_found = len(findings)
            if len(findings) > 2000:
                findings = findings[:2000]
                print(f"[CORScanner] Capped findings from {total_found} to 2000 for delivery")

            # Final progress report
            if agent:
                agent.report_progress(
                    current_operation="CORScanner CORS scan completed",
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
                    "target": target if target else f"{len(targets)} targets",
                    "targets": targets if targets else [target],
                    "tool": "corscanner",
                    "scan_type": "cors"
                },
                "raw_output": raw_output_sanitized
            }
        except FileNotFoundError:
            return {
                "success": False,
                "error": "CORScanner not installed. Install with: git clone https://github.com/chenjj/CORScanner.git /opt/CORScanner && pip install -r /opt/CORScanner/requirements.txt",
                "output": {
                    "findings": [],
                    "total_findings": 0,
                    "findings_delivered": 0,
                    "target": parameters.get("target", ""),
                    "targets": [],
                    "tool": "corscanner",
                    "scan_type": "cors"
                },
                "raw_output": ""
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Error running CORScanner: {str(e)}",
                "output": {
                    "findings": [],
                    "total_findings": 0,
                    "findings_delivered": 0,
                    "target": parameters.get("target", ""),
                    "targets": [],
                    "tool": "corscanner",
                    "scan_type": "cors"
                },
                "raw_output": ""
            }

    def _parse_corscanner_line(self, line: str) -> dict:
        """Parse a CORScanner output line into a structured finding.

        CORScanner outputs lines like:
            [+] URL: http://example.com has misconfiguration type: reflect_origin
            [Vulnerable] http://example.com | type: null_origin | credentials: true
        """
        if not line:
            return None

        finding = None

        # Pattern 1: "[+] URL: <url> has misconfiguration type: <type>"
        match = re.search(
            r'\[\+\]\s+URL:\s+(\S+)\s+has\s+misconfiguration\s+type:\s+(\S+)',
            line, re.IGNORECASE
        )
        if match:
            url = match.group(1)
            vuln_type = match.group(2).strip().lower()
            severity = self.SEVERITY_MAP.get(vuln_type, "MEDIUM")

            # Check if credentials are mentioned (upgrades wildcard to CRITICAL)
            has_credentials = bool(re.search(r'credentials\s*[:=]\s*true', line, re.IGNORECASE))
            if vuln_type == "wildcard" and has_credentials:
                severity = "CRITICAL"

            finding = {
                "url": url,
                "type": vuln_type,
                "severity": severity,
                "credentials": has_credentials,
                "description": self._describe_vuln(vuln_type),
                "raw_line": line
            }

        # Pattern 2: "[Vulnerable] <url> | type: <type> | credentials: <bool>"
        if not finding:
            match = re.search(
                r'\[Vulnerable\]\s+(\S+)\s*\|\s*type:\s*(\S+)',
                line, re.IGNORECASE
            )
            if match:
                url = match.group(1)
                vuln_type = match.group(2).strip().lower()
                severity = self.SEVERITY_MAP.get(vuln_type, "MEDIUM")
                has_credentials = bool(re.search(r'credentials\s*[:=]\s*true', line, re.IGNORECASE))
                if vuln_type == "wildcard" and has_credentials:
                    severity = "CRITICAL"

                finding = {
                    "url": url,
                    "type": vuln_type,
                    "severity": severity,
                    "credentials": has_credentials,
                    "description": self._describe_vuln(vuln_type),
                    "raw_line": line
                }

        # Pattern 3: Generic vulnerable line with URL and type info
        if not finding:
            match = re.search(
                r'(https?://\S+)\s.*?(reflect_origin|prefix_match|suffix_match|not_escape_dot|null_origin|third_party|wildcard|include_match)',
                line, re.IGNORECASE
            )
            if match:
                url = match.group(1)
                vuln_type = match.group(2).strip().lower()
                severity = self.SEVERITY_MAP.get(vuln_type, "MEDIUM")
                has_credentials = bool(re.search(r'credentials\s*[:=]\s*true', line, re.IGNORECASE))
                if vuln_type == "wildcard" and has_credentials:
                    severity = "CRITICAL"

                finding = {
                    "url": url,
                    "type": vuln_type,
                    "severity": severity,
                    "credentials": has_credentials,
                    "description": self._describe_vuln(vuln_type),
                    "raw_line": line
                }

        return finding

    def _describe_vuln(self, vuln_type: str) -> str:
        """Return a human-readable description of the CORS vulnerability type."""
        descriptions = {
            "reflect_origin": "Server reflects the Origin header in Access-Control-Allow-Origin, allowing any origin to access resources",
            "prefix_match": "Server uses prefix matching for origin validation, allowing attacker-controlled subdomains",
            "suffix_match": "Server uses suffix matching for origin validation, allowing attacker-controlled domains with matching suffix",
            "not_escape_dot": "Server does not properly escape dots in origin validation, allowing similar domain bypasses",
            "null_origin": "Server allows the null origin, which can be exploited via sandboxed iframes or redirects",
            "third_party": "Server allows third-party origins that could be compromised to access resources",
            "wildcard": "Server uses wildcard (*) Access-Control-Allow-Origin, potentially with credentials enabled",
            "include_match": "Server uses substring/include matching for origin validation, allowing partial domain bypasses",
        }
        return descriptions.get(vuln_type, f"CORS misconfiguration: {vuln_type}")

    def _build_raw_output(self, raw_lines: list) -> str:
        """Build raw output string from collected lines, limited to 5MB"""
        if not raw_lines:
            return ""
        raw_output = '\n'.join(raw_lines)
        # Limit to 5MB to prevent 413 errors
        if len(raw_output) > 5 * 1024 * 1024:
            raw_output = '\n'.join(raw_lines[:1000]) + f"\n... (truncated, total {len(raw_lines)} lines)"
        return raw_output


def get_tool():
    return CorscannerScanTool()
