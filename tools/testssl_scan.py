"""
testssl.sh TLS/SSL Scanner Tool
Scans a target host for TLS/SSL vulnerabilities, weak ciphers, protocol issues,
and known attacks (Heartbleed, BEAST, POODLE, etc.) using testssl.sh.
"""

import asyncio
import json
import os
import time
from plugin_interface import ToolPlugin
from typing import Dict, Any
from urllib.parse import urlparse


SEVERITY_MAP = {
    "OK": None,       # Passing check, not a finding
    "INFO": "INFO",
    "LOW": "LOW",
    "MEDIUM": "MEDIUM",
    "HIGH": "HIGH",
    "CRITICAL": "CRITICAL",
    "WARN": "MEDIUM",
}


class TestsslScanTool(ToolPlugin):
    NON_TLS_SCHEMES = {"http", "ws"}

    @property
    def name(self) -> str:
        return "testssl:scan"

    @property
    def description(self) -> str:
        return "TLS/SSL scanner - checks for weak ciphers, outdated protocols, certificate issues, and known vulnerabilities (Heartbleed, BEAST, POODLE, etc.) using testssl.sh"

    @property
    def schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target host:port to scan (e.g., 'example.com:443' or 'example.com' which defaults to port 443)"
                },
                "targets": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Multiple host:port targets to scan (alternative to target, for workflow chaining)"
                },
                "maxTargets": {
                    "type": "integer",
                    "description": "Maximum number of targets to scan from array (default: 10)",
                    "default": 10
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
            "domain": ["ssl"],
            "input_type": ["hostname", "ip"],
            "output_type": ["findings"],
            "chainable_after": ["nmap:", "httpx:probe"],
            "chainable_before": [],
        }

    async def execute(self, parameters: Dict[str, Any]) -> Any:
        job_id = parameters.get("_job_id", "unknown")
        agent = parameters.get("_agent")

        # Resolve targets list
        targets_list = self._resolve_targets(parameters)
        if not targets_list:
            return {"success": False, "error": "'target' or 'targets' parameter is required",
                    "output": {"findings": [], "total_checks": 0, "issues_found": 0,
                               "target": "", "tool": "testssl", "scan_type": "tls"},
                    "raw_output": ""}

        # Apply maxTargets limit
        max_targets = parameters.get('maxTargets', 10)
        if len(targets_list) > max_targets:
            print(f"[testssl] Limiting {len(targets_list)} targets to {max_targets}")
            targets_list = targets_list[:max_targets]

        normalized_targets = []
        skipped_targets = []
        for raw_target in targets_list:
            normalized_target, skip_reason = self._normalize_target(raw_target)
            if normalized_target:
                normalized_targets.append(normalized_target)
            elif skip_reason:
                skipped_targets.append({"target": raw_target, "reason": skip_reason})
                print(f"[testssl] Skipping {raw_target}: {skip_reason}")
                if agent:
                    agent.append_output(f"[testssl] Skipping {raw_target}: {skip_reason}")

        if not normalized_targets:
            return {
                "success": True,
                "output": {
                    "findings": [],
                    "total_checks": 0,
                    "issues_found": 0,
                    "target": "",
                    "tool": "testssl",
                    "scan_type": "tls",
                    "skipped_targets": skipped_targets,
                    "note": "No TLS-compatible targets to scan",
                },
                "raw_output": "",
            }

        targets_list = normalized_targets

        total_targets = len(targets_list)
        print(f"[testssl] Starting TLS/SSL scan on {total_targets} target(s)")

        all_findings = []
        all_raw_lines = []
        total_checks_all = 0

        try:
            for t_idx, target in enumerate(targets_list):
                json_file = f"/tmp/testssl_{job_id}_{int(time.time())}_{t_idx}.json"

                if agent:
                    agent.report_progress(
                        current_operation=f"TLS/SSL scan ({t_idx + 1}/{total_targets})",
                        current_target=target,
                        items_processed=t_idx,
                        total_items=total_targets
                    )
                    agent.append_output(f"[testssl] Scanning {target} for TLS/SSL issues...")

                cmd = [
                    "testssl",
                    "--jsonfile", json_file,
                    "--sneaky",
                    "--severity", "LOW",
                    target
                ]

                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )

                raw_lines = []
                start_time = time.time()
                last_progress_time = start_time

                try:
                    async def read_output():
                        nonlocal last_progress_time

                        async def drain_stderr():
                            while True:
                                chunk = await process.stderr.read(4096)
                                if not chunk:
                                    break
                                line = chunk.decode("utf-8", errors="replace").strip()
                                if line:
                                    print(f"[testssl] stderr: {line}")

                        stderr_task = asyncio.create_task(drain_stderr())

                        try:
                            while True:
                                chunk = await process.stdout.read(4096)
                                if not chunk:
                                    break
                                text = chunk.decode("utf-8", errors="replace")
                                for line in text.splitlines():
                                    stripped = line.strip()
                                    if stripped:
                                        raw_lines.append(stripped)

                                now = time.time()
                                if agent and (now - last_progress_time) >= 10.0:
                                    elapsed = int(now - start_time)
                                    agent.report_progress(
                                        current_operation=f"TLS/SSL scan in progress ({t_idx + 1}/{total_targets})",
                                        current_target=target,
                                        items_processed=t_idx,
                                        total_items=total_targets
                                    )
                                    agent.append_output(f"[testssl] Scan in progress... ({elapsed}s elapsed)")
                                    last_progress_time = now
                        finally:
                            stderr_task.cancel()
                            try:
                                await stderr_task
                            except asyncio.CancelledError:
                                pass

                        await process.wait()

                    await asyncio.wait_for(read_output(), timeout=600)  # 10 minutes per target

                except asyncio.TimeoutError:
                    process.kill()
                    await process.wait()
                    print(f"[testssl] Scan timed out after 10 minutes for {target}")
                    if agent:
                        agent.append_output(f"[testssl] Scan timed out after 10 minutes for {target}")
                    all_raw_lines.extend(raw_lines[-200:])
                    # Clean up and continue to next target
                    if os.path.exists(json_file):
                        try:
                            os.remove(json_file)
                        except Exception:
                            pass
                    continue

                all_raw_lines.extend(raw_lines)

                # Parse JSON output file
                if os.path.exists(json_file):
                    try:
                        with open(json_file, "r") as f:
                            raw_json = f.read()
                        checks = json.loads(raw_json)
                        if not isinstance(checks, list):
                            checks = []

                        total_checks_all += len(checks)

                        for check in checks:
                            testssl_severity = check.get("severity", "").strip()
                            mapped_severity = SEVERITY_MAP.get(testssl_severity)
                            if mapped_severity is None:
                                continue
                            all_findings.append({
                                "id": check.get("id", "unknown"),
                                "severity": mapped_severity,
                                "finding": check.get("finding", ""),
                                "ip": check.get("ip", ""),
                                "port": check.get("port", ""),
                            })
                    except (json.JSONDecodeError, Exception) as e:
                        print(f"[testssl] Failed to parse JSON output for {target}: {e}")
                    finally:
                        try:
                            os.remove(json_file)
                        except Exception:
                            pass
                else:
                    print(f"[testssl] Warning: JSON output file not found for {target}")

                print(f"[testssl] [{t_idx + 1}/{total_targets}] {target}: {len(all_findings)} cumulative findings")

            issues_found = len(all_findings)
            print(f"[testssl] Ran {total_checks_all} checks across {total_targets} targets, found {issues_found} issues")

            if agent:
                agent.report_progress(
                    current_operation="TLS/SSL scan complete",
                    current_target=f"{total_targets} targets",
                    items_processed=total_targets,
                    total_items=total_targets
                )
                agent.append_output(f"[testssl] Ran {total_checks_all} checks, found {issues_found} issues across {total_targets} targets")

            raw_output = "\n".join(all_raw_lines)
            if len(raw_output) > 5 * 1024 * 1024:
                raw_output = raw_output[:5 * 1024 * 1024] + "\n... (truncated)"

            return {
                "success": True,
                "output": {
                    "findings": all_findings,
                    "total_checks": total_checks_all,
                    "issues_found": issues_found,
                    "target": targets_list[0] if len(targets_list) == 1 else f"{total_targets} targets",
                    "tool": "testssl",
                    "scan_type": "tls",
                    "skipped_targets": skipped_targets,
                },
                "raw_output": raw_output
            }

        except FileNotFoundError:
            return {
                "success": False,
                "error": "testssl.sh is not installed or not in PATH",
                "output": {
                    "findings": [],
                    "total_checks": 0,
                    "issues_found": 0,
                    "target": targets_list[0] if targets_list else "",
                    "tool": "testssl",
                    "scan_type": "tls",
                    "skipped_targets": skipped_targets,
                },
                "raw_output": ""
            }
        except Exception as e:
            print(f"[testssl] Error: {e}")
            return {
                "success": False,
                "error": str(e),
                "output": {
                    "findings": all_findings,
                    "total_checks": total_checks_all,
                    "issues_found": len(all_findings),
                    "target": targets_list[0] if targets_list else "",
                    "tool": "testssl",
                    "scan_type": "tls",
                    "skipped_targets": skipped_targets,
                },
                "raw_output": ""
            }


    def _normalize_target(self, raw_target: Any) -> tuple[str | None, str | None]:
        """Normalize URL-like targets into host:port and skip plain HTTP URLs."""
        target = str(raw_target or "").strip()
        if not target:
            return None, "empty target"

        if "://" in target:
            parsed = urlparse(target)
            hostname = parsed.hostname
            if not hostname:
                return None, "invalid URL target"

            scheme = (parsed.scheme or "").lower()
            if scheme in self.NON_TLS_SCHEMES:
                return None, f"non-TLS URL scheme '{scheme}'"

            port = parsed.port or 443
            return f"{hostname}:{port}", None

        if ":" not in target:
            return f"{target}:443", None

        return target, None

    def _resolve_targets(self, parameters: Dict[str, Any]) -> list:
        """Resolve target/targets parameter into a list."""
        if 'targets' in parameters and parameters['targets']:
            targets_param = parameters['targets']
            if isinstance(targets_param, str):
                try:
                    return json.loads(targets_param)
                except json.JSONDecodeError:
                    return [targets_param]
            elif isinstance(targets_param, list):
                return targets_param
            else:
                return [str(targets_param)]
        elif 'target' in parameters and parameters.get('target', '').strip():
            return [parameters['target'].strip()]
        return []


def get_tool():
    return TestsslScanTool()
