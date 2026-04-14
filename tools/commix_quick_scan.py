"""
Commix Quick Scan Tool
Quick OS command injection detection with minimal checks (Level 1).
"""

import asyncio
import json
import os
import re
import shutil
import time
from datetime import datetime
from plugin_interface import ToolPlugin
from typing import Dict, Any
from tools._commix_base import parse_commix_output


class CommixQuickScanTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "commix:quick_scan"

    @property
    def description(self) -> str:
        return "Quick OS command injection detection using Commix (level 1, ~10 min)"

    @property
    def schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target URL with parameters to test (e.g., http://example.com/page?cmd=test)"
                },
                "targets": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Multiple URLs with parameters to test"
                },
                "data": {
                    "type": "string",
                    "description": "POST data (e.g., username=admin&cmd=test)"
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
                "testParameter": {
                    "type": "string",
                    "description": "Specific parameter to test (e.g., cmd)"
                },
                "maxTargets": {
                    "type": "integer",
                    "description": "Maximum number of targets to scan from array (default: 20)",
                    "default": 20
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
        """Execute Commix quick command injection scan"""
        target = parameters.get("target")
        targets = parameters.get("targets")
        job_id = parameters.get("_job_id", "unknown")
        agent = parameters.get("_agent")

        # Extract exclusion patterns
        from tools._scope_utils import extract_exclusion_patterns, filter_excluded_urls
        exclusion_url_patterns = extract_exclusion_patterns(parameters)

        if not target and not targets:
            return {"success": False, "error": "Either 'target' or 'targets' required"}

        output_dir = f"/tmp/commix_outputs/{job_id[:8]}"

        try:
            os.makedirs(output_dir, exist_ok=True)

            # Normalize targets list
            if targets:
                if isinstance(targets, str):
                    try:
                        targets = json.loads(targets)
                    except json.JSONDecodeError:
                        targets = [targets]
                if not isinstance(targets, list):
                    targets = [targets]
            else:
                targets = [target]

            # Apply maxTargets limit
            max_targets = parameters.get('maxTargets', 20)
            if len(targets) > max_targets:
                print(f"[Commix Quick] Limiting {len(targets)} targets to {max_targets}")
                targets = targets[:max_targets]

            # Apply exclusion filtering
            if exclusion_url_patterns:
                targets = filter_excluded_urls(targets, exclusion_url_patterns, "Commix Quick")

            # Filter to only URLs with query parameters (command injection needs params)
            urls_with_params = [u for u in targets if '?' in u and '=' in u]
            urls_without_params = [u for u in targets if '?' not in u or '=' not in u]

            if urls_without_params:
                print(f"[Commix Quick] Skipping {len(urls_without_params)} URLs without query parameters")
            if urls_with_params:
                print(f"[Commix Quick] Scanning {len(urls_with_params)} URLs with query parameters")
                targets = urls_with_params
            else:
                if parameters.get("data"):
                    print(f"[Commix Quick] No URLs with query parameters, but POST data provided - proceeding")
                else:
                    return {
                        "success": True,
                        "output": {
                            "findings": [],
                            "total_findings": 0,
                            "target": target or f"{len(urls_without_params)} targets",
                            "targets": urls_without_params,
                            "tool": "commix",
                            "scan_type": "command_injection",
                            "note": "No URLs with query parameters found. Command injection testing requires URLs with parameters."
                        },
                        "raw_output": ""
                    }

            target_count = len(targets)
            scan_target = target if target else f"{target_count} targets"

            if agent:
                agent.report_progress(
                    current_operation="Starting Commix quick command injection scan",
                    current_target=scan_target,
                    items_processed=0,
                    total_items=target_count
                )

            all_findings = []
            all_output_lines = []
            start_time = time.time()

            # Scan each target individually
            for idx, scan_url in enumerate(targets):
                if agent:
                    agent.report_progress(
                        current_operation=f"Quick scanning target {idx + 1}/{target_count}",
                        current_target=scan_url,
                        items_processed=idx,
                        total_items=target_count
                    )
                    agent.append_output(f"[Commix Quick] Scanning ({idx + 1}/{target_count}): {scan_url}")

                target_output_dir = f"{output_dir}/target_{idx}"
                os.makedirs(target_output_dir, exist_ok=True)

                # Build command - quick scan uses --level=1 for minimal checks
                commix_path = os.environ.get('COMMIX_PATH', '/usr/local/bin/commix')
                cmd = ["python3", commix_path]
                cmd.extend(["--url", scan_url])
                cmd.extend([
                    "--batch",
                    "--level=1",
                    f"--output-dir={target_output_dir}",
                ])

                # POST data
                if parameters.get("data"):
                    cmd.extend(["--data", parameters["data"]])

                # Authentication: cookies
                if parameters.get("authCookies"):
                    cmd.extend(["--cookie", parameters["authCookies"]])

                # Authentication: custom headers
                if parameters.get("authHeaders"):
                    for header in parameters["authHeaders"]:
                        if header and header.strip():
                            cmd.extend(["--header", header])

                # Authentication: basic auth
                if parameters.get("authUsername") and parameters.get("authPassword"):
                    auth_str = f"{parameters['authUsername']}:{parameters['authPassword']}"
                    cmd.extend(["--auth-url", scan_url])
                    cmd.extend(["--auth-type", "basic"])
                    cmd.extend(["--auth-cred", auth_str])

                # Specific parameter to test
                if parameters.get("testParameter"):
                    cmd.extend(["-p", parameters["testParameter"]])

                print(f"[Commix Quick] Command: {' '.join(cmd)}")

                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )

                output_lines = []
                last_update = time.time()

                async def read_output():
                    nonlocal last_update
                    while True:
                        line = await process.stdout.readline()
                        if not line:
                            break
                        line_str = line.decode('utf-8', errors='replace').strip()
                        output_lines.append(line_str)

                        if line_str.startswith('[+]') or line_str.startswith('[*]'):
                            if agent:
                                agent.append_output(f"[Commix Quick] {line_str}")

                        current_time = time.time()
                        if agent and (current_time - last_update) >= 10:
                            elapsed = int(current_time - start_time)
                            agent.report_progress(
                                current_operation=f"Quick scan target {idx + 1}/{target_count}",
                                current_target=scan_url,
                                items_processed=idx,
                                total_items=target_count
                            )
                            agent.append_output(f"[Commix Quick] Scanning... ({elapsed}s elapsed)")
                            last_update = current_time

                try:
                    await asyncio.wait_for(read_output(), timeout=600)  # 10 minutes per target
                    await process.wait()
                except asyncio.TimeoutError:
                    process.kill()
                    await process.wait()
                    if agent:
                        agent.append_output(f"[Commix Quick] Timeout on target {scan_url}")

                # Read stderr
                stderr_data = await process.stderr.read()
                if stderr_data:
                    stderr_str = stderr_data.decode('utf-8', errors='replace').strip()
                    if stderr_str:
                        output_lines.append(f"[stderr] {stderr_str}")

                # Parse findings from output
                raw_text = '\n'.join(output_lines)
                target_findings = self._parse_commix_output(raw_text, scan_url)
                all_findings.extend(target_findings)
                all_output_lines.extend(output_lines)

                if target_findings:
                    print(f"[Commix Quick] Found {len(target_findings)} injection(s) in {scan_url}")

            elapsed_time = int(time.time() - start_time)

            if agent:
                agent.report_progress(
                    current_operation="Commix quick scan completed",
                    current_target=scan_target,
                    items_processed=len(all_findings),
                    total_items=len(all_findings)
                )

            print(f"[Commix Quick] Scan completed in {elapsed_time}s, found {len(all_findings)} total findings")

            return {
                "success": True,
                "output": {
                    "findings": all_findings,
                    "total_findings": len(all_findings),
                    "target": target or f"{target_count} targets",
                    "targets": targets,
                    "tool": "commix",
                    "scan_type": "command_injection",
                    "execution_time": elapsed_time
                },
                "raw_output": "\n".join(all_output_lines[-200:])
            }

        except FileNotFoundError:
            return {"success": False, "error": "Commix not installed. Install with: pip3 install commix"}
        except Exception as e:
            return {"success": False, "error": f"Error running Commix: {str(e)}"}
        finally:
            # Clean up output directory
            if os.path.exists(output_dir):
                try:
                    shutil.rmtree(output_dir)
                except Exception as e:
                    print(f"[Commix Quick] Warning: Could not clean up output dir: {e}")

    def _parse_commix_output(self, raw_output: str, target_url: str) -> list:
        return parse_commix_output(raw_output, target_url)


def get_tool():
    return CommixQuickScanTool()
