"""
ffuf Web Fuzzer Tool
Fast web fuzzer for directory/file discovery, vhost enumeration, and parameter fuzzing.
Uses ffuf to brute-force directories, virtual hosts, or GET/POST parameters.
"""

import asyncio
import json
import os
import time
from datetime import datetime
from urllib.parse import urlparse
from plugin_interface import ToolPlugin
from typing import Dict, Any


class FfufWebFuzzerTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "ffuf:web_fuzzer"

    @property
    def description(self) -> str:
        return "Fast web fuzzer for directory/file discovery, vhost enumeration, and parameter fuzzing using ffuf"

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
                "mode": {
                    "type": "string",
                    "enum": ["dir", "vhost", "param"],
                    "description": "Fuzzing mode: dir (directory discovery), vhost (virtual host enumeration), param (parameter fuzzing). Default: dir"
                },
                "wordlist": {
                    "type": "string",
                    "description": "Path to wordlist file (default: /usr/share/wordlists/dirb/common.txt)"
                },
                "matchCodes": {
                    "type": "array",
                    "items": {"type": "integer"},
                    "description": "HTTP status codes to match (default: [200, 201, 301, 302, 403])"
                },
                "filterSize": {
                    "type": "integer",
                    "description": "Filter responses by size (exclude responses of this byte size)"
                },
                "threads": {
                    "type": "integer",
                    "description": "Number of concurrent threads (default: 40)"
                },
                "maxTime": {
                    "type": "integer",
                    "description": "Maximum scan time in seconds (default: no limit)"
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
            "category": "enumeration",
            "phase": 3,
            "domain": ["web"],
            "input_type": ["url"],
            "output_type": ["urls"],
            "chainable_after": ["httpx:probe"],
            "chainable_before": ["nuclei:", "katana:", "gowitness:"],
        }

    async def execute(self, parameters: Dict[str, Any]) -> Any:
        """Execute ffuf web fuzzing scan"""
        target = parameters.get("target")
        targets = parameters.get("targets")
        job_id = parameters.get("_job_id", "unknown")
        agent = parameters.get("_agent")

        mode = parameters.get("mode", "dir")
        wordlist = parameters.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        match_codes = parameters.get("matchCodes", [200, 201, 301, 302, 403])
        filter_size = parameters.get("filterSize")
        threads = parameters.get("threads", 40)
        max_time = parameters.get("maxTime")

        # Extract exclusion patterns and rate limiting
        from tools._scope_utils import extract_exclusion_patterns, extract_rate_limit, filter_excluded_urls
        exclusion_url_patterns = extract_exclusion_patterns(parameters)
        rate_limit_config = extract_rate_limit(parameters)

        if not target and not targets:
            return {"success": False, "error": "Either 'target' or 'targets' required"}

        # Validate wordlist exists before running ffuf
        if not os.path.exists(wordlist):
            return {
                "success": False,
                "error": f"Wordlist not found at '{wordlist}'. Please specify a valid wordlist path via the 'wordlist' parameter.",
                "output": {"findings": [], "total_findings": 0, "tool": "ffuf", "scan_type": "web_fuzzing"}
            }

        try:
            output_dir = "/tmp/agent_outputs"
            os.makedirs(output_dir, exist_ok=True)

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

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

            # Apply exclusion filtering
            if exclusion_url_patterns:
                targets = filter_excluded_urls(targets, exclusion_url_patterns, "ffuf")

            total_targets = len(targets)
            scan_target = target if target and total_targets == 1 else f"{total_targets} targets"

            print(f"[ffuf] Mode: {mode}, Targets: {total_targets}, Threads: {threads}")
            print(f"[ffuf] Wordlist: {wordlist}")

            # Report initial progress
            if agent:
                agent.report_progress(
                    current_operation=f"Starting ffuf {mode} fuzzing",
                    current_target=scan_target,
                    items_processed=0,
                    total_items=total_targets
                )

            all_findings = []
            raw_output_lines = []

            for idx, current_target in enumerate(targets):
                # Strip trailing slash for consistent FUZZ placement
                current_target = current_target.rstrip("/")

                # Build the fuzz URL based on mode
                if mode == "dir":
                    fuzz_url = f"{current_target}/FUZZ"
                elif mode == "vhost":
                    fuzz_url = current_target
                elif mode == "param":
                    # For param mode, append FUZZ as a query parameter value
                    if "?" in current_target:
                        fuzz_url = current_target
                    else:
                        fuzz_url = f"{current_target}?FUZZ=test"
                else:
                    fuzz_url = f"{current_target}/FUZZ"

                output_file = f"{output_dir}/ffuf_{job_id[:8]}_{timestamp}_{idx}.json"

                # Build ffuf command
                cmd = [
                    "ffuf",
                    "-u", fuzz_url,
                    "-w", wordlist,
                    "-o", output_file,
                    "-of", "json",
                    "-mc", ",".join(str(c) for c in match_codes),
                    "-t", str(threads),
                    "-s"  # Silent mode (no banner)
                ]

                # Apply rate limiting
                if rate_limit_config and rate_limit_config.get('rateLimit'):
                    cmd.extend(["-rate", str(rate_limit_config['rateLimit'])])

                # Add vhost header for vhost mode
                if mode == "vhost":
                    parsed = urlparse(current_target)
                    cmd.extend(["-H", f"Host: FUZZ.{parsed.hostname}"])

                # Filter by response size if specified
                if filter_size is not None:
                    cmd.extend(["-fs", str(filter_size)])

                # Max execution time
                if max_time:
                    cmd.extend(["-maxtime", str(max_time)])

                print(f"[ffuf] [{idx + 1}/{total_targets}] Scanning {current_target} (mode: {mode})")

                if agent:
                    agent.report_progress(
                        current_operation=f"ffuf {mode} fuzzing",
                        current_target=current_target,
                        items_processed=idx,
                        total_items=total_targets
                    )

                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )

                start_time = time.time()

                # 20 minute timeout per target
                try:
                    async def run_ffuf():
                        stdout, stderr = await process.communicate()
                        return stdout, stderr

                    stdout, stderr = await asyncio.wait_for(run_ffuf(), timeout=1200)

                    stdout_str = stdout.decode("utf-8", errors="replace").replace("\0", "")
                    stderr_str = stderr.decode("utf-8", errors="replace").replace("\0", "")

                    if stderr_str.strip():
                        print(f"[ffuf] stderr: {stderr_str[:500]}")

                except asyncio.TimeoutError:
                    process.kill()
                    await process.wait()
                    elapsed = int(time.time() - start_time)
                    print(f"[ffuf] Target {current_target} timed out after {elapsed}s")
                    if agent:
                        agent.append_output(f"[ffuf] Target {current_target} timed out after {elapsed}s")
                    # Try to parse partial results from output file
                    pass

                # Parse JSON output file
                target_findings = []
                if os.path.exists(output_file):
                    try:
                        with open(output_file, "r") as f:
                            content = f.read().replace("\0", "")
                            ffuf_output = json.loads(content)

                        results = ffuf_output.get("results", [])
                        for result in results:
                            finding = {
                                "url": result.get("url", ""),
                                "status": result.get("status", 0),
                                "length": result.get("length", 0),
                                "words": result.get("words", 0),
                                "lines": result.get("lines", 0),
                                "content_type": result.get("content-type", ""),
                                "redirect_location": result.get("redirectlocation", ""),
                                "input_word": result.get("input", {}).get("FUZZ", ""),
                                "target": current_target,
                                "mode": mode,
                                "host": result.get("host", "")
                            }
                            target_findings.append(finding)

                        # Add command info to raw output
                        cmd_info = ffuf_output.get("commandline", "")
                        if cmd_info:
                            raw_output_lines.append(f"# Command: {cmd_info}")

                    except (json.JSONDecodeError, KeyError) as e:
                        print(f"[ffuf] Error parsing output for {current_target}: {e}")
                    finally:
                        # Cleanup output file
                        try:
                            os.remove(output_file)
                        except Exception:
                            pass

                all_findings.extend(target_findings)

                if agent and target_findings:
                    agent.append_output(
                        f"[ffuf] {current_target}: found {len(target_findings)} results"
                    )

                print(f"[ffuf] [{idx + 1}/{total_targets}] {current_target}: {len(target_findings)} results")

            print(f"[ffuf] Total findings across all targets: {len(all_findings)}")

            # Build raw output
            raw_output_sanitized = self._build_raw_output(all_findings, raw_output_lines)

            # Cap findings at 2000
            total_found = len(all_findings)
            if len(all_findings) > 2000:
                all_findings = all_findings[:2000]
                print(f"[ffuf] Capped findings from {total_found} to 2000 for delivery")

            # Final progress report
            if agent:
                agent.report_progress(
                    current_operation="ffuf fuzzing completed",
                    current_target=scan_target,
                    items_processed=total_found,
                    total_items=total_found
                )

            return {
                "success": True,
                "output": {
                    "findings": all_findings,
                    "total_findings": total_found,
                    "findings_delivered": len(all_findings),
                    "target": target if target else f"{total_targets} targets",
                    "targets": targets,
                    "tool": "ffuf",
                    "scan_type": mode
                },
                "raw_output": raw_output_sanitized
            }
        except FileNotFoundError:
            return {
                "success": False,
                "error": "ffuf not installed. Install with: go install github.com/ffuf/ffuf/v2@latest",
                "output": {
                    "findings": [],
                    "total_findings": 0,
                    "findings_delivered": 0,
                    "target": parameters.get("target", ""),
                    "targets": [],
                    "tool": "ffuf",
                    "scan_type": mode
                },
                "raw_output": ""
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Error running ffuf: {str(e)}",
                "output": {
                    "findings": [],
                    "total_findings": 0,
                    "findings_delivered": 0,
                    "target": parameters.get("target", ""),
                    "targets": [],
                    "tool": "ffuf",
                    "scan_type": mode
                },
                "raw_output": ""
            }

    def _build_raw_output(self, findings: list, extra_lines: list) -> str:
        """Build raw output string from findings, limited to 5MB"""
        if not findings and not extra_lines:
            return ""
        raw_lines = list(extra_lines)
        for f in findings:
            raw_lines.append(json.dumps(f))
        raw_output = "\n".join(raw_lines)
        # Limit to 5MB to prevent 413 errors
        if len(raw_output) > 5 * 1024 * 1024:
            raw_output = "\n".join(raw_lines[:1000]) + f"\n... (truncated, total {len(raw_lines)} lines)"
        return raw_output


def get_tool():
    return FfufWebFuzzerTool()
