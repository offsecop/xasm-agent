"""
SQLMap Quick Scan Tool
Quickly detects SQL injection vulnerabilities (Risk Level 1)
"""

import asyncio
import json
import os
import time
from datetime import datetime
from plugin_interface import ToolPlugin
from typing import Dict, Any
from tools._sqlmap_base import parse_sqlmap_logs, is_valid_target, parse_log_file


class SqlmapQuickScanTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "sqlmap:quick_scan"

    @property
    def description(self) -> str:
        return "Quick SQL injection detection using SQLMap (Risk 1, ~5 min)"

    @property
    def schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target URL to test (e.g., http://example.com/page?id=1)"
                },
                "targets": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Multiple URLs to test (alternative to target)"
                },
                "cookie": {
                    "type": "string",
                    "description": "Authentication cookie (e.g., PHPSESSID=abc123)"
                },
                "headers": {
                    "type": "object",
                    "description": "Custom HTTP headers"
                },
                "data": {
                    "type": "string",
                    "description": "POST data (e.g., username=admin&password=test)"
                },
                "testParameter": {
                    "type": "string",
                    "description": "Specific parameter to test (e.g., id)"
                },
                "httpRequest": {
                    "type": "string",
                    "description": "Raw HTTP request (Phase 2: for -r mode)"
                },
                "findingId": {
                    "type": "string",
                    "description": "Finding ID to extract metadata from (Phase 2)"
                },
                "useMetadata": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Metadata to extract from finding (Phase 2)"
                }
            },
            "oneOf": [
                {"required": ["target"]},
                {"required": ["targets"]},
                {"required": ["httpRequest"]}
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
        """Execute SQLMap quick scan"""
        target = parameters.get("target")
        targets = parameters.get("targets")
        job_id = parameters.get("_job_id", "unknown")
        agent = parameters.get("_agent")
        
        # Extract exclusion patterns and rate limiting
        from tools._scope_utils import extract_exclusion_patterns, extract_rate_limit, filter_excluded_urls
        exclusion_url_patterns = extract_exclusion_patterns(parameters)
        rate_limit_config = extract_rate_limit(parameters)

        if not target and not targets:
            return {"success": False, "error": "Either 'target' or 'targets' required"}

        try:
            output_dir = f"/tmp/sqlmap_outputs/{job_id[:8]}"
            os.makedirs(output_dir, exist_ok=True)
            
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            target_file = None
            target_count = 1
            
            # Handle multiple targets
            if targets:
                if isinstance(targets, str):
                    try:
                        targets = json.loads(targets)
                    except json.JSONDecodeError:
                        targets = [targets]
                if not isinstance(targets, list):
                    targets = [targets]
                # Apply exclusion filtering
                if exclusion_url_patterns:
                    targets = filter_excluded_urls(targets, exclusion_url_patterns, "SQLMap Quick")
                target_count = len(targets)
                target_file = f"{output_dir}/targets_{timestamp}.txt"
                with open(target_file, 'w') as f:
                    f.write('\n'.join(targets))
                print(f"[SQLMap Quick] Scanning {target_count} targets")
                scan_target = f"{target_count} targets"
            else:
                print(f"[SQLMap Quick] Scanning {target}")
                scan_target = target
            
            # Report initial progress
            if agent:
                agent.report_progress(
                    current_operation="Starting SQLMap quick scan",
                    current_target=scan_target,
                    items_processed=0,
                    total_items=target_count
                )
            
            # Build SQLMap command
            cmd = ["sqlmap"]
            
            # Phase 2: Handle HTTP request (-r mode)
            request_file = None
            if parameters.get('httpRequest'):
                request_file = f"{output_dir}/request_{timestamp}.txt"
                with open(request_file, 'w') as f:
                    f.write(parameters['httpRequest'])
                cmd.extend(["-r", request_file])
                print(f"[SQLMap Quick] Using -r mode with HTTP request file")
            # Target specification
            elif targets:
                cmd.extend(["-m", target_file])
            elif target:
                cmd.extend(["-u", target])
            else:
                return {"success": False, "error": "No target or HTTP request provided"}
            
            # Core flags for quick scan - ALWAYS use --batch
            cmd.extend([
                "--batch",              # Non-interactive (CRITICAL)
                "--risk=1",             # Low risk
                "--level=1",            # Basic testing
                "--threads=4",          # Parallel
                "--timeout=30",         # Request timeout
                "--technique=BEUST",    # All except time-based
                "-o",                   # Optimizations
                f"--output-dir={output_dir}",
                "--flush-session",      # Clean slate
                "--no-cast",            # No casting of payloads
                "--disable-coloring",   # No ANSI colors
                "--answers=quit=N,follow=N,keepalive=Y"
            ])
            
            # Optional parameters
            if parameters.get("cookie"):
                cmd.extend(["--cookie", parameters["cookie"]])
            
            if parameters.get("headers"):
                for key, value in parameters["headers"].items():
                    cmd.extend(["--header", f"{key}: {value}"])
            
            if parameters.get("data"):
                cmd.extend(["--data", parameters["data"]])
            
            if parameters.get("testParameter"):
                cmd.extend(["-p", parameters["testParameter"]])
            
            # Apply rate limiting (--delay in seconds)
            if rate_limit_config and rate_limit_config.get('rateLimit'):
                delay_secs = max(0.1, round(1.0 / rate_limit_config['rateLimit'], 2))
                cmd.extend(["--delay", str(delay_secs)])
                print(f"[SQLMap Quick] Rate limit: {delay_secs}s delay between requests")

            # Apply exclusion for single target
            if target and not targets and exclusion_url_patterns:
                if not filter_excluded_urls([target], exclusion_url_patterns, ""):
                    return {"success": True, "output": {"findings": [], "total_findings": 0, "tool": "sqlmap", "scan_type": "quick", "note": "Target excluded by exclusion patterns"}, "raw_output": ""}

            print(f"[SQLMap Quick] Command: {' '.join(cmd)}")
            
            # Execute SQLMap
            start_time = time.time()
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            # Stream output for progress
            vulnerabilities = []
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
                    
                    # Parse for vulnerabilities
                    if "sqlmap identified" in line_str.lower() or "injectable" in line_str.lower():
                        if agent:
                            agent.append_output(f"[SQLMap] {line_str}")
                    
                    # Periodic progress update
                    current_time = time.time()
                    if agent and (current_time - last_update) >= 10:
                        elapsed = int(current_time - start_time)
                        agent.report_progress(
                            current_operation="Scanning for SQL injection",
                            current_target=scan_target,
                            items_processed=len(vulnerabilities),
                            total_items=target_count
                        )
                        agent.append_output(f"[SQLMap Quick] Scanning... ({elapsed}s elapsed)")
                        last_update = current_time
            
            # Read output with timeout (5 minutes for quick scan)
            try:
                await asyncio.wait_for(read_output(), timeout=300)
                await process.wait()
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                return {
                    "success": False,
                    "error": "SQLMap scan timed out after 5 minutes",
                    "output": {
                        "vulnerabilities": vulnerabilities,
                        "tool": "sqlmap",
                        "scan_type": "quick_scan",
                        "partial": True
                    },
                    "raw_output": "\n".join(output_lines[-100:])  # Last 100 lines
                }
            
            # Cleanup target and request files
            if target_file and os.path.exists(target_file):
                try:
                    os.remove(target_file)
                except Exception as e:
                    print(f"[SQLMap Quick] Warning: Could not delete target file: {e}")
            
            if request_file and os.path.exists(request_file):
                try:
                    os.remove(request_file)
                except Exception as e:
                    print(f"[SQLMap Quick] Warning: Could not delete request file: {e}")
            
            # Parse SQLMap log files for structured data
            # Parse logs and pass actual targets for proper URL extraction
            actual_targets = targets if targets else ([target] if target else [])
            vulnerabilities = self._parse_sqlmap_logs(output_dir, actual_targets)
            
            elapsed_time = int(time.time() - start_time)
            print(f"[SQLMap Quick] Scan completed in {elapsed_time}s, found {len(vulnerabilities)} vulnerabilities")
            
            # Report completion
            if agent:
                agent.report_progress(
                    current_operation="SQLMap scan completed",
                    current_target=scan_target,
                    items_processed=len(vulnerabilities),
                    total_items=len(vulnerabilities)
                )
            
            return {
                "success": True,
                "output": {
                    "vulnerabilities": vulnerabilities,
                    "target": target or f"{target_count} targets",
                    "targets": targets or [target],
                    "tool": "sqlmap",
                    "scan_type": "quick_scan",
                    "execution_time": elapsed_time
                },
                "raw_output": "\n".join(output_lines[-100:])  # Last 100 lines
            }
            
        except FileNotFoundError:
            return {"success": False, "error": "SQLMap not installed"}
        except Exception as e:
            return {"success": False, "error": f"Error running SQLMap: {str(e)}"}
    
    def _parse_sqlmap_logs(self, output_dir: str, targets: list = None) -> list:
        return parse_sqlmap_logs(output_dir, targets, tool_label="SQLMap Quick")


def get_tool():
    return SqlmapQuickScanTool()

