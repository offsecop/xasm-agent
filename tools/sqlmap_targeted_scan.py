"""
SQLMap Targeted Scan Tool
Custom configuration with specific parameters (Risk Level 1-3, configurable)
"""

import asyncio
import json
import os
import time
from datetime import datetime
from plugin_interface import ToolPlugin
from typing import Dict, Any
from tools._sqlmap_base import parse_sqlmap_logs, is_valid_target, parse_log_file


class SqlmapTargetedScanTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "sqlmap:targeted_scan"

    @property
    def description(self) -> str:
        return "Custom SQL injection scan with specific parameters (Risk 1-3, ~60 min)"

    @property
    def schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target URL to test"
                },
                "targets": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Multiple URLs to test"
                },
                "cookie": {
                    "type": "string",
                    "description": "Authentication cookie"
                },
                "headers": {
                    "type": "object",
                    "description": "Custom HTTP headers"
                },
                "data": {
                    "type": "string",
                    "description": "POST data"
                },
                "testParameter": {
                    "type": "string",
                    "description": "Specific parameter to test"
                },
                "riskLevel": {
                    "type": "integer",
                    "description": "Risk level (1-3)",
                    "default": 1,
                    "minimum": 1,
                    "maximum": 3
                },
                "level": {
                    "type": "integer",
                    "description": "Test depth level (1-5)",
                    "default": 1,
                    "minimum": 1,
                    "maximum": 5
                },
                "technique": {
                    "type": "string",
                    "description": "Injection techniques (e.g., BEUST)",
                    "default": "BEUST"
                },
                "dbms": {
                    "type": "string",
                    "description": "Force specific DBMS (e.g., MySQL, PostgreSQL)"
                },
                "customFlags": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Custom sqlmap flags (advanced users only)"
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
        """Execute SQLMap targeted scan"""
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
            # Validate custom flags for prohibited operations
            custom_flags = parameters.get("customFlags", [])
            validation_error = self._validate_custom_flags(custom_flags)
            if validation_error:
                return {"success": False, "error": validation_error}
            
            output_dir = f"/tmp/sqlmap_outputs/{job_id[:8]}"
            os.makedirs(output_dir, exist_ok=True)
            
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            target_file = None
            target_count = 1
            
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
                    targets = filter_excluded_urls(targets, exclusion_url_patterns, "SQLMap Targeted")
                target_count = len(targets)
                target_file = f"{output_dir}/targets_{timestamp}.txt"
                with open(target_file, 'w') as f:
                    f.write('\n'.join(targets))
                scan_target = f"{target_count} targets"
            else:
                scan_target = target
            
            if agent:
                agent.report_progress(
                    current_operation="Starting SQLMap targeted scan",
                    current_target=scan_target,
                    items_processed=0,
                    total_items=target_count
                )
            
            # Build command
            cmd = ["sqlmap"]
            
            # Phase 2: Handle HTTP request (-r mode)
            request_file = None
            if parameters.get('httpRequest'):
                request_file = f"{output_dir}/request_{timestamp}.txt"
                with open(request_file, 'w') as f:
                    f.write(parameters['httpRequest'])
                cmd.extend(["-r", request_file])
                print(f"[SQLMap Targeted] Using -r mode with HTTP request file")
            # Target specification
            elif targets:
                cmd.extend(["-m", target_file])
            elif target:
                cmd.extend(["-u", target])
            else:
                return {"success": False, "error": "No target or HTTP request provided"}
            
            # Configurable scan flags - ALWAYS --batch
            risk_level = parameters.get("riskLevel", 1)
            level = parameters.get("level", 1)
            technique = parameters.get("technique", "BEUST")
            
            cmd.extend([
                "--batch",
                f"--risk={risk_level}",
                f"--level={level}",
                "--threads=4",
                "--timeout=60",
                f"--technique={technique}",
                "-o",
                f"--output-dir={output_dir}",
                "--flush-session",
                "--no-cast",
                "--disable-coloring",
                "--answers=quit=N,follow=N,keepalive=Y"
            ])
            
            # Optional DBMS specification
            if parameters.get("dbms"):
                cmd.extend(["--dbms", parameters["dbms"]])
            
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
            
            # Add custom flags (already validated)
            cmd.extend(custom_flags)
            
            # Apply rate limiting
            if rate_limit_config and rate_limit_config.get('rateLimit'):
                delay_secs = max(0.1, round(1.0 / rate_limit_config['rateLimit'], 2))
                cmd.extend(["--delay", str(delay_secs)])

            # Apply exclusion for single target
            if target and not targets and exclusion_url_patterns:
                if not filter_excluded_urls([target], exclusion_url_patterns, ""):
                    return {"success": True, "output": {"findings": [], "total_findings": 0, "tool": "sqlmap", "scan_type": "targeted", "note": "Target excluded"}, "raw_output": ""}

            print(f"[SQLMap Targeted] Command: {' '.join(cmd)}")
            print(f"[SQLMap Targeted] Risk Level: {risk_level}, Test Level: {level}")
            
            start_time = time.time()
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
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
                    
                    if "sqlmap identified" in line_str.lower() or "injectable" in line_str.lower():
                        if agent:
                            agent.append_output(f"[SQLMap] {line_str}")
                    
                    current_time = time.time()
                    if agent and (current_time - last_update) >= 15:
                        elapsed = int(current_time - start_time)
                        agent.report_progress(
                            current_operation="Targeted SQL injection testing",
                            current_target=scan_target,
                            items_processed=len(vulnerabilities),
                            total_items=target_count
                        )
                        agent.append_output(f"[SQLMap Targeted] Scanning... ({elapsed}s elapsed)")
                        last_update = current_time
            
            try:
                await asyncio.wait_for(read_output(), timeout=3600)  # 60 minutes
                await process.wait()
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                return {
                    "success": False,
                    "error": "SQLMap scan timed out after 60 minutes",
                    "output": {
                        "vulnerabilities": vulnerabilities,
                        "tool": "sqlmap",
                        "scan_type": "targeted_scan",
                        "partial": True
                    },
                    "raw_output": "\n".join(output_lines[-100:])
                }
            
            if target_file and os.path.exists(target_file):
                try:
                    os.remove(target_file)
                except Exception:
                    pass
            
            # Parse logs and pass actual targets for proper URL extraction
            actual_targets = targets if targets else ([target] if target else [])
            vulnerabilities = self._parse_sqlmap_logs(output_dir, actual_targets)
            elapsed_time = int(time.time() - start_time)
            
            if agent:
                agent.report_progress(
                    current_operation="SQLMap targeted scan completed",
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
                    "scan_type": "targeted_scan",
                    "execution_time": elapsed_time
                },
                "raw_output": "\n".join(output_lines[-100:])
            }
            
        except FileNotFoundError:
            return {"success": False, "error": "SQLMap not installed"}
        except Exception as e:
            return {"success": False, "error": f"Error running SQLMap: {str(e)}"}
    
    def _validate_custom_flags(self, custom_flags: list) -> str:
        """Validate that no prohibited flags are used"""
        # Prohibited operations
        prohibited = [
            '--dump', '--dump-all', '--sql-shell', '--os-shell',
            '--os-cmd', '--sql-file', '--priv-esc', '--file-write',
            '--file-dest', '--reg-', '--passwords'  # Password hashes restricted to full scan
        ]
        
        for flag in custom_flags:
            for prohibited_flag in prohibited:
                if prohibited_flag in flag.lower():
                    return f"Prohibited flag detected: {prohibited_flag}. This operation is not allowed for security reasons."
        
        return None
    
    def _parse_sqlmap_logs(self, output_dir: str, targets: list = None) -> list:
        return parse_sqlmap_logs(output_dir, targets, tool_label="SQLMap Targeted")


def get_tool():
    return SqlmapTargetedScanTool()


