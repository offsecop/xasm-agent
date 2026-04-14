"""
SQLMap Detection Scan Tool
Comprehensive SQL injection detection with database identification (Risk Level 1)
"""

import asyncio
import json
import os
import time
from datetime import datetime
from plugin_interface import ToolPlugin
from typing import Dict, Any
from tools._sqlmap_base import parse_sqlmap_logs, is_valid_target, extract_target_url


class SqlmapDetectionScanTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "sqlmap:detection_scan"

    @property
    def description(self) -> str:
        return "Comprehensive SQL injection detection with DB identification (Risk 1, ~15 min)"

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
                "skipWaf": {
                    "type": "boolean",
                    "description": "Skip WAF detection",
                    "default": False
                },
                "testForms": {
                    "type": "boolean",
                    "description": "Auto-detect and test forms",
                    "default": True
                },
                "crawlDepth": {
                    "type": "integer",
                    "description": "Crawl depth for additional URLs",
                    "default": 2
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
            "chainable_before": ["sqlmap:full_scan"],
        }

    async def execute(self, parameters: Dict[str, Any]) -> Any:
        """Execute SQLMap detection scan"""
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
                    targets = filter_excluded_urls(targets, exclusion_url_patterns, "SQLMap Detection")
                target_count = len(targets)
                target_file = f"{output_dir}/targets_{timestamp}.txt"
                with open(target_file, 'w') as f:
                    f.write('\n'.join(targets))
                scan_target = f"{target_count} targets"
            else:
                scan_target = target
            
            if agent:
                agent.report_progress(
                    current_operation="Starting SQLMap detection scan",
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
                print(f"[SQLMap Detection] Using -r mode with HTTP request file")
            # Target specification
            elif targets:
                cmd.extend(["-m", target_file])
            elif target:
                cmd.extend(["-u", target])
            else:
                return {"success": False, "error": "No target or HTTP request provided"}
            
            # Detection scan flags - ALWAYS --batch
            cmd.extend([
                "--batch",
                "--risk=1",
                "--level=3",            # More thorough
                "--threads=4",
                "--timeout=30",
                "--technique=BEUST",
                "-o",
                f"--output-dir={output_dir}",
                "--flush-session",
                "--no-cast",
                "--disable-coloring",
                "--answers=quit=N,follow=N,keepalive=Y",
                "--banner",             # Retrieve DBMS banner
                "--current-user",       # Retrieve current user
                "--current-db",         # Retrieve current database
                "--is-dba"              # Check if user is DBA
            ])
            
            # Optional features
            if parameters.get("testForms", True):
                cmd.append("--forms")
            
            crawl_depth = parameters.get("crawlDepth", 2)
            if crawl_depth > 0:
                cmd.append(f"--crawl={crawl_depth}")
            
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

            # Apply exclusion for single target
            if target and not targets and exclusion_url_patterns:
                if not filter_excluded_urls([target], exclusion_url_patterns, ""):
                    return {"success": True, "output": {"findings": [], "total_findings": 0, "tool": "sqlmap", "scan_type": "detection", "note": "Target excluded"}, "raw_output": ""}

            print(f"[SQLMap Detection] Command: {' '.join(cmd)}")
            
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
                    
                    if "sqlmap identified" in line_str.lower() or "injectable" in line_str.lower() or "banner:" in line_str.lower():
                        if agent:
                            agent.append_output(f"[SQLMap] {line_str}")
                    
                    current_time = time.time()
                    if agent and (current_time - last_update) >= 15:
                        elapsed = int(current_time - start_time)
                        agent.report_progress(
                            current_operation="Detecting SQL injection and enumerating DB",
                            current_target=scan_target,
                            items_processed=len(vulnerabilities),
                            total_items=target_count
                        )
                        agent.append_output(f"[SQLMap Detection] Scanning... ({elapsed}s elapsed)")
                        last_update = current_time
            
            try:
                await asyncio.wait_for(read_output(), timeout=900)  # 15 minutes
                await process.wait()
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                return {
                    "success": False,
                    "error": "SQLMap scan timed out after 15 minutes",
                    "output": {
                        "vulnerabilities": vulnerabilities,
                        "tool": "sqlmap",
                        "scan_type": "detection_scan",
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
                    current_operation="SQLMap detection scan completed",
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
                    "scan_type": "detection_scan",
                    "execution_time": elapsed_time
                },
                "raw_output": "\n".join(output_lines[-100:])
            }
            
        except FileNotFoundError:
            return {"success": False, "error": "SQLMap not installed"}
        except Exception as e:
            return {"success": False, "error": f"Error running SQLMap: {str(e)}"}
    
    def _parse_sqlmap_logs(self, output_dir: str, targets: list = None) -> list:
        from tools._sqlmap_base import build_target_map
        vulnerabilities = []
        try:
            if not os.path.exists(output_dir):
                return vulnerabilities
            target_map = build_target_map(targets)
            for root, dirs, files in os.walk(output_dir):
                for file in files:
                    if file.endswith('.log') or file == 'log':
                        log_path = os.path.join(root, file)
                        fallback_target = None
                        if target_map:
                            for hostname, target_url in target_map.items():
                                if hostname in root:
                                    fallback_target = target_url
                                    break
                        vuln = self._parse_log_file(log_path, fallback_target)
                        if vuln:
                            vulnerabilities.append(vuln)
        except Exception as e:
            print(f"[SQLMap Detection] Error parsing logs: {e}")
        return vulnerabilities

    def _parse_log_file(self, log_path: str, fallback_target: str = None) -> dict:
        """Extract vulnerability details with detection-specific fields (banner, user, db, dba)."""
        try:
            with open(log_path, 'r', errors='replace') as f:
                content = f.read()

            if "sqlmap identified" not in content.lower() and "injectable" not in content.lower():
                return None

            target_url = extract_target_url(content, log_path, fallback_target, "SQLMap Detection")
            if not target_url:
                return None

            vuln = {
                "target": target_url,
                "vulnerable": True,
                "injection_type": None,
                "parameter": None,
                "dbms": None,
                "dbms_version": None,
                "current_user": None,
                "current_db": None,
                "is_dba": None,
                "banner": None,
                "payloads": [],
                "evidence": []
            }

            lines = content.split('\n')
            for i, line in enumerate(lines):
                if line.startswith("Parameter:"):
                    parts = line.split(":")
                    if len(parts) >= 2:
                        vuln["parameter"] = parts[1].strip().split("(")[0].strip()

                if line.strip().startswith("Type:") and not vuln["injection_type"]:
                    vuln["injection_type"] = line.split(":", 1)[1].strip()

                if "parameter" in line.lower() and "appears to be" in line.lower():
                    if "'" in line:
                        parts = line.split("'")
                        if len(parts) >= 2 and not vuln["parameter"]:
                            vuln["parameter"] = parts[1]
                        if len(parts) >= 4 and not vuln["injection_type"]:
                            vuln["injection_type"] = parts[3]

                if "back-end DBMS" in line.lower() and ":" in line:
                    vuln["dbms"] = line.split(":", 1)[1].strip()

                if "banner:" in line.lower() and "'" in line:
                    parts = line.split("'")
                    if len(parts) >= 2:
                        vuln["banner"] = parts[1]

                if "current user:" in line.lower() and "'" in line:
                    parts = line.split("'")
                    if len(parts) >= 2:
                        vuln["current_user"] = parts[1]

                if "current database:" in line.lower() and "'" in line:
                    parts = line.split("'")
                    if len(parts) >= 2:
                        vuln["current_db"] = parts[1]

                if "current user is DBA:" in line.lower():
                    vuln["is_dba"] = "true" in line.lower() or "yes" in line.lower()

                if "Payload:" in line and i + 1 < len(lines):
                    payload = lines[i + 1].strip()
                    if payload and payload not in vuln["payloads"]:
                        vuln["payloads"].append(payload)

                if "Title:" in line and i + 1 < len(lines):
                    title = lines[i + 1].strip()
                    if not vuln["injection_type"] and title:
                        vuln["injection_type"] = title

            return vuln if vuln["vulnerable"] else None

        except Exception as e:
            print(f"[SQLMap Detection] Error parsing log file: {e}")
            return None


def get_tool():
    return SqlmapDetectionScanTool()


