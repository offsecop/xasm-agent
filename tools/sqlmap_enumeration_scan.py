"""
SQLMap Enumeration Scan Tool
Database enumeration (read-only) - Risk Level 2
"""

import asyncio
import csv
import json
import os
import time
from datetime import datetime
from plugin_interface import ToolPlugin
from typing import Dict, Any
from tools._sqlmap_base import parse_sqlmap_logs, is_valid_target, extract_target_url


class SqlmapEnumerationScanTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "sqlmap:enumeration_scan"

    @property
    def description(self) -> str:
        return "SQL injection detection with database enumeration (Risk 2, ~30 min)"

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
                "enumerateDatabases": {
                    "type": "boolean",
                    "description": "List all databases",
                    "default": False
                },
                "enumerateTables": {
                    "type": "boolean",
                    "description": "List tables in current DB",
                    "default": False
                },
                "databaseName": {
                    "type": "string",
                    "description": "Specific database to enumerate"
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
        """Execute SQLMap enumeration scan"""
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
                    targets = filter_excluded_urls(targets, exclusion_url_patterns, "SQLMap Enumeration")
                target_count = len(targets)
                target_file = f"{output_dir}/targets_{timestamp}.txt"
                with open(target_file, 'w') as f:
                    f.write('\n'.join(targets))
                scan_target = f"{target_count} targets"
            else:
                scan_target = target
            
            if agent:
                agent.report_progress(
                    current_operation="Starting SQLMap enumeration scan",
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
                print(f"[SQLMap Enumeration] Using -r mode with HTTP request file")
            # Target specification
            elif targets:
                cmd.extend(["-m", target_file])
            elif target:
                cmd.extend(["-u", target])
            else:
                return {"success": False, "error": "No target or HTTP request provided"}
            
            # Enumeration scan flags - ALWAYS --batch
            cmd.extend([
                "--batch",
                "--risk=2",             # Medium risk
                "--level=4",            # Extensive testing
                "--threads=4",
                "--timeout=60",
                "--technique=BEUST",
                "-o",
                f"--output-dir={output_dir}",
                "--flush-session",
                "--no-cast",
                "--disable-coloring",
                "--answers=quit=N,follow=N,keepalive=Y",
                "--banner",
                "--current-user",
                "--current-db",
                "--is-dba"
            ])
            
            # Enumeration flags (controlled by parameters)
            if parameters.get("enumerateDatabases"):
                cmd.append("--dbs")
            
            if parameters.get("enumerateTables"):
                cmd.append("--tables")
                if parameters.get("databaseName"):
                    cmd.extend(["-D", parameters["databaseName"]])
            
            # Always get schema and counts
            cmd.extend(["--schema", "--count"])
            
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
            
            # Apply rate limiting
            if rate_limit_config and rate_limit_config.get('rateLimit'):
                delay_secs = max(0.1, round(1.0 / rate_limit_config['rateLimit'], 2))
                cmd.extend(["--delay", str(delay_secs)])

            # Apply exclusion for single target
            if target and not targets and exclusion_url_patterns:
                if not filter_excluded_urls([target], exclusion_url_patterns, ""):
                    return {"success": True, "output": {"findings": [], "total_findings": 0, "tool": "sqlmap", "scan_type": "enumeration", "note": "Target excluded"}, "raw_output": ""}

            print(f"[SQLMap Enumeration] Command: {' '.join(cmd)}")
            
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
                    
                    if any(keyword in line_str.lower() for keyword in ["injectable", "database:", "table:", "column:"]):
                        if agent:
                            agent.append_output(f"[SQLMap] {line_str}")
                    
                    current_time = time.time()
                    if agent and (current_time - last_update) >= 20:
                        elapsed = int(current_time - start_time)
                        agent.report_progress(
                            current_operation="Enumerating database structure",
                            current_target=scan_target,
                            items_processed=len(vulnerabilities),
                            total_items=target_count
                        )
                        agent.append_output(f"[SQLMap Enumeration] Scanning... ({elapsed}s elapsed)")
                        last_update = current_time
            
            try:
                await asyncio.wait_for(read_output(), timeout=1800)  # 30 minutes
                await process.wait()
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                return {
                    "success": False,
                    "error": "SQLMap scan timed out after 30 minutes",
                    "output": {
                        "vulnerabilities": vulnerabilities,
                        "tool": "sqlmap",
                        "scan_type": "enumeration_scan",
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
                    current_operation="SQLMap enumeration scan completed",
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
                    "scan_type": "enumeration_scan",
                    "execution_time": elapsed_time,
                    "enumeration": self._extract_enumeration_data(output_dir)
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
            print(f"[SQLMap Enumeration] Error parsing logs: {e}")
        return vulnerabilities

    def _parse_log_file(self, log_path: str, fallback_target: str = None) -> dict:
        """Extract vulnerability details with enumeration-specific fields."""
        try:
            with open(log_path, 'r', errors='replace') as f:
                content = f.read()

            if "sqlmap identified" not in content.lower() and "injectable" not in content.lower():
                return None

            target_url = extract_target_url(content, log_path, fallback_target, "SQLMap Enumeration")
            if not target_url:
                return None

            vuln = {
                "target": target_url,
                "vulnerable": True,
                "injection_type": None,
                "parameter": None,
                "dbms": None,
                "current_user": None,
                "current_db": None,
                "is_dba": None,
                "databases": [],
                "tables": [],
                "payloads": []
            }

            lines = content.split('\n')
            in_database_list = False
            in_table_list = False

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

                if "current user:" in line.lower() and "'" in line:
                    vuln["current_user"] = line.split("'")[1]

                if "current database:" in line.lower() and "'" in line:
                    vuln["current_db"] = line.split("'")[1]

                if "current user is DBA:" in line.lower():
                    vuln["is_dba"] = "true" in line.lower()

                # Parse database list
                if "available databases" in line.lower():
                    in_database_list = True
                elif in_database_list and line.strip().startswith("[*]"):
                    db_name = line.strip()[3:].strip()
                    if db_name:
                        vuln["databases"].append(db_name)
                elif in_database_list and not line.strip():
                    in_database_list = False

                # Parse table list
                if "database" in line.lower() and "table" in line.lower():
                    in_table_list = True
                elif in_table_list and line.strip().startswith("|"):
                    parts = [p.strip() for p in line.split("|") if p.strip()]
                    if parts:
                        vuln["tables"].append(parts[0])
                elif in_table_list and not line.strip():
                    in_table_list = False

                if "Payload:" in line and i + 1 < len(lines):
                    payload = lines[i + 1].strip()
                    if payload and payload not in vuln["payloads"]:
                        vuln["payloads"].append(payload)

            return vuln if vuln["vulnerable"] else None

        except Exception as e:
            print(f"[SQLMap Enumeration] Error parsing log: {e}")
            return None

    def _extract_enumeration_data(self, output_dir: str) -> dict:
        """Extract structured enumeration data from CSV exports.

        BUG-187 fix: Actually parse CSV files and log errors instead of silently passing.
        """
        enumeration = {
            "databases": [],
            "tables": [],
            "schema": {}
        }

        try:
            # SQLMap may create CSV files with enumeration data
            csv_dir = os.path.join(output_dir, "dump")
            if os.path.exists(csv_dir):
                for root, dirs, files in os.walk(csv_dir):
                    # Track database name from directory structure
                    db_name = os.path.basename(root)
                    if db_name == "dump":
                        continue

                    if db_name and db_name not in enumeration["databases"]:
                        enumeration["databases"].append(db_name)

                    for file in files:
                        if file.endswith('.csv'):
                            csv_path = os.path.join(root, file)
                            table_name = file[:-4]  # Remove .csv

                            if table_name not in enumeration["tables"]:
                                enumeration["tables"].append(table_name)

                            try:
                                with open(csv_path, 'r', errors='replace') as f:
                                    reader = csv.reader(f)
                                    rows = list(reader)

                                if rows:
                                    columns = rows[0]
                                    schema_key = f"{db_name}.{table_name}" if db_name else table_name
                                    enumeration["schema"][schema_key] = {
                                        "columns": columns,
                                        "row_count": len(rows) - 1
                                    }
                            except Exception as csv_err:
                                print(f"[SQLMap Enumeration] Error parsing CSV {csv_path}: {csv_err}")
        except Exception as e:
            print(f"[SQLMap Enumeration] Error extracting enumeration data: {e}")

        return enumeration


def get_tool():
    return SqlmapEnumerationScanTool()


