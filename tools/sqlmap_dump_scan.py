"""
SQLMap Dump Scan Tool
Database content extraction (post-exploitation) - Risk Level 3

SECURITY NOTE: This tool allows --dump for authorized security assessments.
Row extraction is capped at 100 rows max per table.
"""

import asyncio
import csv
import json
import os
import time
from datetime import datetime
from plugin_interface import ToolPlugin
from typing import Dict, Any, List
from tools._sqlmap_base import parse_sqlmap_logs, is_valid_target, extract_target_url


class SqlmapDumpScanTool(ToolPlugin):
    # Maximum rows to extract per table (security cap)
    MAX_DUMP_LIMIT = 100

    @property
    def name(self) -> str:
        return "sqlmap:dump_scan"

    @property
    def description(self) -> str:
        return "SQL injection with database content extraction for post-exploitation evidence (Risk 3, ~30 min)"

    @property
    def schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target URL with SQLi vulnerability"
                },
                "targets": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Multiple vulnerable URLs to test"
                },
                "findingId": {
                    "type": "string",
                    "description": "Finding ID to enrich with dump data (preferred for enrichment flow)"
                },
                "dumpTables": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Specific tables to dump (required for safety)",
                    "default": []
                },
                "dumpDatabase": {
                    "type": "string",
                    "description": "Specific database name to target"
                },
                "dumpLimit": {
                    "type": "integer",
                    "description": "Max rows per table (default: 10, max: 100)",
                    "default": 10,
                    "minimum": 1,
                    "maximum": 100
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
                "httpRequest": {
                    "type": "string",
                    "description": "Raw HTTP request (for -r mode)"
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
            "chainable_after": ["katana:", "waybackurls:", "sqlmap:detection_scan"],
            "chainable_before": [],
        }

    async def execute(self, parameters: Dict[str, Any]) -> Any:
        """Execute SQLMap dump scan for post-exploitation evidence"""
        target = parameters.get("target")
        targets = parameters.get("targets")
        job_id = parameters.get("_job_id", "unknown")
        agent = parameters.get("_agent")
        finding_id = parameters.get("findingId")

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
                    targets = filter_excluded_urls(targets, exclusion_url_patterns, "SQLMap Dump")
                target_count = len(targets)
                target_file = f"{output_dir}/targets_{timestamp}.txt"
                with open(target_file, 'w') as f:
                    f.write('\n'.join(targets))
                scan_target = f"{target_count} targets"
            else:
                scan_target = target

            if agent:
                agent.report_progress(
                    current_operation="Starting SQLMap dump scan (post-exploitation)",
                    current_target=scan_target,
                    items_processed=0,
                    total_items=target_count
                )

            # Build command
            cmd = ["sqlmap"]

            # Handle HTTP request (-r mode)
            request_file = None
            if parameters.get('httpRequest'):
                request_file = f"{output_dir}/request_{timestamp}.txt"
                with open(request_file, 'w') as f:
                    f.write(parameters['httpRequest'])
                cmd.extend(["-r", request_file])
                print(f"[SQLMap Dump] Using -r mode with HTTP request file")
            elif targets:
                cmd.extend(["-m", target_file])
            elif target:
                cmd.extend(["-u", target])
            else:
                return {"success": False, "error": "No target or HTTP request provided"}

            # Enforce dump limit with security cap
            dump_limit = min(
                parameters.get("dumpLimit", 10),
                self.MAX_DUMP_LIMIT
            )

            # Dump scan flags - HIGHEST RISK (Risk Level 3)
            dump_tables = parameters.get("dumpTables", [])
            dump_database = parameters.get("dumpDatabase")

            cmd.extend([
                "--batch",
                "--risk=3",             # Maximum risk for dump
                "--level=5",            # Maximum depth
                "--threads=4",
                "--timeout=60",
                "--technique=BEUST",
                "-o",
                f"--output-dir={output_dir}",
                "--no-cast",
                "--disable-coloring",
                "--answers=quit=N,follow=N,keepalive=Y",
                f"--stop={dump_limit}", # Limit rows extracted
                "--csv-del=|",          # Use pipe delimiter for CSV
            ])

            # If specific database/tables provided, use --dump with -D/-T
            # Otherwise use --dump-all to enumerate and extract all
            if dump_database or dump_tables:
                cmd.append("--dump")    # Dump specific tables
            else:
                # Use dump-all for complete extraction
                cmd.extend([
                    "--dump-all",           # Dump all accessible tables
                    "--exclude-sysdbs",     # Skip system databases
                ])

            # Require specific database if provided
            if dump_database:
                cmd.extend(["-D", dump_database])

            # Require specific tables if provided
            if dump_tables:
                if isinstance(dump_tables, str):
                    try:
                        dump_tables = json.loads(dump_tables)
                    except json.JSONDecodeError:
                        dump_tables = [dump_tables]
                cmd.extend(["-T", ",".join(dump_tables)])

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
                    return {"success": True, "output": {"findings": [], "total_findings": 0, "tool": "sqlmap", "scan_type": "dump", "note": "Target excluded"}, "raw_output": ""}

            print(f"[SQLMap Dump] Command: {' '.join(cmd)}")
            print(f"[SQLMap Dump] Dump limit: {dump_limit} rows, Tables: {dump_tables or 'all'}")

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

                    # Log important events
                    if any(keyword in line_str.lower() for keyword in [
                        "injectable", "dumping", "table:", "fetched", "entries"
                    ]):
                        if agent:
                            agent.append_output(f"[SQLMap] {line_str}")

                    current_time = time.time()
                    if agent and (current_time - last_update) >= 20:
                        elapsed = int(current_time - start_time)
                        agent.report_progress(
                            current_operation="Extracting database contents",
                            current_target=scan_target,
                            items_processed=len(vulnerabilities),
                            total_items=target_count
                        )
                        agent.append_output(f"[SQLMap Dump] Extracting... ({elapsed}s elapsed)")
                        last_update = current_time

            try:
                await asyncio.wait_for(read_output(), timeout=1800)  # 30 minutes
                await process.wait()
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                return {
                    "success": False,
                    "error": "SQLMap dump scan timed out after 30 minutes",
                    "output": {
                        "vulnerabilities": vulnerabilities,
                        "tool": "sqlmap",
                        "scan_type": "dump_scan",
                        "partial": True
                    },
                    "raw_output": "\n".join(output_lines[-100:])
                }

            # Cleanup target file
            if target_file and os.path.exists(target_file):
                try:
                    os.remove(target_file)
                except Exception:
                    pass

            # Parse logs and dump data
            actual_targets = targets if targets else ([target] if target else [])
            vulnerabilities = self._parse_sqlmap_logs(output_dir, actual_targets)

            # Parse CSV dump files and attach to vulnerabilities
            dump_data = self._parse_dump_files(output_dir)

            # Merge dump data into vulnerabilities
            for vuln in vulnerabilities:
                vuln["dump_data"] = dump_data

            elapsed_time = int(time.time() - start_time)

            if agent:
                agent.report_progress(
                    current_operation="SQLMap dump scan completed",
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
                    "scan_type": "dump_scan",
                    "execution_time": elapsed_time,
                    "dump_data": dump_data,
                    "findingId": finding_id  # Pass through for enrichment
                },
                "parameters": {
                    "findingId": finding_id  # Ensure findingId is in parameters for ingestion
                },
                "raw_output": "\n".join(output_lines[-100:])
            }

        except FileNotFoundError:
            return {"success": False, "error": "SQLMap not installed"}
        except Exception as e:
            return {"success": False, "error": f"Error running SQLMap: {str(e)}"}

    def _parse_dump_files(self, output_dir: str) -> Dict[str, Any]:
        """Parse CSV dump files from SQLMap output

        SQLMap creates dump files at: {output_dir}/{hostname}/dump/{db_name}/{table_name}.csv
        We need to search recursively for the dump directory.
        """
        dump_data = {
            "databases": {},
            "total_rows_extracted": 0
        }

        try:
            # SQLMap creates: {output_dir}/{hostname}/dump/{database}/{table}.csv
            # Walk the output directory to find any 'dump' subdirectory
            dump_dir = None
            for root, dirs, files in os.walk(output_dir):
                if 'dump' in dirs:
                    dump_dir = os.path.join(root, 'dump')
                    print(f"[SQLMap Dump] Found dump directory at {dump_dir}")
                    break

            if not dump_dir or not os.path.exists(dump_dir):
                print(f"[SQLMap Dump] No dump directory found in {output_dir}")
                # List what directories exist for debugging
                for root, dirs, files in os.walk(output_dir):
                    print(f"[SQLMap Dump] Found: {root} -> dirs: {dirs}, files: {files[:5]}")
                return dump_data

            # Walk through dump directory structure: dump/{db_name}/{table}.csv
            for db_name in os.listdir(dump_dir):
                db_path = os.path.join(dump_dir, db_name)
                if not os.path.isdir(db_path):
                    continue

                dump_data["databases"][db_name] = {"tables": {}}

                for filename in os.listdir(db_path):
                    if filename.endswith('.csv'):
                        table_name = filename[:-4]  # Remove .csv extension
                        csv_path = os.path.join(db_path, filename)

                        table_data = self._parse_csv_file(csv_path)
                        if table_data:
                            dump_data["databases"][db_name]["tables"][table_name] = table_data
                            dump_data["total_rows_extracted"] += len(table_data.get("rows", []))
                            print(f"[SQLMap Dump] Parsed table {db_name}.{table_name}: {len(table_data.get('rows', []))} rows")

            print(f"[SQLMap Dump] Extracted {dump_data['total_rows_extracted']} total rows from {len(dump_data['databases'])} database(s)")

        except Exception as e:
            print(f"[SQLMap Dump] Error parsing dump files: {e}")
            import traceback
            traceback.print_exc()

        return dump_data

    def _parse_csv_file(self, csv_path: str) -> Dict[str, Any]:
        """Parse a single CSV dump file"""
        try:
            with open(csv_path, 'r', errors='replace') as f:
                # SQLMap uses | as delimiter
                reader = csv.reader(f, delimiter='|')
                rows = list(reader)

            if not rows:
                return None

            # First row is column headers
            columns = rows[0] if rows else []
            data_rows = []

            for row in rows[1:]:
                if row and len(row) == len(columns):
                    row_dict = {}
                    for i, col in enumerate(columns):
                        # Mask sensitive data patterns
                        value = row[i] if i < len(row) else ""
                        row_dict[col] = self._mask_sensitive_value(col, value)
                    data_rows.append(row_dict)

            return {
                "columns": columns,
                "rows": data_rows[:self.MAX_DUMP_LIMIT],  # Double-check limit
                "total_rows": len(data_rows),
                "file": os.path.basename(csv_path)
            }

        except Exception as e:
            print(f"[SQLMap Dump] Error parsing CSV {csv_path}: {e}")
            return None

    def _mask_sensitive_value(self, column: str, value: str) -> str:
        """Mask potentially sensitive values for security

        Shows first 4 chars + "..." for password-related columns
        Full value shown for evidence (user responsible for secure handling)
        """
        sensitive_columns = ['password', 'passwd', 'pwd', 'secret', 'token', 'key', 'api_key']

        col_lower = column.lower()
        for sensitive in sensitive_columns:
            if sensitive in col_lower:
                if len(value) > 8:
                    # Show partial hash for evidence without full disclosure
                    return f"{value[:8]}...{value[-4:]}" if len(value) > 12 else f"{value[:4]}..."
                return value[:4] + "..." if len(value) > 4 else value

        return value

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
            print(f"[SQLMap Dump] Error parsing logs: {e}")
        return vulnerabilities

    def _parse_log_file(self, log_path: str, fallback_target: str = None) -> dict:
        """Extract vulnerability details with dump-specific fields (tables_dumped)."""
        try:
            with open(log_path, 'r', errors='replace') as f:
                content = f.read()

            if "sqlmap identified" not in content.lower() and "injectable" not in content.lower():
                return None

            target_url = extract_target_url(content, log_path, fallback_target, "SQLMap Dump")
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
                "tables_dumped": [],
                "payloads": []
            }

            lines = content.split('\n')

            for i, line in enumerate(lines):
                if line.startswith("Parameter:"):
                    parts = line.split(":")
                    if len(parts) >= 2:
                        vuln["parameter"] = parts[1].strip().split("(")[0].strip()

                if line.strip().startswith("Type:") and not vuln["injection_type"]:
                    vuln["injection_type"] = line.split(":", 1)[1].strip()

                if "back-end DBMS" in line.lower() and ":" in line:
                    vuln["dbms"] = line.split(":", 1)[1].strip()

                if "current user:" in line.lower() and "'" in line:
                    vuln["current_user"] = line.split("'")[1]

                if "current database:" in line.lower() and "'" in line:
                    vuln["current_db"] = line.split("'")[1]

                if "current user is DBA:" in line.lower():
                    vuln["is_dba"] = "true" in line.lower()

                # Tables dumped
                if "dumping table" in line.lower() or "fetching entries for table" in line.lower():
                    if "'" in line:
                        parts = line.split("'")
                        for part in parts:
                            if part and part not in vuln["tables_dumped"]:
                                if "." in part or part.isalnum():
                                    vuln["tables_dumped"].append(part)

                if "Payload:" in line and i + 1 < len(lines):
                    payload = lines[i + 1].strip()
                    if payload and payload not in vuln["payloads"]:
                        vuln["payloads"].append(payload)

            return vuln if vuln["vulnerable"] else None

        except Exception as e:
            print(f"[SQLMap Dump] Error parsing log: {e}")
            return None


def get_tool():
    return SqlmapDumpScanTool()
