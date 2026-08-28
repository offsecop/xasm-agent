"""
SQLMap Detection Scan Tool
Comprehensive SQL injection detection (Risk Level 1)
"""

import asyncio
import hashlib
import json
import os
import re
import time
from datetime import datetime
from http import HTTPStatus
from plugin_interface import ToolPlugin
from typing import Dict, Any, Iterable, List, Tuple
from urllib.parse import urlparse, urlunparse

import aiohttp
from yarl import URL

from tools._sqlmap_base import parse_sqlmap_logs, is_valid_target, extract_target_url
from tools.web_authentication_probe import sanitize_evidence_text


PATH_PREFLIGHT_MAX_BODY_BYTES = 65_536
PATH_PREFLIGHT_USER_AGENT = "xASM-SQLMap-Path-Preflight/1.0"
SQL_ERROR_PATTERNS = (
    ("sql-syntax", re.compile(r"\bsql\s+syntax\b", re.I)),
    ("sqlstate", re.compile(r"\bsqlstate\s*\[", re.I)),
    ("unterminated-quoted-string", re.compile(r"unterminated\s+quoted\s+string", re.I)),
    ("unclosed-quotation-mark", re.compile(r"unclosed\s+quotation\s+mark", re.I)),
    ("quoted-string-not-terminated", re.compile(r"quoted\s+string\s+not\s+properly\s+terminated", re.I)),
    ("postgres-syntax-error", re.compile(r"syntax\s+error\s+at\s+or\s+near", re.I)),
    ("postgres-query-error", re.compile(r"\b(?:postgres(?:ql)?|pg_query)\b.{0,120}\b(?:error|failed|syntax)\b", re.I | re.S)),
    ("mysql-error", re.compile(r"\b(?:mysql|mysqli|mariadb)\b.{0,120}\b(?:error|warning|syntax)\b", re.I | re.S)),
    ("sqlite-error", re.compile(r"\b(?:sqlite[_ ]?error|sqliteexception|sqlite3\.operationalerror)\b", re.I)),
    ("oracle-error", re.compile(r"\bora-\d{4,5}\b", re.I)),
    ("sql-server-error", re.compile(r"\b(?:sql server|odbc sql|ole db)\b.{0,120}\b(?:error|driver|provider|syntax)\b", re.I | re.S)),
    ("database-query-error", re.compile(r"\b(?:database|db)\b.{0,80}\bquery\b.{0,80}\b(?:error|failed|syntax)\b", re.I | re.S)),
    ("query-database-error", re.compile(r"\bquery\b.{0,80}\b(?:database|sql|db)\b.{0,80}\b(?:error|failed|syntax)\b", re.I | re.S)),
)


class SqlmapDetectionScanTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "sqlmap:detection_scan"

    @property
    def description(self) -> str:
        return "Comprehensive SQL injection detection (Risk 1, ~15 min)"

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
        """Execute SQLMap detection scan."""
        target = parameters.get("target")
        targets = parameters.get("targets")
        http_request = parameters.get("httpRequest")
        job_id = parameters.get("_job_id", "unknown")
        agent = parameters.get("_agent")

        from tools._scope_utils import extract_exclusion_patterns, extract_rate_limit, filter_excluded_urls
        exclusion_url_patterns = extract_exclusion_patterns(parameters)
        rate_limit_config = extract_rate_limit(parameters)

        if not target and not targets and not http_request:
            return {"success": False, "error": "Either 'target', 'targets', or 'httpRequest' required"}

        try:
            overall_started_at = time.time()
            output_dir = f"/tmp/sqlmap_outputs/{job_id[:8]}"
            os.makedirs(output_dir, exist_ok=True)

            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            target_file = None
            request_file = None
            is_multi_target = bool(targets)

            if targets:
                if isinstance(targets, str):
                    try:
                        targets = json.loads(targets)
                    except json.JSONDecodeError:
                        targets = [targets]
                if not isinstance(targets, list):
                    targets = [targets]
                targets = [str(item) for item in targets if item]
                if exclusion_url_patterns:
                    targets = filter_excluded_urls(targets, exclusion_url_patterns, "SQLMap Detection")
                max_targets = parameters.get("maxTargets", 5)
                if len(targets) > max_targets:
                    print(f"[SQLMap Detection] Capping {len(targets)} targets to maxTargets={max_targets} (avoid 15m scan timeout)")
                    targets = targets[:max_targets]
                requested_targets = list(targets)
            elif target:
                requested_targets = [str(target)]
                if exclusion_url_patterns and not filter_excluded_urls(requested_targets, exclusion_url_patterns, ""):
                    return {"success": True, "output": {"findings": [], "total_findings": 0, "tool": "sqlmap", "scan_type": "detection", "note": "Target excluded"}, "raw_output": ""}
            else:
                requested_targets = []

            preflight_vulnerabilities: List[Dict[str, Any]] = []
            preflight_request_count = 0
            deferred_path_targets: List[str] = []
            remaining_targets = requested_targets
            if requested_targets and not http_request and not parameters.get("data"):
                (
                    preflight_vulnerabilities,
                    remaining_targets,
                    preflight_request_count,
                ) = await self._run_path_sqli_preflight(requested_targets, parameters)
                if preflight_vulnerabilities:
                    deferred_path_targets = [
                        item
                        for item in remaining_targets
                        if self._path_marker_urls(item) is not None
                    ]
                    remaining_targets = [
                        item
                        for item in remaining_targets
                        if self._path_marker_urls(item) is None
                    ]

            if is_multi_target:
                targets = remaining_targets
                target = None
            elif requested_targets:
                target = remaining_targets[0] if remaining_targets else None
                targets = None

            target_count = max(1, len(requested_targets))
            scan_target = (
                f"{len(requested_targets)} targets"
                if len(requested_targets) != 1
                else requested_targets[0]
            )

            if preflight_vulnerabilities:
                print(
                    f"[SQLMap Detection] Path preflight confirmed "
                    f"{len(preflight_vulnerabilities)} candidate(s) in "
                    f"{preflight_request_count} bounded request(s)"
                )

            if preflight_vulnerabilities and not remaining_targets and not http_request:
                elapsed_time = int(time.time() - overall_started_at)
                if agent:
                    agent.report_progress(
                        current_operation="SQL injection confirmed by bounded path differential",
                        current_target=scan_target,
                        items_processed=len(preflight_vulnerabilities),
                        total_items=len(requested_targets),
                    )
                return {
                    "success": True,
                    "output": {
                        "vulnerabilities": preflight_vulnerabilities,
                        "target": requested_targets[0] if len(requested_targets) == 1 else f"{len(requested_targets)} targets",
                        "targets": requested_targets,
                        "tool": "sqlmap",
                        "scan_type": "detection_scan",
                        "execution_time": elapsed_time,
                        "preflight_requests": preflight_request_count,
                        "sqlmap_targets": [],
                        "deferred_path_targets": deferred_path_targets,
                    },
                    "raw_output": (
                        "[SQLMap Detection Preflight] Strong SQL error differential "
                        f"confirmed for {len(preflight_vulnerabilities)} path candidate(s); "
                        "broad SQLMap scan skipped for confirmed candidates"
                        + (
                            f" and deferred for {len(deferred_path_targets)} unconfirmed "
                            "marked path sibling(s)."
                            if deferred_path_targets
                            else "."
                        )
                    ),
                }

            if agent:
                agent.report_progress(
                    current_operation="Starting SQLMap detection scan",
                    current_target=scan_target,
                    items_processed=len(preflight_vulnerabilities),
                    total_items=target_count,
                )

            cmd = ["sqlmap"]
            if http_request:
                request_file = f"{output_dir}/request_{timestamp}.txt"
                with open(request_file, 'w') as f:
                    f.write(http_request)
                cmd.extend(["-r", request_file])
                print("[SQLMap Detection] Using -r mode with HTTP request file")
            elif targets:
                target_file = f"{output_dir}/targets_{timestamp}.txt"
                with open(target_file, 'w') as f:
                    f.write('\n'.join(targets))
                cmd.extend(["-m", target_file])
            elif target:
                cmd.extend(["-u", target])
            else:
                return {"success": False, "error": "No target or HTTP request provided"}

            cmd.extend([
                "--batch",
                "--risk=1",
                "--level=3",
                "--threads=4",
                "--timeout=30",
                "--technique=BEUST",
                "-o",
                f"--output-dir={output_dir}",
                "--flush-session",
                "--no-cast",
                "--disable-coloring",
                "--answers=quit=N,follow=N,keepalive=Y",
            ])

            if parameters.get("testForms", True):
                cmd.append("--forms")

            crawl_depth = 0 if targets else parameters.get("crawlDepth", 2)
            if crawl_depth > 0:
                cmd.append(f"--crawl={crawl_depth}")

            if parameters.get("cookie"):
                cmd.extend(["--cookie", parameters["cookie"]])
            if parameters.get("headers"):
                for key, value in parameters["headers"].items():
                    cmd.extend(["--header", f"{key}: {value}"])
            if parameters.get("data"):
                cmd.extend(["--data", parameters["data"]])
            if parameters.get("testParameter"):
                cmd.extend(["-p", parameters["testParameter"]])
            if rate_limit_config and rate_limit_config.get('rateLimit'):
                delay_secs = max(0.1, round(1.0 / rate_limit_config['rateLimit'], 2))
                cmd.extend(["--delay", str(delay_secs)])

            print(f"[SQLMap Detection] Command: {' '.join(cmd)}")

            start_time = time.time()
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            vulnerabilities = list(preflight_vulnerabilities)
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
                            current_operation="Detecting SQL injection",
                            current_target=scan_target,
                            items_processed=len(vulnerabilities),
                            total_items=target_count,
                        )
                        agent.append_output(f"[SQLMap Detection] Scanning... ({elapsed}s elapsed)")
                        last_update = current_time

            try:
                await asyncio.wait_for(read_output(), timeout=900)
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
                        "partial": True,
                        "preflight_requests": preflight_request_count,
                        "deferred_path_targets": deferred_path_targets,
                    },
                    "raw_output": "\n".join(output_lines[-100:]),
                }

            if target_file and os.path.exists(target_file):
                try:
                    os.remove(target_file)
                except Exception:
                    pass

            actual_targets = targets if targets else ([target] if target else [])
            vulnerabilities.extend(self._parse_sqlmap_logs(output_dir, actual_targets))
            elapsed_time = int(time.time() - overall_started_at)
            raw_output = "\n".join(output_lines[-100:])

            connectivity_errors = (
                "unable to connect to the target url",
                "connection exception detected",
                "no route to host",
                "name or service not known",
                "temporary failure in name resolution",
            )
            target_unreachable = not vulnerabilities and any(
                marker in line.lower()
                for line in output_lines
                for marker in connectivity_errors
            )
            if target_unreachable:
                return {
                    "success": False,
                    "error": "SQLMap could not reach the target URL",
                    "output": {
                        "vulnerabilities": [],
                        "target": requested_targets[0] if len(requested_targets) == 1 else f"{target_count} targets",
                        "targets": requested_targets,
                        "tool": "sqlmap",
                        "scan_type": "detection_scan",
                        "execution_time": elapsed_time,
                        "preflight_requests": preflight_request_count,
                        "deferred_path_targets": deferred_path_targets,
                    },
                    "raw_output": raw_output,
                }

            if agent:
                agent.report_progress(
                    current_operation="SQLMap detection scan completed",
                    current_target=scan_target,
                    items_processed=len(vulnerabilities),
                    total_items=len(vulnerabilities),
                )

            return {
                "success": True,
                "output": {
                    "vulnerabilities": vulnerabilities,
                    "target": requested_targets[0] if len(requested_targets) == 1 else f"{target_count} targets",
                    "targets": requested_targets,
                    "tool": "sqlmap",
                    "scan_type": "detection_scan",
                    "execution_time": elapsed_time,
                    "preflight_requests": preflight_request_count,
                    "sqlmap_targets": actual_targets,
                    "deferred_path_targets": deferred_path_targets,
                },
                "raw_output": raw_output,
            }

        except FileNotFoundError:
            return {"success": False, "error": "SQLMap not installed"}
        except Exception as e:
            return {"success": False, "error": f"Error running SQLMap: {str(e)}"}

    async def _run_path_sqli_preflight(
        self,
        targets: Iterable[str],
        parameters: Dict[str, Any],
    ) -> Tuple[List[Dict[str, Any]], List[str], int]:
        target_list = list(targets)
        candidates = [target for target in target_list if self._path_marker_urls(target) is not None]
        if not candidates:
            return [], target_list, 0

        headers = {
            str(key): str(value)
            for key, value in (parameters.get("headers") or {}).items()
            if value is not None
        }
        headers.setdefault("User-Agent", PATH_PREFLIGHT_USER_AGENT)
        headers.setdefault("Accept", "text/html,application/json,*/*;q=0.8")
        cookie = str(parameters.get("cookie") or "")
        if cookie and not any(key.lower() == "cookie" for key in headers):
            headers["Cookie"] = cookie

        secret_values = [cookie]
        secret_values.extend(
            value for key, value in headers.items()
            if key.lower() in {
                "authorization", "cookie", "proxy-authorization", "x-api-key",
                "x-auth-token", "x-csrf-token", "x-xsrf-token",
            }
        )

        scope_controls = parameters.get("scopeControls") or {}
        rate_limit = scope_controls.get("rateLimit") or parameters.get("rateLimit")
        try:
            delay_seconds = max(0.0, 1.0 / float(rate_limit)) if float(rate_limit) > 0 else 0.0
        except (TypeError, ValueError, ZeroDivisionError):
            delay_seconds = 0.0

        vulnerabilities: List[Dict[str, Any]] = []
        confirmed_targets = set()
        request_count = 0
        timeout = aiohttp.ClientTimeout(total=12, connect=5)

        async with aiohttp.ClientSession(
            timeout=timeout,
            cookie_jar=aiohttp.DummyCookieJar(),
            raise_for_status=False,
        ) as session:
            for marked_target in candidates:
                urls = self._path_marker_urls(marked_target)
                if urls is None:
                    continue
                baseline_url, quote_url, parameter = urls
                try:
                    baseline = await self._fetch_path_preflight(session, baseline_url, headers)
                    request_count += 1
                    if delay_seconds:
                        await asyncio.sleep(delay_seconds)
                    mutated = await self._fetch_path_preflight(session, quote_url, headers)
                    request_count += 1
                except Exception as exc:
                    print(
                        f"[SQLMap Detection] Path preflight could not evaluate "
                        f"{baseline_url}: {type(exc).__name__}"
                    )
                    continue

                baseline_signals = set(self._sql_error_signals(baseline.get("body", "")))
                mutated_signals = set(self._sql_error_signals(mutated.get("body", "")))
                introduced_signals = sorted(mutated_signals - baseline_signals)
                status_transition = (
                    int(baseline.get("status") or 0) < 500
                    and 500 <= int(mutated.get("status") or 0) <= 599
                )
                if not status_transition or not introduced_signals:
                    continue

                baseline_step = self._http_evidence_step(
                    "path-sqli-baseline", baseline_url, headers, baseline, secret_values
                )
                mutated_step = self._http_evidence_step(
                    "path-sqli-single-quote", quote_url, headers, mutated, secret_values
                )
                matched_content = ", ".join(introduced_signals)
                vulnerabilities.append(
                    {
                        "target": baseline_url,
                        "vulnerable": True,
                        "injection_type": "error-based differential",
                        "parameter": parameter,
                        "dbms": None,
                        "payloads": ["%27"],
                        "request": mutated_step["request"],
                        "response": mutated_step["response"],
                        "baseline_request": baseline_step["request"],
                        "baseline_response": baseline_step["response"],
                        "matched_content": matched_content,
                        "http_evidence": {
                            "version": 1,
                            "steps": [baseline_step, mutated_step],
                        },
                    }
                )
                confirmed_targets.add(marked_target)

        remaining = [target for target in target_list if target not in confirmed_targets]
        return vulnerabilities, remaining, request_count

    def _path_marker_urls(self, target: str) -> Tuple[str, str, str] | None:
        try:
            parsed = urlparse(target)
        except ValueError:
            return None
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.fragment
            or parsed.path.count("*") != 1
            or "*" in parsed.netloc
            or "*" in parsed.query
        ):
            return None

        baseline_path = parsed.path.replace("*", "", 1)
        quote_path = parsed.path.replace("*", "%27", 1)
        marked_segment = next(
            (
                index
                for index, segment in enumerate(part for part in parsed.path.split("/") if part)
                if "*" in segment
            ),
            0,
        )
        parameter = f"path segment {marked_segment + 1}"
        return (
            urlunparse(parsed._replace(path=baseline_path)),
            urlunparse(parsed._replace(path=quote_path)),
            parameter,
        )

    async def _fetch_path_preflight(
        self,
        session: aiohttp.ClientSession,
        url: str,
        headers: Dict[str, str],
    ) -> Dict[str, Any]:
        async with session.get(
            URL(url, encoded=True),
            headers=headers,
            allow_redirects=False,
        ) as response:
            body = await response.content.read(PATH_PREFLIGHT_MAX_BODY_BYTES + 1)
            truncated = len(body) > PATH_PREFLIGHT_MAX_BODY_BYTES
            if truncated:
                body = body[:PATH_PREFLIGHT_MAX_BODY_BYTES]
            return {
                "status": int(response.status),
                "reason": str(response.reason or ""),
                "headers": dict(response.headers),
                "body": body.decode("utf-8", errors="replace").replace("\0", ""),
                "truncated": truncated,
            }

    def _sql_error_signals(self, body: str) -> List[str]:
        return [name for name, pattern in SQL_ERROR_PATTERNS if pattern.search(str(body or ""))]

    def _http_evidence_step(
        self,
        label: str,
        url: str,
        headers: Dict[str, str],
        response: Dict[str, Any],
        secret_values: Iterable[str],
    ) -> Dict[str, Any]:
        parsed = urlparse(url)
        path_and_query = parsed.path or "/"
        if parsed.query:
            path_and_query += f"?{parsed.query}"
        request_lines = [f"GET {path_and_query} HTTP/1.1", f"Host: {parsed.netloc}"]
        request_lines.extend(
            f"{key}: {value}" for key, value in headers.items() if key.lower() != "host"
        )
        request_text = sanitize_evidence_text(
            "\r\n".join(request_lines) + "\r\n\r\n",
            secret_values,
            12_000,
        )

        status = int(response.get("status") or 0)
        reason = str(response.get("reason") or "")
        if not reason and status:
            try:
                reason = HTTPStatus(status).phrase
            except ValueError:
                reason = "Unknown"
        response_lines = [f"HTTP/1.1 {status or 'N/A'}{f' {reason}' if reason else ''}"]
        for key, value in list((response.get("headers") or {}).items())[:30]:
            response_lines.append(f"{key}: {value}")
        response_lines.extend(["", str(response.get("body") or "")])
        response_text = sanitize_evidence_text(
            "\r\n".join(response_lines),
            secret_values,
            12_000,
        )
        return {
            "label": label,
            "carrierRole": "baseline" if label.endswith("baseline") else "mutation",
            "request": request_text,
            "requestSha256": hashlib.sha256(request_text.encode("utf-8")).hexdigest(),
            "response": response_text,
            "responseSha256": hashlib.sha256(response_text.encode("utf-8")).hexdigest(),
            "responseStatus": status,
            "responseBodyLength": len(str(response.get("body") or "").encode("utf-8")),
            "responseExcerptTruncated": bool(response.get("truncated")),
        }
    
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
