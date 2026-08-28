"""
Dalfox XSS Scanner Tool
Cross-Site Scripting (XSS) vulnerability detection using Dalfox.
Scans URL parameters for reflected, stored, and DOM-based XSS vulnerabilities.
IMPORTANT: Target URLs must include query parameters (e.g., ?q=test) for XSS testing.
"""

import asyncio
import base64
import json
import os
import re
import time
from datetime import datetime
from plugin_interface import ToolPlugin
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import parse_qsl, urlsplit

import aiohttp


# ToolRegistryEntry kills the job at 600 seconds. Leave one minute for result
# normalization and delivery so the agent cannot report a late phantom success.
DALFOX_TIMEOUT_SECONDS = 540
DALFOX_DEFAULT_CONCURRENCY = 5
DALFOX_MAX_CONCURRENCY = 20
DALFOX_EVIDENCE_MAX_FINDINGS = 6
DALFOX_EVIDENCE_MAX_BYTES = 16_000
DALFOX_EVIDENCE_TIMEOUT_SECONDS = 12
DALFOX_EVIDENCE_CONCURRENCY = 3

_SENSITIVE_HEADER_NAMES = {"authorization", "cookie", "set-cookie", "x-api-key"}
_SENSITIVE_TEXT_PATTERNS = (
    (re.compile(r"(?im)^(Authorization|Cookie|Set-Cookie|X-Api-Key)\s*:[^\r\n]*$"), r"\1: [REDACTED]"),
    (re.compile(r"(?i)(Bearer\s+)[A-Za-z0-9._~+/=-]{12,}"), r"\1[REDACTED]"),
    (re.compile(r"(?i)eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"), "[REDACTED_JWT]"),
    (
        re.compile(
            r"(?i)(\"?(?:password|passwd|token|access_token|refresh_token|api_key|secret)\"?\s*[:=]\s*\"?)([^\"\s,;&}]{4,})"
        ),
        r"\1[REDACTED]",
    ),
    (re.compile(r"(?<![0-9])(?:[0-9][ -]?){13,19}(?![0-9])"), "[REDACTED_NUMBER]"),
)


class DalfoxXssScanTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "dalfox:xss_scan"

    @property
    def description(self) -> str:
        return "XSS vulnerability scanner - tests URL parameters for reflected, stored, and DOM-based Cross-Site Scripting. Targets MUST have query parameters (e.g. ?q=test&page=1)"

    @property
    def schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Single target URL with parameters (e.g., http://example.com/search?q=test)"
                },
                "targets": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Multiple target URLs with parameters to scan (alternative to target)"
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
                "authCookies": {
                    "type": "string",
                    "description": "Session cookies (format: 'name1=value1; name2=value2')",
                    "x-hidden": True
                },
                "authHeaders": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Custom HTTP headers for authentication (format: 'Header: Value')",
                    "x-hidden": True
                },
                "maxTargets": {
                    "type": "integer",
                    "description": "Maximum number of targets to scan from array (default: 50)",
                    "default": 50
                },
                "concurrency": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": DALFOX_MAX_CONCURRENCY,
                    "description": "Bounded Dalfox worker count. A conservative default avoids target throttling that can hide verified XSS results.",
                    "default": DALFOX_DEFAULT_CONCURRENCY
                },
                "skipParameterMining": {
                    "type": "boolean",
                    "description": "Skip dictionary and DOM parameter mining when explicit parameterized URLs are supplied (default: true).",
                    "default": True
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
        """Execute Dalfox XSS scan"""
        target = parameters.get("target")
        targets = parameters.get("targets")
        job_id = parameters.get("_job_id", "unknown")
        agent = parameters.get("_agent")

        # Extract authentication parameters
        auth_username = parameters.get("authUsername")
        auth_password = parameters.get("authPassword")
        auth_cookies = parameters.get("authCookies")
        auth_headers = parameters.get("authHeaders", [])

        # Extract exclusion patterns and rate limiting
        from tools._scope_utils import extract_exclusion_patterns, extract_rate_limit, filter_excluded_urls
        exclusion_url_patterns = extract_exclusion_patterns(parameters)
        rate_limit_config = extract_rate_limit(parameters)

        if not target and not targets:
            return {"success": False, "error": "Either 'target' or 'targets' required"}

        try:
            output_dir = "/tmp/agent_outputs"
            os.makedirs(output_dir, exist_ok=True)

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

            target_file = None
            scan_target = target if target else f"{len(targets) if targets else 0} targets"

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
                max_targets = parameters.get('maxTargets', 50)
                if len(targets) > max_targets:
                    print(f"[Dalfox] Limiting {len(targets)} targets to {max_targets}")
                    targets = targets[:max_targets]

                # Filter to only URLs with query parameters (XSS needs params to test)
                urls_with_params = [u for u in targets if '?' in u and '=' in u]
                urls_without_params = [u for u in targets if '?' not in u or '=' not in u]

                if urls_without_params:
                    print(f"[Dalfox] Skipping {len(urls_without_params)} URLs without query parameters (XSS testing requires params)")

                if urls_with_params:
                    # Apply exclusion filtering
                    if exclusion_url_patterns:
                        urls_with_params = filter_excluded_urls(urls_with_params, exclusion_url_patterns, "Dalfox")
                    print(f"[Dalfox] Scanning {len(urls_with_params)} URLs with query parameters")
                    targets = urls_with_params
                else:
                    return {
                        "success": False,
                        "error": f"No URLs with query parameters found. Dalfox XSS testing requires URLs with parameters (e.g., ?q=test). All {len(urls_without_params)} provided URLs lack query parameters.",
                        "output": {
                            "findings": [],
                            "total_findings": 0,
                            "findings_delivered": 0,
                            "target": scan_target,
                            "targets": targets,
                            "tool": "dalfox",
                            "scan_type": "xss",
                            "skipped_urls": urls_without_params
                        },
                        "raw_output": ""
                    }

                target_file = f"{output_dir}/dalfox_targets_{job_id[:8]}_{timestamp}.txt"
                with open(target_file, 'w') as f:
                    f.write('\n'.join(targets))
                print(f"[Dalfox] Scanning {len(targets)} target URLs for XSS")
            else:
                if '?' not in target or '=' not in target:
                    print(f"[Dalfox] WARNING: Target '{target}' has no query parameters. XSS testing works best with URLs like ?q=test")
                print(f"[Dalfox] Scanning {target}")

            # Compute total_targets AFTER all target resolution/filtering
            total_targets = len(targets) if targets else 1

            # Build dalfox command
            if targets:
                cmd = [
                    "dalfox", "file", target_file,
                    "--format", "json",
                    "--silence"
                ]
            else:
                cmd = [
                    "dalfox", "url", target,
                    "--format", "json",
                    "--silence"
                ]

            # Dalfox defaults to 100 workers. That is too aggressive for many
            # real targets (including intentionally vulnerable training labs):
            # throttled verification requests can make a reflected XSS scan
            # finish with zero PoCs. Keep explicit parameterized scans bounded
            # and skip unrelated parameter mining by default.
            try:
                worker_count = int(parameters.get('concurrency', DALFOX_DEFAULT_CONCURRENCY))
            except (TypeError, ValueError):
                worker_count = DALFOX_DEFAULT_CONCURRENCY
            worker_count = max(1, min(DALFOX_MAX_CONCURRENCY, worker_count))
            if parameters.get('skipParameterMining', True):
                cmd.append("--skip-mining-all")

            # Apply rate limiting (dalfox uses --delay in milliseconds and --worker)
            if rate_limit_config:
                if rate_limit_config.get('rateLimit'):
                    delay_ms = max(1, int(1000 / rate_limit_config['rateLimit']))
                    cmd.extend(["--delay", str(delay_ms)])
                if rate_limit_config.get('concurrency'):
                    worker_count = max(
                        1,
                        min(DALFOX_MAX_CONCURRENCY, int(rate_limit_config['concurrency'])),
                    )
                print(f"[Dalfox] Rate limit: {rate_limit_config.get('rateLimit')} req/s")
            cmd.extend(["--worker", str(worker_count)])
            print(f"[Dalfox] Worker concurrency: {worker_count}")

            # Also apply exclusion for single target
            if target and not targets and exclusion_url_patterns:
                from tools._scope_utils import filter_excluded_urls as _feu
                if not _feu([target], exclusion_url_patterns, ""):
                    return {
                        "success": True,
                        "output": {
                            "findings": [], "total_findings": 0, "findings_delivered": 0,
                            "target": target, "targets": [target], "tool": "dalfox",
                            "scan_type": "xss", "note": "Target excluded by exclusion patterns"
                        },
                        "raw_output": ""
                    }

            # Add authentication options
            auth_used = False
            if auth_username and auth_password:
                auth_str = f"{auth_username}:{auth_password}"
                auth_b64 = base64.b64encode(auth_str.encode()).decode()
                cmd.extend(["--header", f"Authorization: Basic {auth_b64}"])
                print(f"[Dalfox] Using HTTP Basic Authentication (user: {auth_username})")
                auth_used = True

            if auth_cookies:
                cmd.extend(["--cookie", auth_cookies])
                print(f"[Dalfox] Using session cookies (***REDACTED***)")
                auth_used = True

            if auth_headers:
                for header in auth_headers:
                    if header and header.strip():
                        cmd.extend(["--header", header])
                        print(f"[Dalfox] Added custom header")
                auth_used = True

            if auth_used:
                print(f"[Dalfox] Authenticated XSS scan mode enabled")
            else:
                print(f"[Dalfox] Public/unauthenticated XSS scan mode")

            # Report initial progress
            if agent:
                agent.report_progress(
                    current_operation="Starting Dalfox XSS scan",
                    current_target=scan_target,
                    items_processed=0,
                    total_items=total_targets
                )

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout_chunks: List[bytes] = []
            stderr_chunks: List[bytes] = []
            last_progress_update = time.time()
            progress_update_interval = 5.0
            start_time = time.time()

            # Keep the scanner inside the registry's 10-minute job deadline.
            try:
                async def read_output():
                    nonlocal last_progress_update

                    async def read_stderr():
                        """Read stderr in parallel to capture errors"""
                        while True:
                            chunk = await process.stderr.read(1024)
                            if not chunk:
                                break
                            stderr_chunks.append(chunk)
                            stderr_line = chunk.decode('utf-8', errors='replace').strip()
                            if stderr_line:
                                print(f"[Dalfox] stderr: {stderr_line}")

                    async def read_stdout():
                        nonlocal last_progress_update
                        while True:
                            chunk = await process.stdout.read(1024)
                            if not chunk:
                                break
                            stdout_chunks.append(chunk)

                            # Periodic progress update even if no findings yet
                            current_time = time.time()
                            elapsed = current_time - start_time
                            if agent and (current_time - last_progress_update) >= progress_update_interval:
                                agent.report_progress(
                                    current_operation="XSS parameter fuzzing",
                                    current_target=scan_target,
                                    items_processed=0,
                                    total_items=total_targets
                                )
                                agent.append_output(f"[Dalfox] Scanning in progress... ({int(elapsed)}s elapsed)")
                                last_progress_update = current_time

                    await asyncio.gather(read_stdout(), read_stderr())
                    await process.wait()

                await asyncio.wait_for(read_output(), timeout=DALFOX_TIMEOUT_SECONDS)

            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                # Cleanup target file
                if target_file and os.path.exists(target_file):
                    try:
                        os.remove(target_file)
                    except Exception:
                        pass

                raw_stdout = b''.join(stdout_chunks).decode('utf-8', errors='replace').replace('\0', '')
                partial_findings, observation_counts, _parsed = self._parse_dalfox_output(raw_stdout)
                partial_findings, evidence_failures = await self._attach_verified_evidence(
                    partial_findings,
                    targets if targets else [target],
                    auth_username=auth_username,
                    auth_password=auth_password,
                    auth_cookies=auth_cookies,
                    auth_headers=auth_headers,
                )
                observation_counts["evidence_capture_failed"] = evidence_failures
                print(
                    f"[Dalfox] Scan timed out after {DALFOX_TIMEOUT_SECONDS} seconds, "
                    f"returning {len(partial_findings)} partial verified findings"
                )

                # Strip heavy fields and build raw output from partial findings
                partial_stripped = self._strip_findings(partial_findings)

                raw_output_sanitized = self._build_raw_output(partial_stripped)

                total_found = len(partial_stripped)
                if len(partial_stripped) > 2000:
                    partial_stripped = partial_stripped[:2000]

                return {
                    "success": False,
                    "error": f"Dalfox XSS scan timed out after {DALFOX_TIMEOUT_SECONDS} seconds for {scan_target}",
                    "output": {
                        "findings": partial_stripped,
                        "total_findings": total_found,
                        "findings_delivered": len(partial_stripped),
                        "target": target if target else f"{len(targets)} targets",
                        "targets": targets if targets else [target],
                        "tool": "dalfox",
                        "scan_type": "xss",
                        "observation_counts": observation_counts,
                        "partial": True
                    },
                    "raw_output": raw_output_sanitized
                }

            # Cleanup target file
            if target_file and os.path.exists(target_file):
                try:
                    os.remove(target_file)
                except Exception as e:
                    print(f"[Dalfox] Warning: Could not delete target file: {e}")

            raw_stdout = b''.join(stdout_chunks).decode('utf-8', errors='replace').replace('\0', '')
            raw_stderr = b''.join(stderr_chunks).decode('utf-8', errors='replace').replace('\0', '')
            findings, observation_counts, parsed = self._parse_dalfox_output(raw_stdout)

            if process.returncode not in (0, None):
                return {
                    "success": False,
                    "error": f"Dalfox exited with status {process.returncode}",
                    "output": {
                        "findings": [],
                        "total_findings": 0,
                        "findings_delivered": 0,
                        "target": target if target else f"{len(targets)} targets",
                        "targets": targets if targets else [target],
                        "tool": "dalfox",
                        "scan_type": "xss",
                        "observation_counts": observation_counts,
                    },
                    "raw_output": raw_stderr[-4000:],
                }

            if raw_stdout.strip() and not parsed:
                return {
                    "success": False,
                    "error": "Dalfox returned malformed JSON output",
                    "output": {
                        "findings": [],
                        "total_findings": 0,
                        "findings_delivered": 0,
                        "target": target if target else f"{len(targets)} targets",
                        "targets": targets if targets else [target],
                        "tool": "dalfox",
                        "scan_type": "xss",
                        "observation_counts": observation_counts,
                    },
                    "raw_output": raw_stdout[-4000:],
                }

            print(
                f"[Dalfox] Found {len(findings)} verified XSS findings "
                f"(discarded R={observation_counts['reflected']}, G={observation_counts['grep']})"
            )

            verified_observations = len(findings)
            findings, evidence_failures = await self._attach_verified_evidence(
                findings,
                targets if targets else [target],
                auth_username=auth_username,
                auth_password=auth_password,
                auth_cookies=auth_cookies,
                auth_headers=auth_headers,
            )
            observation_counts["evidence_capture_failed"] = evidence_failures
            observation_counts["verified_observations"] = verified_observations
            observation_counts["evidence_backed_verified"] = len(findings)

            # Strip heavy fields from findings
            findings_stripped = self._strip_findings(findings)

            # Build raw output
            raw_output_sanitized = self._build_raw_output(findings_stripped)

            # Cap findings at 2000 to keep payload under 10MB
            total_found = len(findings_stripped)
            if len(findings_stripped) > 2000:
                findings_stripped = findings_stripped[:2000]
                print(f"[Dalfox] Capped findings from {total_found} to 2000 for delivery")

            # Final progress report
            if agent:
                agent.report_progress(
                    current_operation="Dalfox XSS scan completed",
                    current_target=scan_target,
                    items_processed=total_found,
                    total_items=total_found
                )

            return {
                "success": True,
                "output": {
                    "findings": findings_stripped,
                    "total_findings": total_found,
                    "findings_delivered": len(findings_stripped),
                    "target": target if target else f"{len(targets)} targets",
                    "targets": targets if targets else [target],
                    "tool": "dalfox",
                    "scan_type": "xss",
                    "observation_counts": observation_counts,
                    "verification": "dalfox-v-only"
                },
                "raw_output": raw_output_sanitized
            }
        except FileNotFoundError:
            return {
                "success": False,
                "error": "Dalfox not installed. Install with: go install github.com/hahwul/dalfox/v2@latest",
                "output": {
                    "findings": [],
                    "total_findings": 0,
                    "findings_delivered": 0,
                    "target": parameters.get("target", ""),
                    "targets": [],
                    "tool": "dalfox",
                    "scan_type": "xss"
                },
                "raw_output": ""
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Error running Dalfox: {str(e)}",
                "output": {
                    "findings": [],
                    "total_findings": 0,
                    "findings_delivered": 0,
                    "target": parameters.get("target", ""),
                    "targets": [],
                    "tool": "dalfox",
                    "scan_type": "xss"
                },
                "raw_output": ""
            }

    def _parse_dalfox_output(self, raw_output: str) -> Tuple[List[Dict[str, Any]], Dict[str, int], bool]:
        """Parse Dalfox v2.9 JSON and keep only headless-verified V PoCs.

        Dalfox v2.9 prints a JSON array whose PoC entries are comma-terminated
        on individual lines and whose final item is an empty sentinel object.
        Decoding those lines independently drops every real PoC. Wrapper JSON
        (`{"pocs": [...]}`) and JSONL are accepted for compatibility.
        """
        counts = {"verified": 0, "reflected": 0, "grep": 0, "other": 0}
        text = (raw_output or "").strip().replace('\0', '')
        if not text:
            return [], counts, True

        records: List[Dict[str, Any]] = []
        parsed = False
        try:
            document = json.loads(text)
            parsed = True
            if isinstance(document, list):
                records.extend(item for item in document if isinstance(item, dict) and item)
            elif isinstance(document, dict):
                if isinstance(document.get("pocs"), list):
                    records.extend(item for item in document["pocs"] if isinstance(item, dict) and item)
                elif document:
                    records.append(document)
        except json.JSONDecodeError:
            for line in text.splitlines():
                candidate = line.strip().rstrip(',')
                if not candidate or candidate in {'[', ']', '{}'}:
                    continue
                try:
                    item = json.loads(candidate)
                except json.JSONDecodeError:
                    continue
                if isinstance(item, dict) and item:
                    records.append(item)
                    parsed = True

        verified: List[Dict[str, Any]] = []
        for record in records:
            result_type = str(record.get("type") or "").upper()
            if result_type == "V":
                counts["verified"] += 1
                verified.append(record)
            elif result_type == "R":
                counts["reflected"] += 1
            elif result_type == "G":
                counts["grep"] += 1
            else:
                counts["other"] += 1
        return verified, counts, parsed

    def _strip_findings(self, findings: list) -> list:
        """Strip scanner-owned heavy fields while retaining bounded HTTP evidence."""
        stripped = []
        for finding in findings:
            f = dict(finding)
            # Dalfox findings are typically lightweight, but strip any large fields
            f.pop("raw_request", None)
            f.pop("raw_response", None)
            for key in ("request", "response"):
                if isinstance(f.get(key), str):
                    f[key] = f[key][:DALFOX_EVIDENCE_MAX_BYTES]
            # Sanitize null bytes
            f_str = json.dumps(f).replace('\0', '')
            stripped.append(json.loads(f_str))
        return stripped

    async def _attach_verified_evidence(
        self,
        findings: List[Dict[str, Any]],
        allowed_targets: List[Optional[str]],
        *,
        auth_username: Optional[str],
        auth_password: Optional[str],
        auth_cookies: Optional[str],
        auth_headers: List[str],
    ) -> Tuple[List[Dict[str, Any]], int]:
        """Replay bounded verified PoCs to retain reproducible HTTP evidence.

        Dalfox's JSON `V` record proves browser execution but v2.9 does not
        include the underlying HTTP exchange. The agent performs one exact,
        same-origin GET replay per delivered PoC, never follows redirects, and
        drops a PoC when a sanitized request/response pair cannot be captured.
        """

        bounded_findings = findings[:DALFOX_EVIDENCE_MAX_FINDINGS]
        omitted = max(0, len(findings) - len(bounded_findings))
        origins = {
            self._origin(str(value))
            for value in allowed_targets
            if value and self._origin(str(value))
        }
        if not bounded_findings or not origins:
            return [], len(findings)

        request_headers = {
            "User-Agent": "xASM-Dalfox-Evidence/1.0",
            "Accept": "text/html,application/xhtml+xml,application/json,text/plain,*/*",
        }
        for raw_header in auth_headers or []:
            if not isinstance(raw_header, str) or ":" not in raw_header:
                continue
            name, value = raw_header.split(":", 1)
            if name.strip() and "\r" not in name and "\n" not in name:
                request_headers[name.strip()] = value.strip()
        if auth_username and auth_password:
            encoded = base64.b64encode(f"{auth_username}:{auth_password}".encode()).decode()
            request_headers["Authorization"] = f"Basic {encoded}"
        if auth_cookies:
            request_headers["Cookie"] = auth_cookies

        secrets = [
            value
            for value in (auth_username, auth_password, auth_cookies)
            if isinstance(value, str) and value
        ]
        semaphore = asyncio.Semaphore(DALFOX_EVIDENCE_CONCURRENCY)
        timeout = aiohttp.ClientTimeout(
            total=DALFOX_EVIDENCE_TIMEOUT_SECONDS,
            connect=min(5, DALFOX_EVIDENCE_TIMEOUT_SECONDS),
        )
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async def capture(finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
                async with semaphore:
                    return await self._capture_verified_finding(
                        session,
                        finding,
                        origins,
                        [str(value) for value in allowed_targets if value],
                        request_headers,
                        secrets,
                    )

            captured = await asyncio.gather(
                *(capture(finding) for finding in bounded_findings),
                return_exceptions=True,
            )

        delivered = [item for item in captured if isinstance(item, dict)]
        failures = omitted + len(bounded_findings) - len(delivered)
        return delivered, failures

    async def _capture_verified_finding(
        self,
        session: aiohttp.ClientSession,
        finding: Dict[str, Any],
        allowed_origins: set,
        allowed_targets: List[str],
        request_headers: Dict[str, str],
        secrets: List[str],
    ) -> Optional[Dict[str, Any]]:
        poc_url = str(
            finding.get("data")
            or finding.get("poc")
            or finding.get("inject_url")
            or finding.get("url")
            or ""
        ).strip()
        parsed = urlsplit(poc_url)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
            or self._origin(poc_url) not in allowed_origins
            or str(finding.get("method") or "GET").upper() != "GET"
        ):
            return None

        try:
            async with session.get(poc_url, headers=request_headers, allow_redirects=False) as response:
                body_bytes = await self._read_limited(response.content, DALFOX_EVIDENCE_MAX_BYTES + 1)
                truncated = len(body_bytes) > DALFOX_EVIDENCE_MAX_BYTES
                body = body_bytes[:DALFOX_EVIDENCE_MAX_BYTES].decode("utf-8", errors="replace")
                parameter = self._resolve_parameter(finding, poc_url, allowed_targets)
                payload = self._resolve_payload(finding, poc_url, parameter)
                enriched = dict(finding)
                enriched["param"] = parameter
                enriched["payload"] = payload
                enriched["request"] = self._request_transcript(poc_url, request_headers, secrets)
                enriched["response"] = self._response_transcript(
                    response.status,
                    response.reason,
                    dict(response.headers),
                    body,
                    secrets,
                )
                enriched["response_status"] = response.status
                enriched["response_truncated"] = truncated
                headless_verified = (
                    "headless" in str(finding.get("inject_type") or "").lower()
                    or "found dialog" in str(finding.get("message_str") or "").lower()
                )
                enriched["dom_execution"] = headless_verified
                enriched["browser_verification"] = (
                    "dalfox-headless-dialog" if headless_verified else "dalfox-verified-poc"
                )
                enriched["evidence"] = (
                    f"Dalfox verified browser execution; bounded HTTP replay returned "
                    f"{response.status} for parameter {parameter}."
                )
                return enriched
        except Exception as exc:
            print(f"[Dalfox] Evidence replay failed for verified PoC: {type(exc).__name__}")
            return None

    @staticmethod
    async def _read_limited(stream: aiohttp.StreamReader, limit: int) -> bytes:
        chunks: List[bytes] = []
        total = 0
        while total < limit:
            chunk = await stream.read(min(16_384, limit - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        return b"".join(chunks)

    @staticmethod
    def _origin(url: str) -> str:
        try:
            parsed = urlsplit(url)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                return ""
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            return f"{parsed.scheme}://{parsed.hostname.lower()}:{port}"
        except ValueError:
            return ""

    @staticmethod
    def _resolve_parameter(
        finding: Dict[str, Any],
        poc_url: str,
        allowed_targets: List[str],
    ) -> str:
        explicit = str(finding.get("param") or finding.get("parameter") or "").strip()
        if explicit:
            return explicit[:128]
        poc = urlsplit(poc_url)
        pairs = parse_qsl(poc.query, keep_blank_values=True)
        if len(pairs) == 1:
            return pairs[0][0][:128]
        for target in allowed_targets:
            baseline = urlsplit(target)
            if DalfoxXssScanTool._origin(target) != DalfoxXssScanTool._origin(poc_url):
                continue
            if baseline.path != poc.path:
                continue
            baseline_values = dict(parse_qsl(baseline.query, keep_blank_values=True))
            for name, value in pairs:
                if name not in baseline_values or baseline_values[name] != value:
                    return name[:128]
        return "unknown"

    @staticmethod
    def _resolve_payload(finding: Dict[str, Any], poc_url: str, parameter: str) -> str:
        explicit = str(finding.get("payload") or "")
        if explicit:
            return explicit[:2_000]
        for name, value in parse_qsl(urlsplit(poc_url).query, keep_blank_values=True):
            if name == parameter:
                return value[:2_000]
        return ""

    @staticmethod
    def _sanitize_evidence(value: str, secrets: List[str]) -> str:
        text = str(value or "").replace("\0", "")
        for secret in secrets:
            if len(secret) >= 3:
                text = text.replace(secret, "[REDACTED]")
        for pattern, replacement in _SENSITIVE_TEXT_PATTERNS:
            text = pattern.sub(replacement, text)
        return text[:DALFOX_EVIDENCE_MAX_BYTES]

    @classmethod
    def _request_transcript(
        cls,
        url: str,
        headers: Dict[str, str],
        secrets: List[str],
    ) -> str:
        parsed = urlsplit(url)
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        lines = [f"GET {path} HTTP/1.1", f"Host: {parsed.netloc}"]
        for name, value in headers.items():
            rendered = "[REDACTED]" if name.lower() in _SENSITIVE_HEADER_NAMES else value
            lines.append(f"{name}: {rendered}")
        return cls._sanitize_evidence("\r\n".join(lines) + "\r\n\r\n", secrets)

    @classmethod
    def _response_transcript(
        cls,
        status: int,
        reason: Optional[str],
        headers: Dict[str, str],
        body: str,
        secrets: List[str],
    ) -> str:
        safe_reason = str(reason or "").replace("\r", "").replace("\n", "")[:100]
        lines = [f"HTTP/1.1 {status} {safe_reason}".rstrip()]
        included = {"content-type", "content-length", "cache-control", "location", "set-cookie"}
        for name, value in headers.items():
            if name.lower() not in included:
                continue
            rendered = "[REDACTED]" if name.lower() in _SENSITIVE_HEADER_NAMES else value
            lines.append(f"{name}: {rendered}")
        return cls._sanitize_evidence("\r\n".join(lines) + "\r\n\r\n" + body, secrets)

    def _build_raw_output(self, findings: list) -> str:
        """Build raw output string from findings, limited to 5MB"""
        if not findings:
            return ""
        raw_lines = [json.dumps(f) for f in findings]
        raw_output = '\n'.join(raw_lines)
        # Limit to 5MB to prevent 413 errors
        if len(raw_output) > 5 * 1024 * 1024:
            raw_output = '\n'.join(raw_lines[:1000]) + f"\n... (truncated, total {len(raw_lines)} lines)"
        return raw_output


def get_tool():
    return DalfoxXssScanTool()
