"""
httpx Technology Detection Tool

Focused variant of httpx that emphasises technology fingerprinting and web-stack
identification. The passive layer runs the ``httpx`` binary with ``-tech-detect``
(Wappalyzer signatures on the root URL). On top of that, the **#320 product
fingerprint pack** actively probes product-distinctive paths/headers/cookies for
three recent web products that Wappalyzer and the shipped nuclei tech-detect
templates do NOT identify:

  * **Cacti** monitoring console (login signature / ``Cacti`` cookie)
  * **Pterodactyl** game-server panel (``pterodactyl_session`` cookie / title)
  * **Camaleon CMS** on Ruby on Rails (``_camaleon_session`` cookie + ``X-Runtime``)

Each detected product is appended to the host's technology list AND emitted as a
Nuclei-shaped INFO finding so it reuses the standard ingestion
``processNucleiOutput`` dedup/persistence pipeline (ingestion signature
``TECH_FINGERPRINT``). The value is a cheap, early "what product is this" tag
that gates version-aware recent-CVE/tool selection (epic #315 / issue #321).

DELIBERATE COMPLEMENT — what this pack does NOT do (anti-duplication, GATE A):
  * **Apache NiFi**, **Mirth Connect** and **MCPJam Inspector** are intentionally
    NOT fingerprinted here — they already ship as nuclei tech-detect templates
    (``http/technologies/{nifi-detech,mirth-connect-detect,mcp-inspector-detect}.yaml``)
    that emit findings. Re-detecting them would double-report. They are owned by
    ``nuclei:full_scan`` / ``nuclei:web_scan``.

FP-safety: a negative-control path is fetched first; any product body/title
signal whose response is byte-identical to the catch-all (SPA 200) is voided, and
at least one *strong* (product-specific) signal is required before a product is
reported. Cookie names are recorded but cookie VALUES are never emitted.
"""

import asyncio
import hashlib
import json
import os
import re
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import aiohttp

from plugin_interface import ToolPlugin
from tools._agentic_exploration_common import (
    dedupe_keep_order,
    parse_headers,
    read_limited,
)


# --- #320 product-fingerprint pack -------------------------------------------
# Declarative signatures for the THREE net-new products (Cacti / Pterodactyl /
# Camaleon). NiFi / Mirth / MCPJam are deliberately absent (owned by nuclei).
# Signal strength: 'strong' = product-specific (confirms on its own); 'weak' =
# corroborating only (e.g. a generic Rails X-Runtime header). A product is
# reported only when >= 1 'strong' signal fires.
#   header_signals: (name_regex, value_regex, strength)
#   cookie_signals: (cookie_name_regex, strength)
#   body_signals / title_signals: (regex, strength)
#   json_signals:   (regex, strength)  -- only checked on JSON responses
NEGATIVE_CONTROL_PATH = "/xasm-fingerprint-negative-control-9z9z"

FINGERPRINT_SPECS: List[Dict[str, Any]] = [
    {
        "product": "Cacti",
        "template_id": "xasm-tech-fingerprint-cacti",
        "display_name": "Cacti Detected (Tech Fingerprint)",
        "probe_paths": ["/cacti/index.php", "/cacti/", "/cacti/auth_login.php", "/index.php"],
        "header_signals": [],
        "cookie_signals": [(r"^Cacti(?:Session|DateTime)?$", "strong")],
        "title_signals": [(r"\bCacti\b", "strong")],
        "body_signals": [
            (r"cactiLoginLogo|auth_login\.php|Login to Cacti|cacti_version", "strong"),
            (r"\bCacti\b", "weak"),
        ],
        "json_signals": [],
        "version_regex": r"(?:Cacti[^0-9]{0,40})?[Vv]ersion[^0-9]{0,4}(\d+\.\d+\.\d+)",
        "gates": "Cacti recent-CVE pack — CVE-2022-46169 / CVE-2023-39361 (remote_agent.php command-injection / SQLi)",
        "remediation": "Upgrade Cacti to the latest release, require authentication for poller endpoints, and restrict access to remote_agent.php.",
        "description": (
            "Active fingerprint identified a Cacti monitoring console via a path/body/cookie "
            "signature. Surfaces the product so the Cacti recent-CVE nuclei pack and commix "
            "remote_agent.php payloads can be selected version-aware."
        ),
    },
    {
        "product": "Pterodactyl",
        "template_id": "xasm-tech-fingerprint-pterodactyl",
        "display_name": "Pterodactyl Panel Detected (Tech Fingerprint)",
        "probe_paths": ["/api/application", "/api/client", "/auth/login", "/"],
        "header_signals": [],
        "cookie_signals": [(r"^pterodactyl_session$", "strong")],
        "title_signals": [(r"Pterodactyl", "strong")],
        "body_signals": [(r"Pterodactyl", "strong")],
        "json_signals": [(r'"errors"\s*:\s*\[', "weak")],
        "version_regex": None,
        "gates": "Pterodactyl path-traversal pack — CVE-2025-49132 (files/contents arbitrary read) + PEAR LFI->RCE chain",
        "remediation": "Upgrade the Pterodactyl panel to a patched release and restrict the file-management API (files/contents).",
        "description": (
            "Active fingerprint identified a Pterodactyl game-server panel via the "
            "pterodactyl_session cookie / title. Gates selection of the CVE-2025-49132 "
            "path-traversal template and the PEAR LFI->RCE chain."
        ),
    },
    {
        "product": "Camaleon CMS",
        "template_id": "xasm-tech-fingerprint-camaleon",
        "display_name": "Camaleon CMS (Ruby on Rails) Detected (Tech Fingerprint)",
        "probe_paths": ["/", "/admin", "/admin/login"],
        "header_signals": [(r"^X-Runtime$", r".+", "weak"), (r"^X-Request-Id$", r".+", "weak")],
        "cookie_signals": [(r"^_camaleon_session$", "strong")],
        "title_signals": [(r"[Cc]amaleon", "strong")],
        "body_signals": [(r"[Cc]amaleon", "strong")],
        "json_signals": [],
        "version_regex": None,
        "gates": "Camaleon abuse pack — role-field IDOR/mass-assignment + download_private_file traversal + cloud-settings secret scan",
        "remediation": "Upgrade Camaleon CMS, enforce object/property-level authorization on the admin user-update flow, and constrain media download paths.",
        "description": (
            "Active fingerprint identified a Camaleon CMS (Ruby on Rails) instance via the "
            "_camaleon_session cookie corroborated by the Rails X-Runtime header. Gates "
            "role-field IDOR, download_private_file traversal, and cloud-settings secret checks."
        ),
    },
]


class HttpxTechDetectTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "httpx:tech_detect"

    @property
    def description(self) -> str:
        return "Technology detection - fingerprints web technology stacks (httpx/Wappalyzer) plus an active product-fingerprint pack for Cacti, Pterodactyl and Camaleon CMS that drives recent-CVE template/tool selection"

    @property
    def schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Single URL or host to scan (e.g., 'example.com' or 'http://example.com')"
                },
                "targets": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Multiple URLs/hosts to scan (alternative to target)"
                },
                "maxTargets": {
                    "type": "integer",
                    "description": "Maximum number of targets to scan (default: 100)",
                    "default": 100
                },
                "fingerprintPack": {
                    "type": "boolean",
                    "description": "Run the active product-fingerprint pack (Cacti/Pterodactyl/Camaleon) in addition to passive httpx tech-detect (default: true)",
                    "default": True
                },
                "fingerprintMaxOrigins": {
                    "type": "integer",
                    "description": "Maximum responding origins to fingerprint actively (default: 8)",
                    "default": 8
                },
                "fingerprintTimeoutSeconds": {
                    "type": "integer",
                    "description": "Per-request timeout for the active fingerprint probes (default: 15)",
                    "default": 15
                },
                "headers": {
                    "type": "object",
                    "description": "Extra request headers for the fingerprint probes (e.g. auth headers for gated panels)"
                },
                "cookie": {
                    "type": "string",
                    "description": "Cookie header value for fingerprint probes against authenticated panels"
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
            "category": "enrichment",
            "phase": 2,
            "domain": ["web"],
            "input_type": ["url"],
            "output_type": ["findings"],
            "chainable_after": ["httpx:probe", "katana:"],
            "chainable_before": ["nuclei:"],
        }

    async def execute(self, parameters: Dict[str, Any]) -> Any:
        agent = parameters.get("_agent")
        job_id = parameters.get("_job_id", "unknown")

        # Resolve targets
        targets_list = []
        if "targets" in parameters and parameters["targets"]:
            targets_param = parameters["targets"]
            if isinstance(targets_param, str):
                try:
                    targets_list = json.loads(targets_param)
                except json.JSONDecodeError:
                    targets_list = [targets_param]
            elif isinstance(targets_param, list):
                targets_list = targets_param
            else:
                targets_list = [str(targets_param)]
        elif "target" in parameters and parameters["target"]:
            targets_list = [parameters["target"]]

        if not targets_list:
            return {
                "success": False,
                "error": "Either 'target' or 'targets' parameter is required",
                "output": {
                    "results": [],
                    "total": 0,
                    "tool": "httpx",
                    "scan_type": "tech_detect"
                },
                "raw_output": ""
            }

        # Apply maxTargets limit
        max_targets = parameters.get("maxTargets", 100)
        if len(targets_list) > max_targets:
            print(f"[httpx:tech] Limiting {len(targets_list)} targets to {max_targets}")
            targets_list = targets_list[:max_targets]

        total_targets = len(targets_list)
        scan_label = targets_list[0] if total_targets == 1 else f"{total_targets} targets"
        print(f"[httpx:tech] Technology detection on {scan_label}")

        start_time = time.time()

        if agent:
            agent.report_progress(
                current_operation="Starting technology detection",
                current_target=scan_label,
                items_processed=0,
                total_items=total_targets
            )
            agent.append_output(f"[httpx:tech] Scanning {scan_label} for technology stack...")

        # Build command with tech-focused flags
        cmd = [
            "httpx",
            "-json",
            "-silent",
            "-tech-detect",
            "-status-code",
            "-title",
            "-web-server",
            "-content-type",
            "-content-length",
            "-no-color",
            "-follow-redirects"
        ]

        # Handle single vs multiple targets
        target_file = None
        if total_targets == 1:
            cmd.extend(["-u", targets_list[0]])
        else:
            target_file = f"/tmp/httpx_tech_{job_id}_{int(time.time())}.txt"
            with open(target_file, "w") as f:
                f.write("\n".join(targets_list))
            cmd.extend(["-l", target_file])

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=300  # 5 minutes
                )
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                print("[httpx:tech] Timeout after 5 minutes")
                if agent:
                    agent.append_output("[httpx:tech] Scan timed out after 5 minutes")
                return {
                    "success": False,
                    "error": "httpx tech detection timed out after 5 minutes",
                    "output": {
                        "results": [],
                        "total": 0,
                        "tool": "httpx",
                        "scan_type": "tech_detect"
                    },
                    "raw_output": ""
                }

            stdout_text = stdout.decode("utf-8", errors="replace").replace("\0", "") if stdout else ""
            stderr_text = stderr.decode("utf-8", errors="replace").replace("\0", "") if stderr else ""

            elapsed = time.time() - start_time
            print(f"[httpx:tech] Completed in {elapsed:.1f}s (rc: {process.returncode})")

            if process.returncode != 0:
                if not stdout_text:
                    return {
                        "success": False,
                        "error": stderr_text or f"httpx tech detection failed with exit code {process.returncode}",
                        "output": {
                            "results": [],
                            "total": 0,
                            "tool": "httpx",
                            "scan_type": "tech_detect"
                        },
                        "raw_output": stderr_text
                    }
                else:
                    print(f"[httpx:tech] Warning: httpx exited with code {process.returncode} but produced output, parsing results")

            # Parse JSON output
            results = []
            tech_summary = {}  # Aggregate technology counts

            for line in stdout_text.strip().split("\n"):
                if not line.strip():
                    continue
                try:
                    data = json.loads(line.replace("\0", ""))
                    techs = data.get("tech", [])

                    result = {
                        "url": data.get("url", ""),
                        "host": data.get("host", ""),
                        "port": data.get("port", ""),
                        "status_code": data.get("status_code"),
                        "title": data.get("title", ""),
                        "webserver": data.get("webserver", ""),
                        "technologies": techs,
                        "content_type": data.get("content_type", ""),
                    }

                    if data.get("scheme"):
                        result["scheme"] = data["scheme"]

                    results.append(result)

                    # Aggregate tech counts
                    for tech in techs:
                        tech_summary[tech] = tech_summary.get(tech, 0) + 1

                except json.JSONDecodeError:
                    pass

            print(f"[httpx:tech] Detected technologies on {len(results)} hosts")

            # --- #320 active product-fingerprint pack -------------------------
            fingerprints: List[Dict[str, Any]] = []
            findings: List[Dict[str, Any]] = []
            if parameters.get("fingerprintPack", True) and results:
                try:
                    fingerprints, findings = await self._run_fingerprint_pack(
                        results, parameters, agent
                    )
                    # Fold detected products into tech_summary so the passive
                    # banner enrichment reflects them too.
                    for fp in fingerprints:
                        product = fp.get("product")
                        if product:
                            tech_summary[product] = tech_summary.get(product, 0) + 1
                except Exception as fp_err:  # never let fingerprinting fail the tool
                    print(f"[httpx:tech] fingerprint pack error: {fp_err}")

            if agent:
                agent.report_progress(
                    current_operation="Technology detection complete",
                    current_target=scan_label,
                    items_processed=total_targets,
                    total_items=total_targets
                )
                agent.append_output(
                    f"[httpx:tech] Scanned {total_targets} targets, {len(results)} responded"
                )
                if tech_summary:
                    top_techs = sorted(tech_summary.items(), key=lambda x: x[1], reverse=True)[:10]
                    tech_str = ", ".join(f"{t}({c})" for t, c in top_techs)
                    agent.append_output(f"[httpx:tech] Top technologies: {tech_str}")
                if findings:
                    products = ", ".join(sorted({fp.get("product", "?") for fp in fingerprints}))
                    agent.append_output(f"[httpx:tech] Product fingerprints: {products}")

            raw_output = stdout_text
            if len(raw_output) > 5 * 1024 * 1024:
                lines = raw_output.split("\n")
                raw_output = "\n".join(lines[:1000]) + f"\n... (truncated, total {len(lines)} lines)"

            # Build urls array for workflow chaining
            urls = [r['url'] for r in results if r.get('url')]

            return {
                "success": True,
                # Top-level `findings` so ingestion routes the product fingerprints
                # through processNucleiOutput (TECH_FINGERPRINT signature).
                "findings": findings,
                "output": {
                    "results": results,
                    "urls": urls,  # Flat URL array for workflow chaining
                    "targets": urls,  # Alias for tools expecting 'targets'
                    "total": len(results),
                    "tech_summary": tech_summary,
                    "fingerprints": fingerprints,
                    "findings": findings,
                    "tool": "httpx",
                    "scan_type": "tech_detect"
                },
                "raw_output": raw_output
            }

        except FileNotFoundError:
            return {
                "success": False,
                "error": "httpx is not installed or not in PATH",
                "output": {
                    "results": [],
                    "total": 0,
                    "tool": "httpx",
                    "scan_type": "tech_detect"
                },
                "raw_output": ""
            }
        except Exception as e:
            print(f"[httpx:tech] Error: {e}")
            return {
                "success": False,
                "error": str(e),
                "output": {
                    "results": [],
                    "total": 0,
                    "tool": "httpx",
                    "scan_type": "tech_detect"
                },
                "raw_output": ""
            }
        finally:
            if target_file and os.path.exists(target_file):
                try:
                    os.remove(target_file)
                except Exception:
                    pass

    # ------------------------------------------------------------------ #320 #
    async def _run_fingerprint_pack(
        self,
        results: List[Dict[str, Any]],
        parameters: Dict[str, Any],
        agent: Any,
    ) -> "tuple[List[Dict[str, Any]], List[Dict[str, Any]]]":
        """Actively fingerprint Cacti/Pterodactyl/Camaleon on each responding origin.

        Returns (fingerprints, findings). Each detected product mutates the
        matching ``result['technologies']`` in place and yields a Nuclei-shaped
        INFO finding routed through ingestion ``processNucleiOutput``.
        """
        max_origins = max(1, min(int(parameters.get("fingerprintMaxOrigins") or 8), 50))
        timeout_seconds = max(3, min(int(parameters.get("fingerprintTimeoutSeconds") or 15), 60))
        headers = parse_headers(parameters)

        # Map origin -> the first result carrying it (to enrich technologies).
        origin_to_result: Dict[str, Dict[str, Any]] = {}
        for result in results:
            origin = self._result_origin(result)
            if origin and origin not in origin_to_result:
                origin_to_result[origin] = result
            if len(origin_to_result) >= max_origins:
                break

        fingerprints: List[Dict[str, Any]] = []
        findings: List[Dict[str, Any]] = []

        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=timeout_seconds),
        ) as session:
            for origin, result in origin_to_result.items():
                if agent:
                    agent.report_progress("Fingerprinting products", origin, 0, 1)
                products = await self._fingerprint_origin(session, origin, headers)
                for match in products:
                    spec = match["spec"]
                    product = spec["product"]
                    # Enrich the passive tech list (drives banner enrichment for
                    # ALL detected products, including via processHttpxOutput).
                    techs = result.setdefault("technologies", [])
                    if product not in techs:
                        techs.append(product)
                    fingerprints.append(
                        {
                            "product": product,
                            "version": match.get("version"),
                            "matchedAt": match["matched_at"],
                            "confidence": match["confidence"],
                            "signals": match["signals"],
                        }
                    )
                    findings.append(self._finding_for_match(spec, match))

        return fingerprints, findings

    async def _fingerprint_origin(
        self,
        session: aiohttp.ClientSession,
        origin: str,
        headers: Dict[str, str],
    ) -> List[Dict[str, Any]]:
        # Collect the union of probe paths + the negative control, fetch once.
        paths = [NEGATIVE_CONTROL_PATH]
        for spec in FINGERPRINT_SPECS:
            paths.extend(spec["probe_paths"])
        paths = dedupe_keep_order(paths, 32)

        probes: Dict[str, Dict[str, Any]] = {}
        for path in paths:
            probes[path] = await self._fp_fetch(session, origin.rstrip("/") + path, headers)

        neg = probes.get(NEGATIVE_CONTROL_PATH) or {}
        neg_body_hash = neg.get("body_hash")

        matches: List[Dict[str, Any]] = []
        for spec in FINGERPRINT_SPECS:
            match = self._evaluate_product(spec, origin, probes, neg_body_hash)
            if match:
                matches.append(match)
        return matches

    async def _fp_fetch(
        self,
        session: aiohttp.ClientSession,
        url: str,
        headers: Dict[str, str],
        max_bytes: int = 200_000,
    ) -> Dict[str, Any]:
        try:
            async with session.get(url, headers=headers, allow_redirects=False) as response:
                body = await read_limited(response.content, max_bytes + 1)
                body = body[:max_bytes]
                text = body.decode("utf-8", errors="replace").replace("\0", "")
                cookies: List[str] = []
                for set_cookie in response.headers.getall("Set-Cookie", []):
                    name = set_cookie.split("=", 1)[0].strip()
                    if name:
                        cookies.append(name)
                title_match = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
                title = re.sub(r"\s+", " ", title_match.group(1)).strip() if title_match else ""
                return {
                    "status": response.status,
                    "headers": {k: v for k, v in response.headers.items()},
                    "cookies": cookies,
                    "title": title,
                    "body": text,
                    "body_hash": hashlib.sha256(body).hexdigest(),
                }
        except Exception as exc:
            return {
                "status": None,
                "headers": {},
                "cookies": [],
                "title": "",
                "body": "",
                "body_hash": None,
                "error": str(exc)[:200],
            }

    def _evaluate_product(
        self,
        spec: Dict[str, Any],
        origin: str,
        probes: Dict[str, Dict[str, Any]],
        neg_body_hash: Optional[str],
    ) -> Optional[Dict[str, Any]]:
        signals: List[Dict[str, Any]] = []
        strong = 0
        version: Optional[str] = None
        strong_path: Optional[str] = None

        for path in spec["probe_paths"]:
            resp = probes.get(path)
            if not resp or resp.get("status") is None:
                continue
            is_catchall = bool(
                resp.get("body_hash") and neg_body_hash and resp["body_hash"] == neg_body_hash
            )

            # Header signals (e.g. Rails X-Runtime). Catch-all does not void these.
            for name_re, value_re, strength in spec.get("header_signals", []):
                for hk, hv in resp["headers"].items():
                    if re.match(name_re, hk, re.I) and re.search(value_re, str(hv or ""), re.I):
                        signals.append({"type": "header", "path": path, "name": hk, "strength": strength})
                        if strength == "strong":
                            strong += 1
                            strong_path = strong_path or path
                        break

            # Cookie-name signals (product-specific session cookies). A cookie
            # that the app sets globally is a real signal, so it is NOT voided by
            # appearing on the negative control.
            for cookie_re, strength in spec.get("cookie_signals", []):
                for cname in resp["cookies"]:
                    if re.match(cookie_re, cname, re.I):
                        signals.append({"type": "cookie", "path": path, "name": cname, "strength": strength})
                        if strength == "strong":
                            strong += 1
                            strong_path = strong_path or path
                        break

            # Body / title / JSON signals are content-derived. Only a SUCCESS
            # response (2xx/3xx) is content-scanned: a 4xx page commonly ECHOES
            # the requested path (e.g. Express/NestJS "Cannot GET /cacti/
            # auth_login.php"), which would otherwise self-trigger a path-derived
            # body signal on any server. Also voided when the response is the
            # catch-all (SPA 200) page identical to the negative control.
            if not is_catchall and 200 <= resp.get("status", 0) < 400:
                title = resp.get("title") or ""
                for title_re, strength in spec.get("title_signals", []):
                    if title and re.search(title_re, title):
                        signals.append({"type": "title", "path": path, "value": title[:80], "strength": strength})
                        if strength == "strong":
                            strong += 1
                            strong_path = strong_path or path
                        break
                body = resp.get("body") or ""
                for body_re, strength in spec.get("body_signals", []):
                    if re.search(body_re, body):
                        signals.append({"type": "body", "path": path, "strength": strength})
                        if strength == "strong":
                            strong += 1
                            strong_path = strong_path or path
                        break
                ctype = str(resp["headers"].get("Content-Type") or "").lower()
                if "json" in ctype:
                    for json_re, strength in spec.get("json_signals", []) or []:
                        if re.search(json_re, body):
                            signals.append({"type": "json", "path": path, "strength": strength})
                            if strength == "strong":
                                strong += 1
                                strong_path = strong_path or path
                            break
                if spec.get("version_regex") and version is None:
                    vm = re.search(spec["version_regex"], body)
                    if vm:
                        version = vm.group(1)

        if strong < 1:
            return None

        matched_path = strong_path or spec["probe_paths"][0]
        matched_at = origin.rstrip("/") + matched_path
        weak = len([s for s in signals if s.get("strength") == "weak"])
        # Bounded confidence: 1 strong = 0.8, +0.1 per extra strong, +0.03 per weak.
        confidence = min(0.99, 0.8 + 0.1 * (strong - 1) + 0.03 * weak)
        return {
            "spec": spec,
            "version": version,
            "matched_at": matched_at,
            "matched_path": matched_path,
            "signals": signals,
            "confidence": round(confidence, 2),
        }

    def _finding_for_match(self, spec: Dict[str, Any], match: Dict[str, Any]) -> Dict[str, Any]:
        url = match["matched_at"]
        version = match.get("version")
        extracted = [
            f"product:{spec['product']}",
            *([f"version:{version}"] if version else []),
            *[
                f"{s['type']}:{s.get('name') or s.get('value') or s['strength']}"
                for s in match["signals"]
            ],
            f"gates:{spec['gates']}",
            f"confidence:{match['confidence']}",
        ]
        name = spec["display_name"]
        if version:
            name = f"{spec['product']} {version} Detected (Tech Fingerprint)"
        parsed = urlparse(url)
        request = f"GET {parsed.path or '/'} HTTP/1.1\r\nHost: {parsed.netloc}\r\n\r\n"
        response = (
            f"HTTP fingerprint match for {spec['product']} via "
            f"{', '.join(sorted({s['type'] for s in match['signals']}))} signal(s)"
        )
        return {
            "template-id": spec["template_id"],
            "templateID": spec["template_id"],
            "matched-at": url,
            "matched": url,
            "host": url,
            "matcher-name": f"{spec['product'].lower().split()[0]}-fingerprint",
            "extracted-results": [item for item in extracted if item],
            "info": {
                "name": name,
                "severity": "info",
                "description": spec["description"],
                "remediation": spec["remediation"],
                "tags": "tech,fingerprint",
            },
            "request": request,
            "response": response,
        }

    def _result_origin(self, result: Dict[str, Any]) -> Optional[str]:
        url = str(result.get("url") or "").strip()
        if url:
            parsed = urlparse(url)
            if parsed.scheme in ("http", "https") and parsed.netloc:
                return f"{parsed.scheme}://{parsed.netloc}"
        host = str(result.get("host") or "").strip()
        if not host:
            return None
        scheme = str(result.get("scheme") or "http")
        port = str(result.get("port") or "").strip()
        netloc = host
        if port and not (
            (scheme == "http" and port == "80") or (scheme == "https" and port == "443")
        ):
            netloc = f"{host}:{port}"
        return f"{scheme}://{netloc}"


def get_tool():
    return HttpxTechDetectTool()
