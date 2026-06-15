"""
DNS validation tool
Validates discovered hostnames without creating assets or DNS-to-IP relations.
"""

import asyncio
import ipaddress
import json
import random
import string
from plugin_interface import ToolPlugin
from typing import Dict, Any, List, Set


class DNSResolveValidateTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "dns:resolve_validate"

    @property
    def description(self) -> str:
        return "Validates FQDN candidates via DNS without creating assets. Returns only resolvable hostnames for safe workflow chaining."

    @property
    def schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Single FQDN to validate"
                },
                "targets": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Multiple FQDNs to validate"
                },
                "parentDomain": {
                    "type": "string",
                    "description": "Parent domain used for wildcard DNS detection"
                },
                "maxTargets": {
                    "type": "integer",
                    "description": "Maximum number of targets to validate from array (default: 200)",
                    "default": 200
                },
                "filterWildcard": {
                    "type": "boolean",
                    "description": "Filter hosts that only match the parent domain wildcard DNS response (default: true)",
                    "default": True
                },
                "timeoutSeconds": {
                    "type": "integer",
                    "description": "Per-record dig timeout in seconds (default: 8)",
                    "default": 8
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
            "category": "discovery",
            "phase": 2,
            "domain": ["dns"],
            "input_type": ["fqdn", "hostname"],
            "output_type": ["domains"],
            "chainable_after": ["subfinder:"],
            "chainable_before": ["httpx:probe", "katana:", "dirsearch:", "arjun:"],
        }

    async def execute(self, parameters: Dict[str, Any]) -> Any:
        agent = parameters.get("_agent")
        targets = self._resolve_targets(parameters)

        if not targets:
            return self._empty_result(success=True)

        max_targets = int(parameters.get("maxTargets", 200) or 200)
        if len(targets) > max_targets:
            print(f"[DNS Validate] Limiting {len(targets)} targets to {max_targets}")
            targets = targets[:max_targets]

        timeout = int(parameters.get("timeoutSeconds", 8) or 8)
        filter_wildcard = bool(parameters.get("filterWildcard", True))
        parent_domain = (parameters.get("parentDomain") or parameters.get("domain") or "").strip().lower()

        wildcard_ips: Set[str] = set()
        if filter_wildcard and parent_domain:
            wildcard_ips = await self._detect_wildcard_ips(parent_domain, timeout)
            if wildcard_ips:
                print(f"[DNS Validate] Wildcard DNS detected for {parent_domain}: {sorted(wildcard_ips)}")

        if agent:
            agent.report_progress(
                current_operation=f"Validating DNS for {len(targets)} candidate(s)",
                current_target=targets[0],
                items_processed=0,
                total_items=len(targets),
            )

        results = []
        resolved_hosts = []
        all_ips = []
        wildcard_filtered = 0
        raw_blocks = []

        for idx, target in enumerate(targets):
            hostname = self._normalize_hostname(target)
            if not hostname:
                results.append({"target": target, "resolved": False, "error": "invalid_hostname"})
                continue

            try:
                a_records, raw_a = await self._dig(hostname, "A", timeout)
                aaaa_records, raw_aaaa = await self._dig(hostname, "AAAA", timeout)
                cname_records, raw_cname = await self._dig(hostname, "CNAME", timeout)
            except FileNotFoundError:
                return {
                    "success": False,
                    "error": "dig command not found",
                    "output": {
                        "results": [],
                        "resolvedHosts": [],
                        "targets": [],
                        "domains": [],
                        "ips": [],
                        "total": 0,
                        "tool": "dig",
                        "scan_type": "dns_resolve_validate",
                    },
                    "raw_output": "",
                }

            ips = self._dedupe([record for record in a_records + aaaa_records if self._is_ip(record)])
            cnames = self._dedupe([record.rstrip(".") for record in cname_records if record])
            raw_blocks.append(f"# {hostname}\nA:\n{raw_a}\nAAAA:\n{raw_aaaa}\nCNAME:\n{raw_cname}".strip())

            wildcard_match = bool(wildcard_ips and set(ips) and set(ips).issubset(wildcard_ips))
            resolved = bool(ips)

            if resolved and wildcard_match:
                wildcard_filtered += 1
                resolved = False

            if resolved:
                resolved_hosts.append(hostname)
                all_ips.extend(ips)

            results.append({
                "target": hostname,
                "resolved": resolved,
                "ips": ips,
                "cnames": cnames,
                "wildcardFiltered": wildcard_match,
            })

            if agent:
                agent.report_progress(
                    current_operation="DNS validation",
                    current_target=hostname,
                    items_processed=idx + 1,
                    total_items=len(targets),
                )

        resolved_hosts = self._dedupe(resolved_hosts)
        all_ips = self._dedupe(all_ips)

        if agent:
            agent.report_progress(
                current_operation="DNS validation completed",
                current_target=targets[0],
                items_processed=len(targets),
                total_items=len(targets),
            )
            agent.append_output(
                f"[DNS Validate] {len(resolved_hosts)}/{len(targets)} candidates resolved"
                + (f", {wildcard_filtered} wildcard-filtered" if wildcard_filtered else "")
            )

        return {
            "success": True,
            "output": {
                "results": results,
                "resolvedHosts": resolved_hosts,
                "targets": resolved_hosts,
                "domains": resolved_hosts,
                "ips": all_ips,
                "total": len(resolved_hosts),
                "wildcardFiltered": wildcard_filtered,
                "tool": "dig",
                "scan_type": "dns_resolve_validate",
                "ingestAssets": False,
            },
            "raw_output": "\n\n".join(raw_blocks),
        }

    def _empty_result(self, success: bool = True) -> Dict[str, Any]:
        return {
            "success": success,
            "output": {
                "results": [],
                "resolvedHosts": [],
                "targets": [],
                "domains": [],
                "ips": [],
                "total": 0,
                "tool": "dig",
                "scan_type": "dns_resolve_validate",
                "ingestAssets": False,
            },
            "raw_output": "",
        }

    def _resolve_targets(self, parameters: Dict[str, Any]) -> List[str]:
        if parameters.get("targets"):
            targets_param = parameters["targets"]
            if isinstance(targets_param, str):
                try:
                    decoded = json.loads(targets_param)
                    if isinstance(decoded, list):
                        return [str(item) for item in decoded]
                    return [str(decoded)]
                except json.JSONDecodeError:
                    return [targets_param]
            if isinstance(targets_param, list):
                return [str(item) for item in targets_param]
            return [str(targets_param)]

        if parameters.get("target"):
            return [str(parameters["target"])]

        return []

    async def _detect_wildcard_ips(self, parent_domain: str, timeout: int) -> Set[str]:
        wildcard_sets = []
        for _ in range(2):
            random_label = "xasm-" + "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(16))
            candidate = f"{random_label}.{parent_domain}"
            a_records, _ = await self._dig(candidate, "A", timeout)
            aaaa_records, _ = await self._dig(candidate, "AAAA", timeout)
            ips = {record for record in a_records + aaaa_records if self._is_ip(record)}
            if ips:
                wildcard_sets.append(ips)

        if len(wildcard_sets) < 2:
            return set()

        return set.intersection(*wildcard_sets)

    async def _dig(self, target: str, record_type: str, timeout: int) -> tuple[List[str], str]:
        process = await asyncio.create_subprocess_exec(
            "dig",
            "+short",
            record_type,
            target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout, _ = await asyncio.wait_for(process.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            return [], ""

        text = stdout.decode("utf-8", errors="replace") if stdout else ""
        records = [line.strip() for line in text.splitlines() if line.strip()]
        return records, text.strip()

    def _normalize_hostname(self, value: str) -> str:
        value = (value or "").strip().lower().rstrip(".")
        if not value or " " in value or "/" in value:
            return ""
        if "." not in value:
            return ""
        return value

    def _is_ip(self, value: str) -> bool:
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    def _dedupe(self, values: List[str]) -> List[str]:
        seen = set()
        unique = []
        for value in values:
            if value and value not in seen:
                seen.add(value)
                unique.append(value)
        return unique


def get_tool():
    return DNSResolveValidateTool()
