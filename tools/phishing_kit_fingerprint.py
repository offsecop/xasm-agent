"""
Phishing Kit Fingerprint Tool
Fingerprints known phishing kits on target domains by probing for kit-specific
artifacts, signature patterns, and infrastructure indicators.
"""

import json
import os
import re
import time
import asyncio
import aiohttp
import random
from plugin_interface import ToolPlugin
from typing import Dict, Any, List, Optional

USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0',
]


class PhishingKitFingerprintTool(ToolPlugin):

    @property
    def name(self) -> str:
        return "phishing_kit:fingerprint"

    @property
    def description(self) -> str:
        return (
            "Fingerprint known phishing kits on target domains by probing for "
            "kit-specific artifacts, signature patterns, and infrastructure indicators."
        )

    @property
    def schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "targets": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of domains to fingerprint"
                },
                "brandMonitorId": {
                    "type": "string",
                    "description": "Brand monitor ID"
                },
                "typosquatDomainMap": {
                    "type": "object",
                    "description": "Map of domain to typosquat domain ID"
                },
                "maxTargets": {
                    "type": "integer",
                    "default": 50,
                    "description": "Max targets to scan"
                },
                "timeout": {
                    "type": "integer",
                    "default": 10,
                    "description": "HTTP timeout per request in seconds"
                }
            },
            "required": ["targets"]
        }

    @property
    def metadata(self) -> Dict[str, Any]:
        return {
            "category": "recon",
            "phase": 2,
            "domain": ["web", "phishing"],
            "input_type": ["domain"],
            "output_type": ["phishing_kits"],
            "chainable_after": ["typosquat:detect", "brand_monitor:screenshot"],
            "chainable_before": [],
        }

    def __init__(self):
        super().__init__()
        self._signatures = None

    def _load_signatures(self):
        if self._signatures is None:
            sig_path = os.path.join(os.path.dirname(__file__), 'data', 'phishing_kit_signatures.json')
            try:
                with open(sig_path, 'r') as f:
                    self._signatures = json.load(f)
            except (FileNotFoundError, json.JSONDecodeError) as e:
                print(f"[PhishingKit] Failed to load signatures from {sig_path}: {e}")
                self._signatures = {"probePaths": [], "kits": {}, "genericIndicators": []}
        return self._signatures

    async def execute(self, parameters: Dict[str, Any]) -> Any:
        start_time = time.time()
        agent = parameters.get('_agent')

        targets = parameters.get('targets', [])
        if isinstance(targets, str):
            try:
                targets = json.loads(targets)
            except json.JSONDecodeError:
                targets = [targets]

        brand_monitor_id = parameters.get('brandMonitorId', '')
        typosquat_domain_map = parameters.get('typosquatDomainMap', {})
        if isinstance(typosquat_domain_map, str):
            try:
                typosquat_domain_map = json.loads(typosquat_domain_map)
            except json.JSONDecodeError:
                typosquat_domain_map = {}

        max_targets = int(parameters.get('maxTargets', 50))
        timeout = int(parameters.get('timeout', 10))

        targets = targets[:max_targets]
        signatures = self._load_signatures()

        if agent:
            agent.report_progress(
                current_operation=f"Fingerprinting {len(targets)} domains for phishing kits...",
                current_target=targets[0] if targets else '',
                items_processed=0,
                total_items=len(targets),
            )

        results = []
        semaphore = asyncio.Semaphore(10)

        async def probe_domain(domain):
            domain_result = {
                'domain': domain,
                'typosquatDomainId': typosquat_domain_map.get(domain),
                'kitsDetected': [],
                'unmatchedArtifacts': [],
                'overallConfidence': 0,
                'totalPathsProbed': 0,
                'totalMatches': 0,
                'error': None
            }

            try:
                probe_results = {}
                base_url = f"https://{domain}"

                async with semaphore:
                    connector = aiohttp.TCPConnector(ssl=False)
                    client_timeout = aiohttp.ClientTimeout(total=timeout)
                    async with aiohttp.ClientSession(connector=connector, timeout=client_timeout) as session:
                        # Probe all paths
                        for path in signatures.get('probePaths', []):
                            url = f"{base_url}{path}"
                            ua = random.choice(USER_AGENTS)
                            try:
                                async with session.get(url, headers={'User-Agent': ua}, allow_redirects=True, max_field_size=65536) as resp:
                                    status = resp.status
                                    body = ''
                                    if status < 400:
                                        body = await resp.text(errors='replace')
                                        body = body[:65536]  # 64KB limit
                                    headers = dict(resp.headers)
                                    probe_results[path] = {
                                        'status': status,
                                        'exists': status < 400,
                                        'body': body,
                                        'headers': headers
                                    }
                            except Exception:
                                probe_results[path] = {'status': 0, 'exists': False, 'body': '', 'headers': {}}
                            domain_result['totalPathsProbed'] += 1

                        # Also probe root path for HTML patterns
                        if '/' not in probe_results:
                            try:
                                ua = random.choice(USER_AGENTS)
                                async with session.get(base_url, headers={'User-Agent': ua}, allow_redirects=True) as resp:
                                    body = await resp.text(errors='replace')
                                    probe_results['/'] = {
                                        'status': resp.status,
                                        'exists': resp.status < 400,
                                        'body': body[:65536],
                                        'headers': dict(resp.headers)
                                    }
                            except Exception:
                                probe_results['/'] = {'status': 0, 'exists': False, 'body': '', 'headers': {}}

                # Check each kit
                for kit_name, kit_info in signatures.get('kits', {}).items():
                    kit_sigs = kit_info.get('signatures', [])
                    total_weight = sum(s['weight'] for s in kit_sigs)
                    matched_weight = 0
                    matched_sigs = []

                    for sig in kit_sigs:
                        matched = False
                        sig_type = sig['type']

                        if sig_type == 'path_exists':
                            path = sig['path']
                            if path in probe_results and probe_results[path]['exists']:
                                matched = True

                        elif sig_type == 'path_content':
                            path = sig.get('path', '/')
                            pattern = sig.get('pattern', '')
                            if path in probe_results and probe_results[path]['exists']:
                                if re.search(pattern, probe_results[path]['body'], re.IGNORECASE):
                                    matched = True

                        elif sig_type == 'html_pattern':
                            pattern = sig.get('pattern', '')
                            # Check all probed pages
                            for path, result in probe_results.items():
                                if result['exists'] and re.search(pattern, result['body'], re.IGNORECASE):
                                    matched = True
                                    break

                        elif sig_type == 'header_pattern':
                            header_name = sig.get('header', '').lower()
                            pattern = sig.get('pattern', '')
                            for path, result in probe_results.items():
                                if result['exists']:
                                    for h_name, h_value in result['headers'].items():
                                        if h_name.lower() == header_name and re.search(pattern, str(h_value), re.IGNORECASE):
                                            matched = True
                                            break
                                if matched:
                                    break

                        if matched:
                            matched_weight += sig['weight']
                            matched_sigs.append({
                                'type': sig_type,
                                'path': sig.get('path', ''),
                                'pattern': sig.get('pattern', ''),
                                'weight': sig['weight'],
                                'matched': True
                            })

                    if matched_weight > 0 and total_weight > 0:
                        confidence = round(matched_weight / total_weight * 100)
                        if confidence >= 20:  # Minimum threshold to report
                            domain_result['kitsDetected'].append({
                                'kitName': kit_name,
                                'confidence': confidence,
                                'matchCount': len(matched_sigs),
                                'totalSignatures': len(kit_sigs),
                                'matchedWeight': matched_weight,
                                'totalWeight': total_weight,
                                'matchedSignatures': matched_sigs,
                                'description': kit_info.get('description', '')
                            })

                # Check generic indicators
                for indicator in signatures.get('genericIndicators', []):
                    matched = False
                    ind_type = indicator['type']

                    if ind_type == 'path_exists':
                        path = indicator['path']
                        if path in probe_results and probe_results[path]['exists']:
                            matched = True

                    elif ind_type == 'html_pattern':
                        pattern = indicator.get('pattern', '')
                        for path, result in probe_results.items():
                            if result['exists'] and re.search(pattern, result['body'], re.IGNORECASE):
                                matched = True
                                break

                    if matched:
                        domain_result['unmatchedArtifacts'].append({
                            'name': indicator['name'],
                            'category': indicator.get('category', 'unknown'),
                            'type': ind_type,
                            'weight': indicator['weight']
                        })
                        domain_result['totalMatches'] += 1

                # Sort kits by confidence
                domain_result['kitsDetected'].sort(key=lambda k: k['confidence'], reverse=True)

                # Overall confidence = highest kit confidence
                if domain_result['kitsDetected']:
                    domain_result['overallConfidence'] = domain_result['kitsDetected'][0]['confidence']
                    domain_result['totalMatches'] += sum(k['matchCount'] for k in domain_result['kitsDetected'])

            except Exception as e:
                domain_result['error'] = str(e)

            return domain_result

        # Run all probes concurrently
        tasks = [probe_domain(domain) for domain in targets]
        results = await asyncio.gather(*tasks)

        duration = round(time.time() - start_time, 2)

        # Build summary
        kits_found = sum(1 for r in results if r['kitsDetected'])
        total_artifacts = sum(len(r['unmatchedArtifacts']) for r in results)

        if agent:
            agent.report_progress(
                current_operation=f"Fingerprinting complete: {kits_found}/{len(results)} domains with kits detected",
                current_target=targets[0] if targets else '',
                items_processed=len(results),
                total_items=len(results),
            )

        output = {
            'brandMonitorId': brand_monitor_id,
            'typosquatDomainMap': typosquat_domain_map,
            'results': results,
            'summary': {
                'totalScanned': len(results),
                'kitsDetected': kits_found,
                'totalArtifacts': total_artifacts,
                'domainsWithErrors': sum(1 for r in results if r['error'])
            },
            'tool': 'phishing_kit',
            'scan_type': 'fingerprint'
        }

        raw_output = json.dumps(output, default=str)

        if agent:
            agent.append_output(raw_output)

        return {
            'success': True,
            'output': output,
            'raw_output': raw_output,
            'execution_metrics': {
                'duration_seconds': duration,
                'targets_scanned': len(results)
            }
        }


def get_tool():
    return PhishingKitFingerprintTool()
