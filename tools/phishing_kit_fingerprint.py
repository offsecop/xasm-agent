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
import uuid
import urllib.parse
from plugin_interface import ToolPlugin
from typing import Dict, Any, List, Optional

# Catch-all server detection (BUG-FIX 2026-05-18).
#
# When a target server returns 200-OK for arbitrary nonexistent paths (SPA
# catch-all routing, parking pages, default-route web servers), the original
# `path_exists` heuristic mis-fires across every kit signature in the catalog
# because every probe path "exists." A single scan against such a server
# typically scores 5-7 unrelated kits simultaneously (impossible IRL) and
# produces stored fingerprint rows whose evidence does not reflect reality.
#
# The fix is a control probe: hit a randomized, almost-certainly-nonexistent
# path BEFORE the signature loop. If the control returns < 400 AND its body
# is materially similar to the root body, the server is catch-all. We then:
#   - Suppress every `path_exists` match (the predicate is meaningless here)
#   - Differential-check `html_pattern` / `path_content` matches: require the
#     pattern to be present in the path body AND absent from the control body
#     (otherwise the pattern is generic SPA shell content, not kit evidence)
#
# Tuning constants:
#  - CATCH_ALL_BODY_TOLERANCE: max relative size delta vs root body to still
#    call it catch-all. 5% allows for trivial route-dependent variance
#    (canonical link, document title) while flagging the >95% identical case
#    that defeats path_exists.
CATCH_ALL_BODY_TOLERANCE = 0.05


def _mask_url_echoes(body: str, path: str) -> str:
    """Strip occurrences of the probed path (and its url-encoded forms) from
    the body before pattern matching.

    SPAs — especially Next.js / Remix / similar React-hydration frameworks —
    embed the request URL inside the response body (canonical links,
    hydration JSON payloads, breadcrumbs, OG tags). When a kit-fingerprint
    `html_pattern` signature happens to overlap with a URL path segment
    (e.g. the Caffeine kit's pattern `caffeine|CAFFEINE` overlaps with its
    own probed path `/caffeine/`), the regex matches the URL echo, not real
    kit content. That's a structural false positive — confirmed in the wild
    on `app-291.preview.questra.ai` (2026-05-18).

    By masking URL-shaped occurrences of `path` from `body` before the regex
    search, we require the pattern to appear in non-URL content. This is a
    minimum bar — a kit that genuinely embeds its name in body text (most do)
    still matches; a catch-all server only echoing the URL does not.
    """
    if not path or path == '/':
        return body
    stripped = path.strip('/')
    forms = {
        path,
        stripped,
        urllib.parse.quote(path, safe=''),
        urllib.parse.quote(stripped, safe=''),
        # URL-encoded with %2F slashes (the form Next.js typically uses)
        path.replace('/', '%2F'),
        path.replace('/', '%2f'),
    }
    out = body
    for form in forms:
        if form:
            out = out.replace(form, ' ')
    return out


def _is_catch_all(control: Dict[str, Any], root: Dict[str, Any]) -> bool:
    """True when the control probe and root probe look indistinguishable —
    i.e., the server returns the same shell for arbitrary unknown paths."""
    if not control.get('exists'):
        return False
    if not root.get('exists'):
        return False
    control_len = len(control.get('body') or '')
    root_len = len(root.get('body') or '')
    if root_len == 0:
        # Both empty → either catch-all returning empty 200, or both legitimately
        # empty. Treat as catch-all to be conservative; signatures matching
        # empty content aren't useful evidence either way.
        return control_len == 0
    delta = abs(control_len - root_len) / root_len
    return delta < CATCH_ALL_BODY_TOLERANCE

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
                'error': None,
                # BUG-FIX 2026-05-18 — surface server-shape signal so the
                # ingestion service can store it on the fingerprint row
                # (scanMetadata.isCatchAllServer). Defaults to False;
                # flipped when the control probe says otherwise.
                'isCatchAllServer': False,
                'metadata': {
                    'isCatchAllServer': False,
                    'controlProbeStatus': None,
                    'controlProbeBodyLen': None,
                    'suppressedPathExistsMatches': 0,
                    'suppressedHtmlPatternMatches': 0,
                },
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

                        # BUG-FIX 2026-05-18 — Control probe.
                        #
                        # Hit a UUID-randomized path that no legitimate kit or
                        # SPA route would ever serve. If the server returns
                        # < 400 with content close in size to the root body,
                        # we're hitting a catch-all and every `path_exists`
                        # signature in the catalog will mis-match. We suppress
                        # path_exists matches and run a differential check on
                        # html_pattern matches.
                        control_path = f"/__nonexistent-{uuid.uuid4().hex}__/"
                        control_url = f"{base_url}{control_path}"
                        control_result = {'status': 0, 'exists': False, 'body': '', 'headers': {}}
                        try:
                            ua = random.choice(USER_AGENTS)
                            async with session.get(control_url, headers={'User-Agent': ua}, allow_redirects=True) as resp:
                                control_body = ''
                                if resp.status < 400:
                                    control_body = await resp.text(errors='replace')
                                    control_body = control_body[:65536]
                                control_result = {
                                    'status': resp.status,
                                    'exists': resp.status < 400,
                                    'body': control_body,
                                    'headers': dict(resp.headers),
                                }
                        except Exception:
                            # Control probe failed → assume not catch-all
                            # (network error doesn't tell us about server shape).
                            pass

                        is_catch_all = _is_catch_all(control_result, probe_results.get('/', {}))
                        domain_result['isCatchAllServer'] = is_catch_all
                        domain_result['metadata']['isCatchAllServer'] = is_catch_all
                        domain_result['metadata']['controlProbeStatus'] = control_result['status']
                        domain_result['metadata']['controlProbeBodyLen'] = len(control_result['body'])

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
                                # BUG-FIX 2026-05-18 — suppress when the server
                                # returns 200 for arbitrary paths (the predicate
                                # has no information content on catch-all servers).
                                if domain_result['isCatchAllServer']:
                                    domain_result['metadata']['suppressedPathExistsMatches'] += 1
                                else:
                                    matched = True

                        elif sig_type == 'path_content':
                            path = sig.get('path', '/')
                            pattern = sig.get('pattern', '')
                            if path in probe_results and probe_results[path]['exists']:
                                # Mask URL-echoes first (see _mask_url_echoes
                                # docstring) so we don't credit a match that's
                                # just the request URL being reflected in the
                                # response body.
                                masked = _mask_url_echoes(probe_results[path]['body'], path)
                                if re.search(pattern, masked, re.IGNORECASE):
                                    # Differential check on catch-all servers:
                                    # the pattern must not also be in the
                                    # (masked) control body.
                                    if domain_result['isCatchAllServer']:
                                        masked_control = _mask_url_echoes(
                                            control_result['body'], control_path
                                        )
                                        if re.search(pattern, masked_control, re.IGNORECASE):
                                            domain_result['metadata']['suppressedHtmlPatternMatches'] += 1
                                            continue
                                    matched = True
                                elif re.search(pattern, probe_results[path]['body'], re.IGNORECASE):
                                    # Unmasked body matched but masked didn't —
                                    # the entire match was a URL echo.
                                    domain_result['metadata']['suppressedHtmlPatternMatches'] += 1

                        elif sig_type == 'html_pattern':
                            pattern = sig.get('pattern', '')
                            # Check all probed pages, with URL-echo masking.
                            for path, result in probe_results.items():
                                if not result['exists']:
                                    continue
                                masked = _mask_url_echoes(result['body'], path)
                                if re.search(pattern, masked, re.IGNORECASE):
                                    if domain_result['isCatchAllServer']:
                                        masked_control = _mask_url_echoes(
                                            control_result['body'], control_path
                                        )
                                        if re.search(pattern, masked_control, re.IGNORECASE):
                                            domain_result['metadata']['suppressedHtmlPatternMatches'] += 1
                                            continue
                                    matched = True
                                    break
                                elif re.search(pattern, result['body'], re.IGNORECASE):
                                    # Pattern was only in the URL echo, not real body.
                                    domain_result['metadata']['suppressedHtmlPatternMatches'] += 1

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
                            # BUG-FIX 2026-05-18 — same catch-all suppression
                            # as the kit-signature loop above. Generic indicators
                            # are even more prone to catch-all noise.
                            if domain_result['isCatchAllServer']:
                                domain_result['metadata']['suppressedPathExistsMatches'] += 1
                            else:
                                matched = True

                    elif ind_type == 'html_pattern':
                        pattern = indicator.get('pattern', '')
                        for path, result in probe_results.items():
                            if not result['exists']:
                                continue
                            masked = _mask_url_echoes(result['body'], path)
                            if re.search(pattern, masked, re.IGNORECASE):
                                if domain_result['isCatchAllServer']:
                                    masked_control = _mask_url_echoes(
                                        control_result['body'], control_path
                                    )
                                    if re.search(pattern, masked_control, re.IGNORECASE):
                                        domain_result['metadata']['suppressedHtmlPatternMatches'] += 1
                                        continue
                                matched = True
                                break
                            elif re.search(pattern, result['body'], re.IGNORECASE):
                                domain_result['metadata']['suppressedHtmlPatternMatches'] += 1

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
