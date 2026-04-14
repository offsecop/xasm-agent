"""
Dark Web Monitor Tool
Queries OSINT sources and threat intelligence feeds for dark web mentions,
credential leaks, phishing kit sales, and brand targeting discussions.
"""

import asyncio
import aiohttp
import json
import os
import time
import hashlib
from typing import Dict, Any, List, Optional
from pathlib import Path
from plugin_interface import ToolPlugin


class DarkWebMonitorTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "darkweb:monitor"

    @property
    def description(self) -> str:
        return "Monitor dark web sources, paste sites, and threat intelligence feeds for brand mentions, credential leaks, phishing kit sales, and targeting discussions"

    @property
    def schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "Target domain to monitor (e.g., example.com)"
                },
                "keywords": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Additional keywords to search for"
                },
                "brandMonitorId": {
                    "type": "string",
                    "description": "Brand monitor ID for result correlation"
                },
                "sources": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Sources to query (default: all). Options: urlhaus, otx, github, leakcheck, threatfox, hibp, intelx, simulation"
                },
                "maxResults": {
                    "type": "integer",
                    "description": "Maximum results to return (default: 100)"
                }
            },
            "required": ["domain"]
        }

    @property
    def metadata(self) -> Dict[str, Any]:
        return {
            "category": "recon",
            "phase": 1,
            "domain": ["osint", "darkweb"],
            "input_type": ["domain"],
            "output_type": ["darkweb_mentions"],
            "chainable_after": ["typosquat:detect"],
            "chainable_before": [],
        }

    async def execute(self, parameters: Dict[str, Any]) -> Any:
        agent = parameters.get('_agent')
        domain = parameters.get('domain', '')
        keywords = parameters.get('keywords', [])
        brand_monitor_id = parameters.get('brandMonitorId', '')
        sources = parameters.get('sources', ['urlhaus', 'otx', 'github', 'leakcheck', 'threatfox', 'hibp', 'intelx'])
        max_results = parameters.get('maxResults', 100)

        if isinstance(keywords, str):
            keywords = json.loads(keywords) if keywords.startswith('[') else [keywords]

        start_time = time.time()
        all_results = []
        sources_queried = 0
        sources_with_hits = 0
        errors = []

        if agent:
            agent.report_progress(
                current_operation=f"Starting threat intelligence scan for {domain}",
                current_target=domain,
                items_processed=0,
                total_items=len(sources),
            )

        # Query each source
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=120)) as session:
            tasks = []

            if 'urlhaus' in sources:
                tasks.append(self._query_urlhaus(session, domain, agent))
            if 'otx' in sources:
                tasks.append(self._query_otx(session, domain, agent))
            if 'github' in sources:
                tasks.append(self._query_github(session, domain, keywords, agent))
            if 'threatfox' in sources:
                tasks.append(self._query_threatfox(session, domain, agent))
            if 'hibp' in sources:
                tasks.append(self._query_hibp_breaches(session, domain, agent))
            if 'intelx' in sources:
                tasks.append(self._query_intelx(session, domain, agent))

            results = await asyncio.gather(*tasks, return_exceptions=True)

            for i, result in enumerate(results):
                sources_queried += 1
                if isinstance(result, Exception):
                    errors.append(str(result))
                elif result:
                    all_results.extend(result)
                    sources_with_hits += 1

            # LeakCheck requires sequential rate-limited calls
            if 'leakcheck' in sources:
                try:
                    lc_results = await self._query_leakcheck(session, domain, agent)
                    if lc_results:
                        all_results.extend(lc_results)
                        sources_with_hits += 1
                    sources_queried += 1
                except Exception as e:
                    errors.append(f"LeakCheck: {str(e)}")
                    sources_queried += 1

        # Always include simulation data if requested or if few results
        use_simulation = (
            'simulation' in sources or
            os.environ.get('DARKWEB_SIMULATION', '').lower() == 'true'
        )

        if use_simulation:
            sim_results = self._load_simulation_data(domain, keywords)
            all_results.extend(sim_results)
            sources_queried += 1
            if sim_results:
                sources_with_hits += 1
            if agent:
                agent.report_progress(
                    current_operation=f"Loaded {len(sim_results)} simulation results",
                    current_target=domain,
                    items_processed=sources_queried,
                    total_items=len(sources),
                )

        # Deduplicate by content hash
        seen_hashes = set()
        unique_results = []
        for r in all_results:
            h = hashlib.sha256(f"{r.get('source','')}{r.get('sourceId','')}{r.get('title','')}".encode()).hexdigest()
            if h not in seen_hashes:
                seen_hashes.add(h)
                unique_results.append(r)

        # Limit results
        unique_results = unique_results[:max_results]

        # Build severity/matchType breakdowns
        severity_breakdown = {}
        match_type_breakdown = {}
        for r in unique_results:
            sev = r.get('severity', 'MEDIUM')
            severity_breakdown[sev] = severity_breakdown.get(sev, 0) + 1
            mt = r.get('matchType', 'BRAND_MENTION')
            match_type_breakdown[mt] = match_type_breakdown.get(mt, 0) + 1

        elapsed = time.time() - start_time

        output = {
            'brandMonitorId': brand_monitor_id,
            'domain': domain,
            'keywords': keywords,
            'results': unique_results,
            'summary': {
                'totalMentions': len(unique_results),
                'sourcesQueried': sources_queried,
                'sourcesWithHits': sources_with_hits,
                'severityBreakdown': severity_breakdown,
                'matchTypeBreakdown': match_type_breakdown,
                'errors': errors,
            },
            'tool': 'darkweb',
            'scan_type': 'monitor',
        }

        raw_output = json.dumps(output, indent=2, default=str)

        if agent:
            agent.report_progress(
                current_operation=f"Threat intel scan complete: {len(unique_results)} mentions from {sources_with_hits}/{sources_queried} sources",
                current_target=domain,
                items_processed=sources_queried,
                total_items=sources_queried,
            )
            agent.append_output(raw_output)

        return {
            'success': True,
            'output': output,
            'raw_output': raw_output,
            'execution_metrics': {
                'duration_seconds': round(elapsed, 2),
                'sources_queried': sources_queried,
                'total_results': len(unique_results),
            }
        }

    async def _query_urlhaus(self, session: aiohttp.ClientSession, domain: str, agent=None) -> List[Dict]:
        """Query abuse.ch URLhaus for domain mentions"""
        results = []
        try:
            if agent:
                agent.report_progress(f"Querying URLhaus for {domain}")

            url = 'https://urlhaus-api.abuse.ch/v1/host/'
            async with session.post(url, data={'host': domain}) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    urls = data.get('urls', [])
                    for entry in urls[:20]:
                        threat = entry.get('threat', 'malware_download')
                        results.append({
                            'source': 'THREAT_INTEL_FEED',
                            'sourceName': 'URLhaus (abuse.ch)',
                            'sourceUrl': entry.get('url', ''),
                            'sourceId': str(entry.get('id', '')),
                            'title': f"Malicious URL detected: {entry.get('url', domain)}",
                            'contentSnippet': f"URLhaus reports a {threat} threat associated with {domain}. Status: {entry.get('url_status', 'unknown')}. Tags: {', '.join(entry.get('tags', []) or ['none'])}",
                            'matchType': 'MALWARE_C2' if threat == 'malware_download' else 'BRAND_MENTION',
                            'matchedKeywords': [domain],
                            'severity': 'HIGH' if threat == 'malware_download' else 'MEDIUM',
                            'relevanceScore': 85,
                            'riskScore': 80,
                            'discoveredAt': entry.get('date_added', None),
                            'metadata': {
                                'threat': threat,
                                'status': entry.get('url_status'),
                                'tags': entry.get('tags'),
                                'reporter': entry.get('reporter'),
                            }
                        })
        except Exception as e:
            if agent:
                agent.report_progress(f"URLhaus query failed: {str(e)}")
        return results

    async def _query_otx(self, session: aiohttp.ClientSession, domain: str, agent=None) -> List[Dict]:
        """Query AlienVault OTX for domain intelligence"""
        results = []
        try:
            if agent:
                agent.report_progress(f"Querying AlienVault OTX for {domain}")

            url = f'https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general'
            headers = {}
            otx_key = os.environ.get('OTX_API_KEY', '')
            if otx_key:
                headers['X-OTX-API-KEY'] = otx_key

            async with session.get(url, headers=headers) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    pulses = data.get('pulse_info', {}).get('pulses', [])
                    for pulse in pulses[:15]:
                        tags = pulse.get('tags', [])
                        # Determine match type based on tags
                        match_type = 'BRAND_MENTION'
                        severity = 'MEDIUM'
                        if any(t in tags for t in ['phishing', 'credential']):
                            match_type = 'CREDENTIAL_LEAK'
                            severity = 'HIGH'
                        elif any(t in tags for t in ['malware', 'c2', 'botnet', 'trojan']):
                            match_type = 'MALWARE_C2'
                            severity = 'HIGH'
                        elif any(t in tags for t in ['apt', 'targeted']):
                            match_type = 'TARGETING_DISCUSSION'
                            severity = 'HIGH'

                        results.append({
                            'source': 'THREAT_INTEL_FEED',
                            'sourceName': 'AlienVault OTX',
                            'sourceUrl': f"https://otx.alienvault.com/pulse/{pulse.get('id', '')}",
                            'sourceId': pulse.get('id', ''),
                            'title': pulse.get('name', f'OTX Pulse mentioning {domain}'),
                            'contentSnippet': pulse.get('description', '')[:500] or f"Threat intelligence pulse mentioning {domain}. Tags: {', '.join(tags[:10])}",
                            'matchType': match_type,
                            'matchedKeywords': [domain] + [t for t in tags if domain.split('.')[0] in t.lower()][:5],
                            'severity': severity,
                            'relevanceScore': min(95, 50 + len(tags) * 5),
                            'riskScore': min(90, 40 + len(pulses) * 3),
                            'discoveredAt': pulse.get('created', None),
                            'metadata': {
                                'tags': tags[:20],
                                'references': pulse.get('references', [])[:5],
                                'adversary': pulse.get('adversary', None),
                                'targeted_countries': pulse.get('targeted_countries', []),
                            }
                        })
        except Exception as e:
            if agent:
                agent.report_progress(f"OTX query failed: {str(e)}")
        return results

    async def _query_github(self, session: aiohttp.ClientSession, domain: str, keywords: List[str], agent=None) -> List[Dict]:
        """Search GitHub for exposed secrets and code mentioning the domain"""
        results = []
        try:
            if agent:
                agent.report_progress(f"Searching GitHub for {domain}")

            github_token = os.environ.get('GITHUB_TOKEN', '')
            if not github_token:
                if agent:
                    agent.report_progress("No GITHUB_TOKEN set, skipping GitHub search")
                return results

            headers = {
                'Authorization': f'token {github_token}',
                'Accept': 'application/vnd.github.v3+json',
            }

            # Search for domain in code (potential secrets/configs)
            search_queries = [
                f'"{domain}" password OR secret OR api_key OR token',
                f'"{domain}" smtp OR database OR connection_string',
            ]

            for query in search_queries:
                url = f'https://api.github.com/search/code?q={query}&per_page=10'
                async with session.get(url, headers=headers) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        items = data.get('items', [])
                        for item in items[:5]:
                            repo = item.get('repository', {})
                            results.append({
                                'source': 'CODE_REPOSITORY',
                                'sourceName': f"GitHub - {repo.get('full_name', 'unknown')}",
                                'sourceUrl': item.get('html_url', ''),
                                'sourceId': f"github-{item.get('sha', '')[:12]}",
                                'title': f"Potential exposed secret in {repo.get('full_name', 'unknown')}",
                                'contentSnippet': f"Code containing references to {domain} found in {item.get('path', 'unknown file')} in repository {repo.get('full_name', 'unknown')}. This may contain exposed credentials or API keys.",
                                'matchType': 'EXPOSED_SECRET',
                                'matchedKeywords': [domain],
                                'severity': 'HIGH',
                                'relevanceScore': 75,
                                'riskScore': 70,
                                'discoveredAt': None,
                                'metadata': {
                                    'repository': repo.get('full_name'),
                                    'path': item.get('path'),
                                    'sha': item.get('sha'),
                                }
                            })
                    elif resp.status == 403:
                        if agent:
                            agent.report_progress("GitHub API rate limit reached")
                        break

                await asyncio.sleep(2)  # Rate limiting

        except Exception as e:
            if agent:
                agent.report_progress(f"GitHub search failed: {str(e)}")
        return results

    async def _query_leakcheck(self, session: aiohttp.ClientSession, domain: str, agent=None) -> List[Dict]:
        """Query LeakCheck public API for credential leaks"""
        results = []
        prefixes = ['info', 'admin', 'support', 'hr', 'sales', 'security', 'noreply', 'contact', 'help', 'billing']
        try:
            if agent:
                agent.report_progress(f"Querying LeakCheck for {domain} credential leaks")

            for prefix in prefixes:
                email = f"{prefix}@{domain}"
                try:
                    url = f'https://leakcheck.io/api/public?check={email}'
                    async with session.get(url) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            if data.get('success') and data.get('found', 0) > 0:
                                sources_list = data.get('sources', [])
                                for src in sources_list[:5]:
                                    src_name = src.get('name', 'Unknown')
                                    src_date = src.get('date', None)
                                    fields = src.get('fields', [])
                                    has_password = 'password' in [f.lower() for f in fields] if fields else False
                                    results.append({
                                        'source': 'CREDENTIAL_DUMP',
                                        'sourceName': 'LeakCheck (Stealer Logs)',
                                        'sourceUrl': f'https://leakcheck.io/',
                                        'sourceId': f"leakcheck-{email}-{src_name}".replace(' ', '-').lower(),
                                        'title': f"Credential leak found for {email}",
                                        'contentSnippet': f"Found in {src_name}{f' ({src_date})' if src_date else ''}. Exposed fields: {', '.join(fields) if fields else 'unknown'}. Email {email} appears in leaked credential database.",
                                        'matchType': 'CREDENTIAL_LEAK',
                                        'matchedKeywords': [domain, email],
                                        'severity': 'CRITICAL' if has_password else 'HIGH',
                                        'relevanceScore': 95 if has_password else 85,
                                        'riskScore': 90 if has_password else 75,
                                        'discoveredAt': src_date,
                                        'metadata': {
                                            'email': email,
                                            'breachSource': src_name,
                                            'breachDate': src_date,
                                            'exposedFields': fields,
                                            'hasPassword': has_password,
                                        }
                                    })
                        elif resp.status == 429:
                            if agent:
                                agent.report_progress("LeakCheck rate limited, stopping")
                            break
                except Exception as e:
                    if agent:
                        agent.report_progress(f"LeakCheck query for {email} failed: {str(e)}")
                await asyncio.sleep(1)  # Rate limit: 1 req/sec

            if agent and results:
                agent.report_progress(f"LeakCheck found {len(results)} credential leaks")
        except Exception as e:
            if agent:
                agent.report_progress(f"LeakCheck query failed: {str(e)}")
        return results

    async def _query_threatfox(self, session: aiohttp.ClientSession, domain: str, agent=None) -> List[Dict]:
        """Query ThreatFox (abuse.ch) for IOC data"""
        results = []
        try:
            if agent:
                agent.report_progress(f"Querying ThreatFox for {domain}")

            url = 'https://threatfox-api.abuse.ch/api/v1/'
            payload = {"query": "search_ioc", "search_term": domain}
            async with session.post(url, json=payload) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if data.get('query_status') == 'ok':
                        iocs = data.get('data', [])
                        for ioc in (iocs or [])[:15]:
                            ioc_type = ioc.get('ioc_type', '')
                            threat_type = ioc.get('threat_type', '')
                            malware = ioc.get('malware', '')
                            malware_printable = ioc.get('malware_printable', malware)
                            confidence = ioc.get('confidence_level', 50)

                            match_type = 'MALWARE_C2' if threat_type in ['botnet_cc', 'payload_delivery'] else 'BRAND_MENTION'
                            severity = 'CRITICAL' if confidence > 75 else 'HIGH' if confidence > 50 else 'MEDIUM'

                            results.append({
                                'source': 'THREAT_INTEL_FEED',
                                'sourceName': 'ThreatFox (abuse.ch)',
                                'sourceUrl': f"https://threatfox.abuse.ch/ioc/{ioc.get('id', '')}",
                                'sourceId': f"threatfox-{ioc.get('id', '')}",
                                'title': f"IOC reported: {ioc.get('ioc', domain)} ({malware_printable})",
                                'contentSnippet': f"ThreatFox IOC: {ioc.get('ioc', '')}. Threat type: {threat_type}. Malware: {malware_printable}. Confidence: {confidence}%. Tags: {', '.join(ioc.get('tags', []) or ['none'])}",
                                'matchType': match_type,
                                'matchedKeywords': [domain],
                                'severity': severity,
                                'relevanceScore': min(95, confidence),
                                'riskScore': min(90, confidence),
                                'discoveredAt': ioc.get('first_seen', None),
                                'metadata': {
                                    'iocType': ioc_type,
                                    'threatType': threat_type,
                                    'malware': malware_printable,
                                    'confidence': confidence,
                                    'tags': ioc.get('tags', []),
                                    'reporter': ioc.get('reporter', ''),
                                    'lastSeen': ioc.get('last_seen_utc', None),
                                }
                            })
        except Exception as e:
            if agent:
                agent.report_progress(f"ThreatFox query failed: {str(e)}")
        return results

    async def _query_hibp_breaches(self, session: aiohttp.ClientSession, domain: str, agent=None) -> List[Dict]:
        """Query Have I Been Pwned for breaches associated with the domain"""
        results = []
        try:
            if agent:
                agent.report_progress(f"Querying HIBP for {domain} breaches")

            url = 'https://haveibeenpwned.com/api/v3/breaches'
            headers = {'User-Agent': 'ASM-Platform-DarkWebMonitor'}
            async with session.get(url, headers=headers) as resp:
                if resp.status == 200:
                    breaches = await resp.json()
                    for breach in breaches:
                        breach_domain = breach.get('Domain', '').lower()
                        breach_name = breach.get('Name', '').lower()

                        # Match if the domain field matches OR domain appears in breach name
                        if breach_domain == domain.lower() or domain.lower().split('.')[0] in breach_name:
                            data_classes = breach.get('DataClasses', [])
                            has_passwords = 'Passwords' in data_classes
                            pwn_count = breach.get('PwnCount', 0)

                            severity = 'CRITICAL' if has_passwords and pwn_count > 100000 else 'HIGH' if has_passwords else 'MEDIUM'

                            results.append({
                                'source': 'CREDENTIAL_DUMP',
                                'sourceName': 'Have I Been Pwned',
                                'sourceUrl': f"https://haveibeenpwned.com/api/v3/breach/{breach.get('Name', '')}",
                                'sourceId': f"hibp-{breach.get('Name', '')}",
                                'title': f"Data breach: {breach.get('Title', breach.get('Name', domain))}",
                                'contentSnippet': f"Breach '{breach.get('Title', '')}' on {breach.get('BreachDate', 'unknown date')}. {pwn_count:,} accounts affected. Exposed data: {', '.join(data_classes[:10])}. Verified: {breach.get('IsVerified', False)}",
                                'matchType': 'CREDENTIAL_LEAK',
                                'matchedKeywords': [domain],
                                'severity': severity,
                                'relevanceScore': 90 if breach_domain == domain.lower() else 60,
                                'riskScore': 85 if has_passwords else 65,
                                'discoveredAt': breach.get('AddedDate', breach.get('BreachDate', None)),
                                'metadata': {
                                    'breachName': breach.get('Name'),
                                    'breachDate': breach.get('BreachDate'),
                                    'pwnCount': pwn_count,
                                    'dataClasses': data_classes,
                                    'isVerified': breach.get('IsVerified', False),
                                    'isSensitive': breach.get('IsSensitive', False),
                                    'hasPasswords': has_passwords,
                                }
                            })
        except Exception as e:
            if agent:
                agent.report_progress(f"HIBP query failed: {str(e)}")
        return results

    async def _query_intelx(self, session: aiohttp.ClientSession, domain: str, agent=None) -> List[Dict]:
        """Query IntelX.io for credential leaks and breach data.

        Free tier (no API key): Uses Phonebook API for email enumeration.
        Pro tier (INTELX_API_KEY set): Uses Intelligent Search for deeper results.
        """
        results = []
        try:
            if agent:
                agent.report_progress(f"Querying IntelX.io for {domain}")

            api_key = os.environ.get('INTELX_API_KEY', '')
            base_url = 'https://2.intelx.io'

            if api_key:
                # Pro tier: Intelligent Search API
                results = await self._query_intelx_pro(session, base_url, api_key, domain, agent)
            else:
                # Free tier: Phonebook API (no key required)
                results = await self._query_intelx_phonebook(session, base_url, domain, agent)

            if agent and results:
                agent.report_progress(f"IntelX found {len(results)} results for {domain}")

        except Exception as e:
            if agent:
                agent.report_progress(f"IntelX query failed: {str(e)}")
        return results

    async def _query_intelx_phonebook(self, session: aiohttp.ClientSession, base_url: str, domain: str, agent=None) -> List[Dict]:
        """Free tier: Phonebook API for email enumeration on the domain."""
        results = []
        try:
            # Start phonebook search
            search_url = f'{base_url}/phonebook/search'
            params = {
                'term': domain,
                'maxresults': 50,
                'media': 0,  # 0 = all
                'target': 1,  # 1 = emails
            }
            async with session.get(search_url, params=params) as resp:
                if resp.status != 200:
                    if agent:
                        agent.report_progress(f"IntelX Phonebook search returned status {resp.status}")
                    return results
                data = await resp.json()
                search_id = data.get('id')
                if not search_id:
                    return results

            # Wait briefly then fetch results
            await asyncio.sleep(2)

            result_url = f'{base_url}/phonebook/search/result'
            params = {'id': search_id, 'limit': 50, 'offset': 0}
            async with session.get(result_url, params=params) as resp:
                if resp.status != 200:
                    return results
                data = await resp.json()
                selectors = data.get('selectors', [])

                for sel in selectors[:30]:
                    selector_value = sel.get('selectorvalue', '')
                    selector_type = sel.get('selectortypeh', '')

                    if '@' in selector_value and domain.lower() in selector_value.lower():
                        results.append({
                            'source': 'CREDENTIAL_DUMP',
                            'sourceName': 'IntelX.io (Phonebook)',
                            'sourceUrl': f'https://intelx.io/?s={domain}',
                            'sourceId': f"intelx-pb-{hashlib.sha256(selector_value.encode()).hexdigest()[:12]}",
                            'title': f"Email found in breach databases: {selector_value}",
                            'contentSnippet': f"Email address {selector_value} associated with {domain} was found in IntelX.io phonebook search across breach databases and paste sites. Type: {selector_type}.",
                            'matchType': 'CREDENTIAL_LEAK',
                            'matchedKeywords': [domain, selector_value],
                            'severity': 'HIGH',
                            'relevanceScore': 80,
                            'riskScore': 75,
                            'discoveredAt': None,
                            'metadata': {
                                'email': selector_value,
                                'selectorType': selector_type,
                                'breachSource': 'IntelX Phonebook',
                                'tier': 'free',
                            }
                        })
        except Exception as e:
            if agent:
                agent.report_progress(f"IntelX Phonebook query failed: {str(e)}")
        return results

    async def _query_intelx_pro(self, session: aiohttp.ClientSession, base_url: str, api_key: str, domain: str, agent=None) -> List[Dict]:
        """Pro tier: Intelligent Search API for deeper breach data."""
        results = []
        headers = {'x-key': api_key}
        try:
            # Start intelligent search
            search_url = f'{base_url}/intelligent/search'
            payload = {
                'term': domain,
                'maxresults': 50,
                'media': 0,
                'sort': 2,  # sort by relevance
                'terminate': [None],
            }
            async with session.post(search_url, json=payload, headers=headers) as resp:
                if resp.status == 402:
                    if agent:
                        agent.report_progress("IntelX API key has insufficient credits, falling back to free tier")
                    return await self._query_intelx_phonebook(session, base_url, domain, agent)
                if resp.status != 200:
                    if agent:
                        agent.report_progress(f"IntelX Intelligent Search returned status {resp.status}")
                    return results
                data = await resp.json()
                search_id = data.get('id')
                if not search_id:
                    return results

            # Wait then fetch results
            await asyncio.sleep(3)

            result_url = f'{base_url}/intelligent/search/result'
            params = {'id': search_id, 'limit': 50, 'offset': 0}
            async with session.get(result_url, params=params, headers=headers) as resp:
                if resp.status != 200:
                    return results
                data = await resp.json()
                records = data.get('records', [])

                for record in records[:30]:
                    name = record.get('name', '')
                    media_type = record.get('mediah', 'unknown')
                    bucket = record.get('bucketh', 'unknown')
                    added = record.get('added', None)
                    system_id = record.get('systemid', '')

                    # Determine severity based on media type
                    severity = 'HIGH'
                    match_type = 'CREDENTIAL_LEAK'
                    if 'paste' in media_type.lower():
                        match_type = 'PASTE_SITE'
                        severity = 'MEDIUM'
                    elif 'leak' in bucket.lower() or 'breach' in bucket.lower():
                        severity = 'CRITICAL'
                    elif 'darknet' in bucket.lower() or 'tor' in bucket.lower():
                        match_type = 'DARK_WEB_MENTION'
                        severity = 'HIGH'

                    results.append({
                        'source': 'CREDENTIAL_DUMP',
                        'sourceName': f'IntelX.io ({bucket})',
                        'sourceUrl': f'https://intelx.io/?s={domain}',
                        'sourceId': f"intelx-{system_id[:12] if system_id else hashlib.sha256(name.encode()).hexdigest()[:12]}",
                        'title': f"Breach data found: {name[:100] if name else domain}",
                        'contentSnippet': f"Found in IntelX.io {bucket} database. Media type: {media_type}. Source: {name[:200]}. This record may contain credentials, PII, or sensitive data associated with {domain}.",
                        'matchType': match_type,
                        'matchedKeywords': [domain],
                        'severity': severity,
                        'relevanceScore': 85,
                        'riskScore': 80 if severity in ['CRITICAL', 'HIGH'] else 65,
                        'discoveredAt': added,
                        'metadata': {
                            'breachSource': bucket,
                            'mediaType': media_type,
                            'systemId': system_id,
                            'name': name[:200],
                            'tier': 'pro',
                        }
                    })
        except Exception as e:
            if agent:
                agent.report_progress(f"IntelX Intelligent Search failed: {str(e)}")
        return results

    def _load_simulation_data(self, domain: str, keywords: List[str]) -> List[Dict]:
        """Load simulation data from JSON file and replace placeholders"""
        try:
            data_path = Path(__file__).parent / 'data' / 'darkweb_sample_data.json'
            with open(data_path, 'r') as f:
                data = json.load(f)

            mentions = data.get('mentions', [])
            results = []
            for mention in mentions:
                # Deep copy and replace placeholders
                entry = json.loads(json.dumps(mention))
                for key in ['title', 'contentSnippet', 'sourceUrl']:
                    if key in entry and isinstance(entry[key], str):
                        entry[key] = entry[key].replace('{{domain}}', domain)

                # Replace keywords in matchedKeywords
                if 'matchedKeywords' in entry:
                    entry['matchedKeywords'] = [
                        kw.replace('{{domain}}', domain) for kw in entry['matchedKeywords']
                    ]

                # Add simulation flag
                if not entry.get('metadata'):
                    entry['metadata'] = {}
                entry['metadata']['simulation'] = True

                results.append(entry)

            return results
        except Exception as e:
            print(f"[DarkWebMonitor] Failed to load simulation data: {e}")
            return []


def get_tool():
    return DarkWebMonitorTool()
