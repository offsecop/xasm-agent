"""
Brand Discover VIPs Tool
Discovers VIPs (executives, leadership) from company websites
by crawling team/about/leadership pages.
"""

import json
import re
from plugin_interface import ToolPlugin
from typing import Dict, Any, List, Optional


SENIORITY_KEYWORDS = {
    'c-level': [
        'ceo', 'cto', 'cfo', 'coo', 'cio', 'ciso', 'cmo', 'cro', 'cpo',
        'chief executive', 'chief technology', 'chief financial', 'chief operating',
        'chief information', 'chief security', 'chief marketing', 'chief revenue',
        'chief product', 'chief',
    ],
    'vp': [
        'vp', 'vice president', 'svp', 'evp', 'avp',
        'senior vice president', 'executive vice president',
    ],
    'director': [
        'director', 'managing director', 'sr. director', 'senior director',
    ],
}

TEAM_PATHS = [
    '/about', '/team', '/leadership', '/about-us', '/our-team',
    '/people', '/management', '/executives', '/about/team',
    '/about/leadership', '/company/team',
]


def _classify_seniority(title: str) -> str:
    """Classify a job title into a seniority level."""
    title_lower = title.lower()
    for kw in SENIORITY_KEYWORDS['c-level']:
        if kw in title_lower:
            return 'c-level'
    for kw in SENIORITY_KEYWORDS['vp']:
        if kw in title_lower:
            return 'vp'
    for kw in SENIORITY_KEYWORDS['director']:
        if kw in title_lower:
            return 'director'
    return 'other'


def _passes_filter(seniority: str, filter_level: str) -> bool:
    """Check if a seniority level passes the given filter."""
    if filter_level == 'all':
        return True
    hierarchy = ['c-level', 'vp', 'director', 'other']
    filter_idx = {
        'c-level': 0,
        'vp+': 1,
        'director+': 2,
        'all': 3,
    }.get(filter_level, 0)
    seniority_idx = hierarchy.index(seniority) if seniority in hierarchy else 3
    return seniority_idx <= filter_idx


class BrandDiscoverVipsTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "brand:discover_vips"

    @property
    def description(self) -> str:
        return (
            "Discovers VIPs (executives, leadership) from company websites "
            "by crawling team, about, and leadership pages."
        )

    @property
    def schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "companyName": {
                    "type": "string",
                    "description": "Company name for context"
                },
                "domain": {
                    "type": "string",
                    "description": "Company domain (e.g. example.com)"
                },
                "brandMonitorId": {
                    "type": "string",
                    "description": "Brand monitor ID"
                },
                "seniorityFilter": {
                    "type": "string",
                    "description": "Filter: c-level, vp+, director+, or all (default: c-level)",
                    "default": "c-level"
                },
                "maxResults": {
                    "type": "integer",
                    "description": "Maximum number of VIPs to return (default: 20)",
                    "default": 20
                },
            },
            "required": ["domain"]
        }

    @property
    def metadata(self) -> Dict[str, Any]:
        return {
            "category": "brand",
            "phase": 3,
            "domain": ["web", "osint"],
            "input_type": ["domain"],
            "output_type": ["vips"],
            "chainable_after": ["typosquat:detect"],
            "chainable_before": [],
        }

    async def execute(self, parameters: Dict[str, Any]) -> Any:
        agent = parameters.get('_agent')

        company_name = parameters.get('companyName', '')
        domain = parameters.get('domain', '')
        brand_monitor_id = parameters.get('brandMonitorId', '')
        seniority_filter = parameters.get('seniorityFilter', 'c-level')
        max_results = parameters.get('maxResults', 20)

        if not domain:
            return {
                'success': False,
                'error': 'domain parameter is required',
                'output': {
                    'vips': [], 'totalFound': 0, 'pagesScanned': 0,
                    'brandMonitorId': brand_monitor_id,
                    'tool': 'brand', 'scan_type': 'discover_vips',
                }
            }

        if not brand_monitor_id:
            return {
                'success': False,
                'error': 'brandMonitorId parameter is required',
                'output': {
                    'vips': [], 'totalFound': 0, 'pagesScanned': 0,
                    'brandMonitorId': None,
                    'tool': 'brand', 'scan_type': 'discover_vips',
                }
            }

        # Clean domain
        domain = domain.replace('https://', '').replace('http://', '').rstrip('/')

        if agent:
            agent.report_progress(
                current_operation=f"Discovering VIPs from {domain}",
                current_target=domain,
                items_processed=0,
                total_items=len(TEAM_PATHS),
            )

        all_people: List[Dict[str, Any]] = []
        pages_scanned = 0

        try:
            from playwright.async_api import async_playwright

            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True, args=['--no-sandbox'])
                context = await browser.new_context(
                    viewport={'width': 1920, 'height': 1080},
                    user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                )

                for idx, path in enumerate(TEAM_PATHS):
                    url = f'https://{domain}{path}'
                    try:
                        page = await context.new_page()
                        response = await page.goto(url, wait_until='networkidle', timeout=15000)

                        if response and response.status == 200:
                            pages_scanned += 1
                            people = await self._extract_people(page, url)
                            all_people.extend(people)

                            if agent:
                                agent.append_output(
                                    f"[BrandVIPs] {url}: found {len(people)} person(s)"
                                )

                        await page.close()
                    except Exception as e:
                        print(f"[BrandVIPs] Failed to load {url}: {e}")
                        try:
                            await page.close()
                        except Exception:
                            pass

                    if agent:
                        agent.report_progress(
                            current_operation="Scanning team pages",
                            current_target=url,
                            items_processed=idx + 1,
                            total_items=len(TEAM_PATHS),
                        )

                await browser.close()
        except Exception as e:
            return {
                'success': False,
                'error': f'Playwright browser launch failed: {str(e)[:300]}',
                'output': {
                    'vips': [], 'totalFound': 0, 'pagesScanned': 0,
                    'brandMonitorId': brand_monitor_id,
                    'tool': 'brand', 'scan_type': 'discover_vips',
                }
            }

        # Deduplicate by name
        seen_names: dict = {}
        for person in all_people:
            name_key = person['fullName'].lower().strip()
            if name_key not in seen_names:
                seen_names[name_key] = person
            else:
                # Merge: prefer richer data
                existing = seen_names[name_key]
                if not existing.get('linkedinUrl') and person.get('linkedinUrl'):
                    existing['linkedinUrl'] = person['linkedinUrl']
                if not existing.get('photoUrl') and person.get('photoUrl'):
                    existing['photoUrl'] = person['photoUrl']
                if not existing.get('title') and person.get('title'):
                    existing['title'] = person['title']

        unique_people = list(seen_names.values())

        # Classify seniority and filter
        for person in unique_people:
            title = person.get('title', '')
            person['seniorityLevel'] = _classify_seniority(title)

        filtered = [
            person for person in unique_people
            if _passes_filter(person['seniorityLevel'], seniority_filter)
        ]

        # Sort by seniority (c-level first)
        seniority_order = {'c-level': 0, 'vp': 1, 'director': 2, 'other': 3}
        filtered.sort(key=lambda p: seniority_order.get(p.get('seniorityLevel', 'other'), 3))

        # Apply max results limit
        filtered = filtered[:max_results]

        if agent:
            agent.report_progress(
                current_operation="VIP discovery completed",
                current_target=domain,
                items_processed=len(TEAM_PATHS),
                total_items=len(TEAM_PATHS),
            )
            agent.append_output(
                f"[BrandVIPs] Found {len(filtered)} VIP(s) from {pages_scanned} page(s) "
                f"(filter: {seniority_filter})"
            )

        return {
            'success': True,
            'output': {
                'vips': filtered,
                'totalFound': len(filtered),
                'pagesScanned': pages_scanned,
                'brandMonitorId': brand_monitor_id,
                'tool': 'brand',
                'scan_type': 'discover_vips',
            }
        }

    async def _extract_people(self, page, source_url: str) -> List[Dict[str, Any]]:
        """Extract person data from a page using DOM analysis."""
        try:
            people_data = await page.evaluate("""() => {
                const people = [];
                const seen = new Set();

                // Strategy 1: Look for common team member patterns
                // Cards with headings + paragraph (name + title)
                const cards = document.querySelectorAll(
                    '[class*="team"], [class*="member"], [class*="person"], ' +
                    '[class*="staff"], [class*="leader"], [class*="executive"], ' +
                    '[class*="bio"], [class*="profile"]'
                );

                for (const card of cards) {
                    const nameEl = card.querySelector('h2, h3, h4, h5, strong, [class*="name"]');
                    const titleEl = card.querySelector('p, span, [class*="title"], [class*="role"], [class*="position"]');
                    const imgEl = card.querySelector('img');
                    const linkEl = card.querySelector('a[href*="linkedin.com"]');

                    if (nameEl) {
                        const name = nameEl.textContent.trim();
                        if (name && name.length > 2 && name.length < 100 && !seen.has(name.toLowerCase())) {
                            seen.add(name.toLowerCase());
                            const title = titleEl ? titleEl.textContent.trim().substring(0, 200) : '';
                            // Skip if "title" looks like a paragraph (too long)
                            const cleanTitle = title.length > 100 ? '' : title;
                            people.push({
                                fullName: name,
                                title: cleanTitle,
                                photoUrl: imgEl ? imgEl.src : null,
                                linkedinUrl: linkEl ? linkEl.href : null,
                            });
                        }
                    }
                }

                // Strategy 2: Look for LinkedIn links with nearby text
                if (people.length === 0) {
                    const linkedinLinks = document.querySelectorAll('a[href*="linkedin.com/in/"]');
                    for (const link of linkedinLinks) {
                        const parent = link.closest('div, li, article, section');
                        if (parent) {
                            const nameEl = parent.querySelector('h2, h3, h4, h5, strong');
                            if (nameEl) {
                                const name = nameEl.textContent.trim();
                                if (name && !seen.has(name.toLowerCase())) {
                                    seen.add(name.toLowerCase());
                                    const titleEl = parent.querySelector('p, span');
                                    people.push({
                                        fullName: name,
                                        title: titleEl ? titleEl.textContent.trim().substring(0, 200) : '',
                                        photoUrl: null,
                                        linkedinUrl: link.href,
                                    });
                                }
                            }
                        }
                    }
                }

                return people.slice(0, 100);
            }""")

            # Add metadata
            results = []
            for person in (people_data or []):
                if not person.get('fullName'):
                    continue
                # Basic name validation: at least 2 words or known single names
                name = person['fullName'].strip()
                words = name.split()
                if len(words) < 1:
                    continue

                title = person.get('title', '')
                seniority = _classify_seniority(title)

                # Confidence based on data completeness
                confidence = 0.5
                if title:
                    confidence += 0.2
                if person.get('linkedinUrl'):
                    confidence += 0.15
                if person.get('photoUrl'):
                    confidence += 0.1
                if len(words) >= 2:
                    confidence += 0.05

                results.append({
                    'fullName': name,
                    'title': title,
                    'photoUrl': person.get('photoUrl'),
                    'linkedinUrl': person.get('linkedinUrl'),
                    'seniorityLevel': seniority,
                    'confidence': round(min(confidence, 1.0), 2),
                    'discoverySource': 'company_website',
                })

            return results

        except Exception as e:
            print(f"[BrandVIPs] Person extraction failed for {source_url}: {e}")
            return []


def get_tool():
    return BrandDiscoverVipsTool()
