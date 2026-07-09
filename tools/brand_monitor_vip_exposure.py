"""
Brand VIP exposure monitoring tool.

Uses public search results to look for social profiles, impersonation attempts,
targeting signals, and exposure mentions tied to a registered VIP.
"""

import asyncio
import hashlib
import os
import random
import re
import sys
from html import unescape
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, unquote, urlparse

import aiohttp

from plugin_interface import ToolPlugin

# #981 — live SERP (Serper.dev) dispatch goes through the shared quota-bearing
# credential helpers. Guard sys.path so `from lib...` resolves whether the tool
# is loaded via plugin_loader (agent root already on path) or run standalone
# (tests / ad-hoc), mirroring darkweb_monitor.py.
_AGENT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _AGENT_ROOT not in sys.path:
    sys.path.append(_AGENT_ROOT)

from lib.integration_credentials import (  # noqa: E402
    checkout_provider,
    reconcile_call,
    upstream_request,
    IntegrationAuthError,
    IntegrationServerError,
    QuotaExceededError,
)
from lib.token_rarity import is_common_token, RISK_ANCHOR_TOKENS  # noqa: E402


PLATFORM_MAP = {
    'linkedin.com': 'LINKEDIN',
    'www.linkedin.com': 'LINKEDIN',
    'x.com': 'X',
    'www.x.com': 'X',
    'twitter.com': 'X',
    'www.twitter.com': 'X',
    'instagram.com': 'INSTAGRAM',
    'www.instagram.com': 'INSTAGRAM',
}

SOCIAL_PROFILE_PATTERNS = {
    'LINKEDIN': [r'/in/', r'/company/'],
    'X': [r'/[A-Za-z0-9_]{2,}$'],
    'INSTAGRAM': [r'/[A-Za-z0-9_.]{2,}$'],
}

DEFAULT_HEADERS = {
    'User-Agent': (
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 '
        '(KHTML, like Gecko) Chrome/122.0 Safari/537.36'
    ),
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
}

EXPOSURE_KEYWORDS = {
    'IMPERSONATION': [
        'impersonat', 'fake account', 'fake profile', 'parody', 'scam profile',
        'clone account', 'fraud account', 'spoof account',
    ],
    # Leak/exposure words are the ONLY HIGH-severity CONTACT_EXPOSURE triggers.
    # Bare contact nouns ('email'/'phone'/etc.) routinely appear on benign
    # "Contact Us" pages and even in our own search queries
    # ("{name} {company} email phone"), so on their own they MUST NOT fire HIGH.
    'CONTACT_EXPOSURE_LEAK': [
        'leak', 'breach', 'dox', 'doxx', 'exposed', 'paste', 'combolist',
        'pastebin',
    ],
    # Bare contact nouns: only count as CONTACT_EXPOSURE (and only MEDIUM) when
    # they co-occur with a leak word above.
    'CONTACT_NOUN': [
        'email', 'phone', 'address', 'contact', 'mobile',
    ],
    'TARGETING_SIGNAL': [
        'target', 'threat', 'harass', 'attack', 'credential', 'phish',
        'extort', 'blackmail', 'swat',
    ],
}


def _normalize_spaces(value: str) -> str:
    return re.sub(r'\s+', ' ', value or '').strip()


def _exec_dork_templates(
    name: str,
    company: str = '',
    domain: str = '',
    after_date: Optional[str] = None,
) -> List[str]:
    """#348 — PURE-FUNCTION operator-rich search-dork templates for executive /
    VIP exposure discovery. Returns a deduped, order-preserving list of Google-
    style dork queries (site:/filetype:/quoted-phrase operators) that surface
    profile pages, paste/doc leaks, and contact-PII exposure for a named exec.

    This is a PURE TEMPLATE BUILDER — it performs no I/O. Its output is consumed
    by `_build_serp_dork_cohorts` (the exec-pinpoint cohort) and executed live
    through the sanctioned SERP_SEARCH provider (#981, Serper.dev) via
    `_dispatch_serper` / `_execute_exec_dorks`. Brave / SerpAPI / Tavily remain
    DEFERRED (2026-05-15 scope decision); Serper is the first admitted SERP
    vendor. Keeping the operator grammar here (not inline at the call site) keeps
    the dork vocabulary reviewable + locked independently of provider wiring.
    """
    n = _normalize_spaces(name)
    if not n:
        return []
    quoted_name = f'"{n}"'
    co = _normalize_spaces(company)
    dom = _normalize_spaces(domain).lower().lstrip('@')

    templates: List[str] = []

    # 1. Professional-profile scoping (LinkedIn) — the primary exec footprint.
    templates.append(f'site:linkedin.com {quoted_name}')

    # 2. Paste / doc-leak site scoping — where dumped PII actually lands.
    for paste_site in ('pastebin.com', 'ghostbin.com', 'paste.ee'):
        templates.append(f'site:{paste_site} {quoted_name}')

    # 3. Document-leak dorks — confidential PDFs/docs naming the company.
    if co:
        quoted_co = f'"{co}"'
        templates.append(f'filetype:pdf {quoted_co} confidential')
        templates.append(f'filetype:xlsx {quoted_co} ("{n}" OR confidential)')
        # Exec named alongside the company in any indexed doc.
        templates.append(f'{quoted_name} {quoted_co} (resume OR org chart OR directory)')

    # 4. Contact-PII dork — exec name beside an owned mailbox or a phone label.
    if dom:
        templates.append(f'{quoted_name} ("@{dom}" OR "phone")')
    else:
        templates.append(f'{quoted_name} ("email" OR "phone")')

    # 5. Breach / dox scoping — exec name beside leak vocabulary.
    templates.append(f'{quoted_name} (breach OR leak OR dox OR combolist)')

    # 6. (#454/G5) AROUND(n) association — assert the exec co-occurs WITH the
    #    company within n words, killing the homonym/co-incidental-mention noise a
    #    bare `"name" "company"` conjunction lets through.
    if co:
        templates.append(f'{quoted_name} AROUND(5) "{co}"')

    # 7. (#454/G5) Recency window — surface NEWLY stood-up fakes / recent leaks.
    #    `after:` defaults to a 2-year lookback when no explicit date is supplied.
    if after_date is None:
        try:
            after_date = datetime.now(timezone.utc).replace(
                year=datetime.now(timezone.utc).year - 2
            ).strftime('%Y-%m-%d')
        except ValueError:  # Feb-29 guard
            after_date = f'{datetime.now(timezone.utc).year - 2}-01-01'
    templates.append(f'{quoted_name} after:{after_date}')

    # 8. (#454/G5) Subtract-the-legit-footprint — the single most useful
    #    impersonation-discovery move: the exec mentioned OFF their real LinkedIn
    #    and OFF the owned domain (impersonation / off-platform exposure).
    subtraction = f'{quoted_name} -site:linkedin.com'
    if dom:
        subtraction += f' -site:{dom}'
    templates.append(subtraction)

    # Dedupe preserving order.
    seen: set = set()
    out: List[str] = []
    for t in templates:
        if t and t not in seen:
            seen.add(t)
            out.append(t)
    return out


def _pivot_dork_templates(identifier: str) -> List[str]:
    """#454/G5 — the iterative pivot loop: a CONFIRMED exec email/handle (found by
    the first dork pass) is re-fed into credential/breach dorks to find where that
    specific identifier has been dumped. Pure function; deduped, order-preserving.
    """
    ident = _normalize_spaces(identifier).strip().lstrip('@')
    if not ident:
        return []
    quoted = f'"{ident}"'
    templates = [
        f'{quoted} (password OR passwd OR pwd OR credentials)',
        f'{quoted} (breach OR leak OR dump OR combolist)',
        'site:pastebin.com ' + quoted,
        f'{quoted} filetype:txt (login OR password)',
    ]
    seen: set = set()
    out: List[str] = []
    for t in templates:
        if t and t not in seen:
            seen.add(t)
            out.append(t)
    return out


# #981 — sanctioned SERP provider key (the enum value the ProviderQuotaService
# checks; concrete vendor = Serper.dev, discriminated by settings.provider).
_SERP_PROVIDER_KEY = 'SERP_SEARCH'

# SSRF: the Serper endpoint is PINNED here — the tool NEVER uses the
# checkout-returned baseUrl (the catalog omits `baseUrl` from optionalFields),
# so an operator cannot repoint SERP_SEARCH at an internal host to exfiltrate
# the key or drive blind server-side POSTs.
SERPER_ENDPOINT = 'https://google.serper.dev/search'
# Depth lever: `num>10` does NOT deepen (Serper caps a page at 10 results); the
# `page` parameter is the only way to reach results 11+, and EACH page is a
# separate metered call. So we page, we do not inflate `num`.
SERPER_RESULTS_PER_PAGE = 10
# Per-cohort depth policy (#981 §5): pinpoint dorks (LinkedIn/paste/data-broker)
# have a worthless tail → 1 page; discovery dorks (combosquat/brand-abuse/…)
# paginate loop-until-dry, bounded.
PINPOINT_MAX_PAGES = 1
DISCOVERY_MAX_PAGES = 3
# FinOps HARD cap: worst-case metered pages per VIP scan. At $0.001/page this
# bounds a single VIP sweep to ~$0.03 no matter how many cohorts run. Enforced
# as a hard stop in `_execute_exec_dorks`; asserted by the agent test.
MAX_SERP_PAGES_PER_VIP = 30

# Known third-party directory / platform hosts: a brand/exec appearing on ONE
# of these is a brand-MENTION on a legit platform, NOT a squat/impersonation.
# Decided on the registrable domain, so subdomains (brand.pissedconsumer.com)
# are suppressed too. These are the real 2026-07-03 FP sources generalised.
KNOWN_DIRECTORY_HOSTS = {
    'linkedin.com', 'crunchbase.com', 'pissedconsumer.com', 'soft112.com',
    'facebook.com', 'twitter.com', 'x.com', 'instagram.com', 'youtube.com',
    'glassdoor.com', 'indeed.com', 'bloomberg.com', 'reuters.com',
    'wikipedia.org', 'apps.apple.com', 'play.google.com', 'github.com',
    'medium.com', 'trustpilot.com', 'yelp.com', 'bbb.org', 'sec.gov',
}
# Data-broker PII hosts → actionable MEDIUM (opt-out request), not noise.
DATA_BROKER_HOSTS = {
    'rocketreach.co', 'zoominfo.com', 'datanyze.com', 'spokeo.com',
    'whitepages.com', 'radaris.com', 'beenverified.com', 'peoplefinder.com',
    'intelius.com', 'fastpeoplesearch.com', 'thatsthem.com', 'nuwber.com',
}
# Public-record / press / regulator / gov / podcast hosts. A public-company
# exec NAMED on one of these is a public MENTION, not a contact-PII exposure —
# route a name match to LOW PUBLIC_MENTION rather than HIGH CONTACT_EXPOSURE.
# Registrable-domain matched (so subdomains resolve too); *.gc.ca covered via
# the eTLD+1 endswith check.
_PUBLIC_RECORD_HOSTS = {
    'ciro.ca', 'osc.ca', 'ourcommons.ca', 'gc.ca', 'canada.ca',
    'sec.gov', 'finra.org', 'sedar.com', 'sedarplus.ca',
    'simplecast.com', 'buzzsprout.com', 'libsyn.com', 'podbean.com',
    'reuters.com', 'bloomberg.com', 'apnews.com', 'wsj.com', 'ft.com',
    'nytimes.com', 'theglobeandmail.com', 'cbc.ca', 'bbc.com', 'bbc.co.uk',
    'forbes.com', 'cnbc.com', 'businesswire.com', 'prnewswire.com',
    'globenewswire.com', 'newswire.ca',
}
# Nickname → canonical-name equivalences for data-broker person-slug matching
# (Fix #2, wrong-person attribution). Bidirectional: mike≈michael, ed≈edward.
_NICKNAME_EQUIV = {
    'mike': 'michael', 'mich': 'michael',
    'ed': 'edward', 'eddie': 'edward', 'ted': 'edward',
    'bob': 'robert', 'rob': 'robert', 'bobby': 'robert',
    'bill': 'william', 'will': 'william', 'billy': 'william',
    'jim': 'james', 'jimmy': 'james', 'jamie': 'james',
    'tom': 'thomas', 'tommy': 'thomas',
    'dave': 'david', 'dan': 'daniel', 'danny': 'daniel',
    'chris': 'christopher', 'nick': 'nicholas', 'tony': 'anthony',
    'joe': 'joseph', 'joey': 'joseph', 'steve': 'steven', 'stephen': 'steven',
    'matt': 'matthew', 'ben': 'benjamin', 'sam': 'samuel',
    'kate': 'katherine', 'katie': 'katherine', 'kathy': 'katherine',
    'liz': 'elizabeth', 'beth': 'elizabeth', 'betty': 'elizabeth',
    'sue': 'susan', 'jen': 'jennifer', 'jenny': 'jennifer',
    'peggy': 'margaret', 'meg': 'margaret', 'maggie': 'margaret',
}
# Municipal records / meeting-portal hosts — a named exec on one of these
# (agendas, minor-variance / committee-of-adjustment filings) frequently carries
# a home address ⇒ a residence-DOX signal. Registrable-domain matched.
_MUNICIPAL_RECORDS_HOSTS = {
    'escribemeetings.com', 'civicweb.net', 'legistar.com', 'novusagenda.com',
    'iqm2.com', 'granicus.com', 'civicplus.com',
}
_RESIDENCE_TERMS = (
    'minor variance', 'committee of adjustment', 'home address', 'residence of',
    'property owner', 'site plan application', 'zoning', 'land use',
)

# Deterministic cohort by hostClass (#3): when the HOST classifier fires, the
# emitted metadata.cohort is derived from the host signal (canonical, URL-stable)
# rather than the dork that happened to surface the URL. Keys are the `category`
# values set in `_serp_hit_to_finding`.
_CANONICAL_COHORT_BY_HOSTCLASS = {
    'DATA_BROKER_PII': 'data_broker',
    'COMBOSQUAT': 'combosquat',
    'OBJECT_STORE_BUCKET': 'object_store',
    'RESIDENCE_EXPOSURE': 'residence',
}

# Object-store markers — bucket hits are kept ONLY when the brand is in the
# BUCKET NAME (brand-in-content was ~100% FP on the 2026-07-03 sweep).
OBJECT_STORE_MARKERS = (
    's3.amazonaws.com', 'storage.googleapis.com', 'blob.core.windows.net',
    'r2.cloudflarestorage.com', 'digitaloceanspaces.com',
)
# Registrable-domain (eTLD+1) helper: the small set of multi-label public
# suffixes we care about. A full PSL is overkill for dork triage; this covers
# the common ccTLD second levels so `foo.co.uk` → `foo.co.uk`, not `co.uk`.
_MULTI_LEVEL_TLDS = {
    'co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'co.jp', 'com.au', 'net.au',
    'org.au', 'co.nz', 'com.br', 'com.mx', 'co.in', 'co.za', 'com.sg',
    'com.hk', 'com.tr', 'com.cn', 'com.tw',
}


class _SerpNotConfigured(Exception):
    """No usable SERP_SEARCH integration (404 no-integration / 403 agent-access
    off). NOT a failure — the sweep simply isn't available, so the caller falls
    through to the existing behaviour (never a false empty-clean)."""


class _SerpSweepFailed(Exception):
    """A CONFIGURED SERP provider was actively broken mid-sweep (401 revoked key,
    429 quota, 402 cost-breaker, persistent 5xx). Scan-invalidating: the caller
    must FAIL the job, never report a clean zero-findings result."""


def _registrable_domain(host: str) -> str:
    """eTLD+1 of a hostname (best-effort, PSL-lite). '' on empty input."""
    host = (host or '').lower().strip().strip('.').split(':')[0]
    if not host:
        return ''
    labels = host.split('.')
    if len(labels) <= 2:
        return host
    if '.'.join(labels[-2:]) in _MULTI_LEVEL_TLDS:
        return '.'.join(labels[-3:])
    return '.'.join(labels[-2:])


def _host_in_directory(host: str, hostset: set) -> bool:
    reg = _registrable_domain(host)
    return bool(host) and (
        host in hostset or reg in hostset or
        any(host == h or host.endswith('.' + h) for h in hostset)
    )


def _label_tokens(label: str) -> List[str]:
    """Split a domain label into standalone tokens on non-alphanumeric AND
    camelCase boundaries (hostnames are lowercased upstream, but raw input is
    handled defensively). Mirrors the typosquat engine's combosquat
    tokenization (typosquat_detect.py splits the SLD on hyphens/dots)."""
    if not label:
        return []
    with_bounds = re.sub(r'(?<=[a-z0-9])(?=[A-Z])', '-', label)
    return [t for t in re.split(r'[^a-zA-Z0-9]+', with_bounds) if t]


def _label_has_standalone_brand_token(label: str, brand_tokens) -> bool:
    """P0-4 — combosquat requires the brand as a STANDALONE token of the
    registrable label, never a raw substring, mirroring the platform's own
    combosquat rule in typosquat_detect.py (exact token membership in the
    tokenized SLD, brand token length >= 4). A glued coincidental label
    ('<brand>wealth'-style, or a short brand inside an unrelated word) must NOT
    hard-emit IMPERSONATION/HIGH."""
    toks = {t.lower() for t in _label_tokens(label)}
    return any(
        len(b) >= 4 and b.lower() in toks
        for b in (brand_tokens or [])
        if b
    )


def _combosquat_second_anchor_present(label: str, brand_tokens) -> bool:
    """Phase 4 (P1-4 #825) — rarity-aware second-anchor check for the P0-4
    standalone-token rule.

    An exact-but-COMMON brand word (an ordinary dictionary word —
    `is_common_token`, wordfreq Zipf across en/es/fr/pt/de/it) standing alone
    in a registrable label collides with the ordinary use of the word, so it
    must NOT hard-emit IMPERSONATION/HIGH by itself. It needs a SECOND brand
    anchor in the same label:
      - another, DISTINCT brand token also standalone (multi-word brand
        confirmation: 'mode' + 'apparel'), or
      - a credential/attack-suffix token (`RISK_ANCHOR_TOKENS`: login/verify/
        support/…) — impersonation intent regardless of word rarity.

    Returns True when the standalone-token hit may keep the HIGH band:
      - any matched brand token is RARE (a coined name is its own anchor), or
      - a common matched token is corroborated by a second anchor.
    Returns False for the bare common-word collision (the caller defers to the
    content classifier instead of hard-flagging). Fail-open by construction: a
    missing wordfreq makes every token read RARE → prior behavior.
    """
    toks = {t.lower() for t in _label_tokens(label)}
    matched = [
        b.lower() for b in (brand_tokens or [])
        if b and len(b) >= 4 and b.lower() in toks
    ]
    if not matched:
        return False
    # A RARE matched brand token is self-anchoring.
    if any(not is_common_token(m) for m in matched):
        return True
    # All matched tokens are common → need a second anchor in the label.
    if len(set(matched)) >= 2:
        return True
    if any(t in RISK_ANCHOR_TOKENS for t in toks):
        return True
    return False


def _classify_serp_host(
    url: str,
    owned_domains: Optional[List[str]] = None,
    typosquat_domains: Optional[List[str]] = None,
    brand_tokens: Optional[List[str]] = None,
    full_name: str = '',
) -> Optional[Dict[str, Any]]:
    """HOST-risk classification of a SERP hit (orthogonal to the CONTENT-keyword
    axis of `_classify_exposure`). Returns:
      - {'action':'suppress', 'reason':...}   → do not emit (owned/known/tracked)
      - {'action':'flag', 'category', 'exposureType', 'severity', 'riskScore',
         'confidence'}                          → emit with this host severity
      - None                                    → no host signal; defer to the
                                                  content classifier.
    Combosquat is decided on the REGISTRABLE domain (eTLD+1), never a bare host
    substring, cross-referenced against ownedDomains + the tracked typosquat set.
    """
    host = (urlparse(url or '').hostname or '').lower()
    if not host:
        return None
    reg = _registrable_domain(host)
    owned = {_registrable_domain(d) for d in (owned_domains or []) if d}
    known_squats = {_registrable_domain(d) for d in (typosquat_domains or []) if d}
    tokens = [t.lower() for t in (brand_tokens or []) if t and len(t) >= 3]

    # 1) Owned property → never flag.
    if reg and reg in owned:
        return {'action': 'suppress', 'reason': 'owned'}
    # 2) Already-tracked squat → suppress from NEW-combosquat flagging (the
    #    typosquat engine already owns it; avoids double-surfacing).
    if reg and reg in known_squats:
        return {'action': 'suppress', 'reason': 'known_typosquat'}
    # 3) Known third-party directory/platform → brand-mention, not a squat
    #    (the questrade.pissedconsumer.com / *.soft112.com FP class).
    if _host_in_directory(host, KNOWN_DIRECTORY_HOSTS):
        return {'action': 'suppress', 'reason': 'known_directory'}
    # 4) Data-broker PII host → MEDIUM, actionable (opt-out). CONTACT_EXPOSURE
    #    so it mirrors to triage even at MEDIUM. BUT a data-broker PERSON page
    #    (zoominfo.com/p/<Name>, rocketreach.co/<name>-email) is frequently a
    #    DIFFERENT person with the same/similar name — verify the URL person slug
    #    matches the VIP (nickname-aware) before flagging; a clear homonym is
    #    SUPPRESSED (the #2 wrong-person FP class). Company-directory pages
    #    (/c/, /companies/, /pic/, …) are brand-level and always kept.
    if _host_in_directory(host, DATA_BROKER_HOSTS):
        person_match = _data_broker_person_slug_matches(url, full_name)
        if person_match is False:
            return {'action': 'suppress', 'reason': 'data_broker_wrong_person'}
        return {
            'action': 'flag', 'category': 'DATA_BROKER_PII',
            'exposureType': 'CONTACT_EXPOSURE', 'severity': 'MEDIUM',
            'riskScore': 52, 'confidence': 0.6,
        }
    # 5) Object-store bucket — keep ONLY when a brand token is in the bucket
    #    NAME, never brand-in-CONTENT (brand-in-content was ~100% FP). The bucket
    #    name is the host label for virtual-host style (<bucket>.s3.amazonaws.com)
    #    and the FIRST PATH SEGMENT for path style (s3.amazonaws.com/<bucket>/…);
    #    the object key (rest of the path) is content and must NOT be matched.
    marker = next((m for m in OBJECT_STORE_MARKERS if m in host), None)
    if marker:
        if host.endswith('.' + marker):
            bucket = host[: -(len(marker) + 1)].split('.')[-1]
        else:
            bucket = (urlparse(url).path or '').lstrip('/').split('/')[0].lower()
        if any(tok in bucket for tok in tokens):
            return {
                'action': 'flag', 'category': 'OBJECT_STORE_BUCKET',
                'exposureType': 'DATA_EXPOSURE', 'severity': 'MEDIUM',
                'riskScore': 55, 'confidence': 0.5,
            }
        return {'action': 'suppress', 'reason': 'bucket_brand_in_content'}
    # 6) Combosquat — brand token as a STANDALONE token of the eTLD+1 main
    #    label (not owned/known/tracked, all checked above). The flagship
    #    high-value detection. P0-4: an exact-token match (len >= 4) mirroring
    #    typosquat_detect.py's combosquat rule — a raw substring hit (brand
    #    glued inside an unrelated word) is dropped here, not raised HIGH.
    #    Phase 4 (P1-4 #825): rarity-aware — an exact-but-COMMON brand word
    #    (a common dictionary word) needs a SECOND anchor (another brand token, or a
    #    credential/attack-suffix token) before it hard-emits HIGH; a bare
    #    common-word collision defers to the content classifier instead.
    reg_label = reg.split('.')[0] if reg else ''
    if reg_label and _label_has_standalone_brand_token(reg_label, tokens):
        if _combosquat_second_anchor_present(reg_label, tokens):
            return {
                'action': 'flag', 'category': 'COMBOSQUAT',
                'exposureType': 'IMPERSONATION', 'severity': 'HIGH',
                'riskScore': 78, 'confidence': 0.7,
            }
        # Common-word brand token, no second anchor → no HOST-level signal;
        # the content classifier still gets its look (None, not suppress).
        return None
    # 7) No host-level signal → let the content classifier decide.
    return None


def _build_serp_dork_cohorts(
    full_name: str,
    company_name: str = '',
    company_domain: str = '',
    owned_domains: Optional[List[str]] = None,
) -> List[Dict[str, Any]]:
    """Build cohort-tagged SERP dork specs `[{cohort, query, kind}]`. Reuses the
    exec-dork vocabulary (`_exec_dork_templates`) for the exec cohort and adds
    the sharpened brand cohorts (#981). Cohorts proven noisy/owned by other
    lanes (github-code-secret, index-of, homoglyph, social-handle, onion) are
    deliberately EXCLUDED. Pure function — no I/O."""
    name = _normalize_spaces(full_name)
    co = _normalize_spaces(company_name)
    dom = _normalize_spaces(company_domain).lower().lstrip('@').split('/')[0]
    brand = co or (dom.split('.')[0] if dom else '')
    owned = [str(d).strip().lower() for d in (owned_domains or []) if d]
    if dom and dom not in owned:
        owned = owned + [dom]
    neg_owned = ' '.join(f'-site:{d}' for d in owned[:5])

    specs: List[Dict[str, Any]] = []
    seen: set = set()

    def add(cohort: str, query: str, kind: str) -> None:
        q = _normalize_spaces(query)
        if q and q not in seen:
            seen.add(q)
            specs.append({'cohort': cohort, 'query': q, 'kind': kind})

    # Exec cohort — reuse the single exec-dork vocabulary. Subtract-footprint /
    # doc-leak templates are discovery; the rest (LinkedIn/paste/AROUND) pinpoint.
    if name:
        for q in _exec_dork_templates(name, co, dom):
            kind = 'discovery' if ('-site:' in q or 'filetype:' in q) else 'pinpoint'
            add('exec', q, kind)
        # Exec investment-scam / BEC lure.
        add('brand_abuse_investment',
            f'"{name}" (bitcoin OR crypto OR giveaway OR "invest with me")', 'discovery')
        # Broadened paste cohort (0-recall treated low-confidence, never clean).
        add('paste',
            f'"{name}" (site:rentry.co OR site:controlc.com OR site:justpaste.it '
            f'OR site:0bin.net OR site:telegra.ph)', 'pinpoint')
        # Data-broker exec PII (classifier routes these to MEDIUM/actionable).
        add('data_broker',
            f'"{name}" (site:rocketreach.co OR site:zoominfo.com OR site:datanyze.com '
            f'OR site:spokeo.com OR site:whitepages.com OR site:radaris.com)', 'pinpoint')
        # Residence / municipal DOX — surfaces home-address exposure via municipal
        # meeting portals (escribemeetings/civicweb) + property/minor-variance
        # records. This is the class that finds a CEO's home address; residence
        # hits are elevated to HIGH in _serp_hit_to_finding (physical-safety PII).
        add('residence',
            f'"{name}" (address OR "minor variance" OR property OR "site plan" '
            f'OR "committee of adjustment" OR site:escribemeetings.com '
            f'OR site:*.escribemeetings.com OR site:*.civicweb.net)', 'discovery')
        # Email-convention / doc-leak — an unmasked exec email in an indexed doc
        # exposes the first-initial+surname convention (direct BEC value).
        _dom_frag = f'"@{dom}" OR ' if dom else ''
        add('email_convention',
            f'filetype:pdf "{name}" ({_dom_frag}email OR contact)', 'discovery')

    if brand:
        b = f'"{brand}"'
        # Combosquat / off-domain login — the flagship, highest-value cohort.
        add('combosquat',
            f'{b} (login OR "sign in" OR verify OR account OR portal OR secure) {neg_owned}',
            'discovery')
        # App-mirror brand abuse.
        add('app_mirror',
            f'{b} (apk OR "download app") -site:play.google.com -site:apps.apple.com',
            'discovery')
        # Brand-abuse: fake support / phone scam.
        add('brand_abuse_support',
            f'{b} ("customer service number" OR "support number" OR helpline OR "call now") {neg_owned}',
            'discovery')
        # Brand-abuse: fake recruitment / job scam.
        add('brand_abuse_job',
            f'{b} (hiring OR "job offer" OR "work from home") '
            f'(whatsapp OR telegram OR "text us" OR gmail.com) {neg_owned} -site:linkedin.com',
            'discovery')
        # Brand-abuse: investment scam.
        add('brand_abuse_investment',
            f'{b} ("account manager" OR "trading signals" OR guaranteed OR "double your") '
            f'(whatsapp OR telegram)', 'discovery')
        # Doc / cloud-doc leak.
        add('doc_leak',
            f'filetype:pdf {b} (confidential OR internal OR "do not distribute") {neg_owned}',
            'discovery')
        # Object-store buckets (low-yield; classifier keeps only bucket-name hits).
        # Broadened beyond S3/GCS/Azure to the other public object stores whose
        # buckets are routinely left world-readable: DigitalOcean Spaces,
        # Cloudflare R2 public dev buckets, Alibaba OSS, and Firebase RTDB/Storage.
        add('object_store',
            f'(site:s3.amazonaws.com OR site:storage.googleapis.com '
            f'OR site:blob.core.windows.net OR site:digitaloceanspaces.com '
            f'OR site:r2.dev OR site:oss.aliyuncs.com OR site:firebaseio.com '
            f'OR site:firebasestorage.googleapis.com) {brand}', 'discovery')
        # Non-GitHub code-host leak — SERP is the ONLY coverage for these
        # (no code-search API lane reaches GitLab/Bitbucket/Codeberg/etc.).
        codehosts = ('(site:gitlab.com OR site:bitbucket.org OR site:codeberg.org '
                     'OR site:sourceforge.net OR site:gitea.com OR site:hub.docker.com)')
        if dom:
            add('code_host', f'{codehosts} ("{dom}" OR "@{dom}")', 'discovery')
        else:
            add('code_host', f'{codehosts} {b}', 'discovery')
        # Code-SEARCH engines — cross-repo indexers (grep.app, searchcode,
        # publicwww, Sourcegraph) that surface brand/domain strings buried in
        # public code the per-host code_host dork can't reach. Deliberately does
        # NOT include site:github.com (the GitHub code lane owns that; the #454
        # noisy-lane exclusion). Domain-scoped when available for precision.
        codesearch = ('(site:grep.app OR site:searchcode.com OR site:publicwww.com '
                      'OR site:sourcegraph.com)')
        if dom:
            add('code_search', f'{codesearch} ("{dom}" OR "@{dom}")', 'discovery')
        else:
            add('code_search', f'{codesearch} {b}', 'discovery')

    return specs


async def _dispatch_serper(
    query: str,
    page: int,
    session: aiohttp.ClientSession,
    timeout_seconds: Optional[float] = None,
) -> Dict[str, Any]:
    """Live Serper.dev dispatch for ONE metered page (#981 §3). Per the issue's
    per-page-metering contract: checkout a lease → POST → reconcile, one bracket
    per page, so a `ProviderCallLog` row exists per page and the DAILY cap can
    halt a runaway sweep at a page boundary.

    Returns `{'hits': [...], 'unswept': bool}`. Error handling (fail-closed —
    NEVER a swept-clean empty page on failure):
      - checkout 404/403 no-integration       → `_SerpNotConfigured` (fall-through)
      - checkout/HTTP 401, 402, 403, 429       → `_SerpSweepFailed` (abort sweep)
      - HTTP 400 (free-tier filetype block)    → `unswept=True` (this page only)
      - HTTP 404/5xx/other, transport, JSON    → `unswept=True` (this page only;
        an all-unswept sweep then fails closed in execute())
    NEVER logs or returns the decrypted apiKey."""
    try:
        lease = await checkout_provider(_SERP_PROVIDER_KEY, requested_units=1, session=session)
    except IntegrationAuthError:
        raise _SerpSweepFailed('serp_auth_failed')       # 401 revoked/bad key
    except QuotaExceededError:
        raise _SerpSweepFailed('serp_quota_exceeded')    # 429 quota exhausted
    except IntegrationServerError as exc:
        msg = str(exc)
        if any(m in msg for m in ('HTTP 404', 'HTTP 403', 'No active', 'not enabled', 'Unknown provider')):
            raise _SerpNotConfigured(msg)                # not configured / agent-access off
        raise _SerpSweepFailed('serp_server_error')      # 402 cost-breaker / 5xx / transport

    api_key = lease.get('apiKey')
    lease_token = lease.get('leaseToken')
    if not api_key or not lease_token:
        raise _SerpSweepFailed('serp_no_key')
    eff_timeout = timeout_seconds or lease.get('timeoutSeconds') or 30

    ok = True
    err_code: Optional[str] = None
    unswept = False
    hits: List[Dict[str, str]] = []
    resp = None
    try:
        # Endpoint is PINNED (SSRF) — the leased baseUrl is deliberately ignored.
        resp, _ = await upstream_request(
            session, 'POST', SERPER_ENDPOINT,
            headers={'X-API-KEY': api_key, 'Content-Type': 'application/json'},
            json_body={'q': query, 'num': SERPER_RESULTS_PER_PAGE, 'page': page},
            provider_label='serper',
            timeout_seconds=eff_timeout,
        )
        status = getattr(resp, 'status', 0)
        if status == 400:
            # Free-tier config-filetype block → unswept (low-confidence), the
            # sweep of THIS query is NOT a clean zero. Never empty-clean.
            ok = False
            err_code = 'serp_http_400'
            unswept = True
        elif status == 401:
            ok = False
            err_code = 'serp_http_401'
            raise _SerpSweepFailed('serp_http_401')       # key revoked mid-sweep
        elif status in (402, 403):
            # Cost-breaker (402) / forbidden (403) — the vendor is CUT OFF; every
            # further call will fail the same way, so abort the whole sweep.
            ok = False
            err_code = f'serp_http_{status}'
            raise _SerpSweepFailed(f'serp_http_{status}')
        elif status == 429:
            ok = False
            err_code = 'serp_http_429'
            raise _SerpSweepFailed('serp_http_429')
        elif status >= 400:
            # 404 / 5xx / other — upstream_request already retried 5xx; a
            # persistent failure here is NOT a clean page. Mark this page
            # `unswept` so the sweep can never be reported swept-clean on an
            # upstream error (an all-unswept sweep fails closed in execute()).
            ok = False
            err_code = f'serp_http_{status}'
            unswept = True
        else:
            data = await resp.json()
            for item in (data.get('organic') or []):
                link = item.get('link')
                if not link:
                    continue
                hits.append({
                    'url': link,
                    'title': item.get('title', '') or '',
                    'snippet': item.get('snippet', '') or '',
                })
    except _SerpSweepFailed:
        raise
    except Exception:
        # Transport error / timeout / malformed JSON — NEVER a clean page.
        ok = False
        err_code = 'serp_dispatch_error'
        unswept = True
    finally:
        if resp is not None:
            try:
                await resp.release()
            except Exception:
                pass
        # ONE reconcile per page, always — with success + error_code attribution
        # so 4xx/5xx feed the reconciled-failure throttle path.
        try:
            await reconcile_call(
                _SERP_PROVIDER_KEY, lease_token,
                units=1, success=ok, error_code=err_code, session=session,
            )
        except Exception:
            pass
    return {'hits': hits, 'unswept': unswept}


async def _execute_exec_dorks(
    dork_specs: List[Dict[str, Any]],
    agent=None,
    max_pages: int = MAX_SERP_PAGES_PER_VIP,
    _dispatch=None,
) -> Dict[str, Any]:
    """Execute cohort-tagged SERP dork specs through an injectable per-page
    dispatch `(query, page) -> {'hits': [...], 'unswept': bool}`.

    Per-cohort depth: pinpoint = 1 page; discovery = loop-until-dry bounded by
    DISCOVERY_MAX_PAGES. A GLOBAL `max_pages` hard cap bounds worst-case metered
    spend per VIP scan. Fail-closed contract:
      - `_dispatch is None`                       → status 'unswept_no_provider'
      - first dispatch raises `_SerpNotConfigured`→ status 'unswept_no_provider'
      - queries blocked/broken (400 free-tier, 404/5xx, transport) and NOTHING
        swept clean                               → status 'unswept' (caller FAILs)
      - `_SerpSweepFailed` (401/402/403/429)      → propagates (caller FAILs job)
    NEVER returns `{swept:True, results:[]}` from a failed/blocked-only sweep.
    The caller (execute()) treats BOTH a raised `_SerpSweepFailed` AND a returned
    status 'unswept' as a job failure — only 'unswept_no_provider' falls through.
    """
    if _dispatch is None:
        if agent:
            agent.report_progress(
                current_operation='SERP execution skipped: no SERP provider configured',
            )
        return {'swept': False, 'status': 'unswept_no_provider', 'results': []}

    results: List[Dict[str, Any]] = []
    pages_used = 0
    swept_any = False
    unswept_any = False
    diagnostics = {'pagesUsed': 0, 'queriesRun': 0, 'unsweptQueries': 0, 'truncated': False}

    try:
        for spec in dork_specs:
            if pages_used >= max_pages:
                diagnostics['truncated'] = True
                break
            query = spec.get('query') if isinstance(spec, dict) else spec
            kind = spec.get('kind', 'discovery') if isinstance(spec, dict) else 'discovery'
            cohort = spec.get('cohort') if isinstance(spec, dict) else None
            if not query:
                continue
            per_cohort_max = PINPOINT_MAX_PAGES if kind == 'pinpoint' else DISCOVERY_MAX_PAGES
            diagnostics['queriesRun'] += 1
            page = 1
            while page <= per_cohort_max and pages_used < max_pages:
                pages_used += 1
                page_result = await _dispatch(query, page)
                if (page_result or {}).get('unswept'):
                    unswept_any = True
                    diagnostics['unsweptQueries'] += 1
                    break  # a blocked query — don't paginate it, never clean it
                swept_any = True
                hits = (page_result or {}).get('hits') or []
                new_hits = 0
                for hit in hits:
                    if not (hit or {}).get('url'):
                        continue
                    hit['_cohort'] = cohort
                    hit['_query'] = query
                    hit['_page'] = page
                    results.append(hit)
                    new_hits += 1
                # loop-until-dry: stop on pinpoint, or when a discovery page dries
                # up (no new hits) or returns a short final page.
                if kind == 'pinpoint' or new_hits == 0 or len(hits) < SERPER_RESULTS_PER_PAGE:
                    break
                page += 1
    except _SerpNotConfigured:
        if not swept_any and not results:
            if agent:
                agent.report_progress(
                    current_operation='SERP provider not configured; skipping SERP sweep',
                )
            return {'swept': False, 'status': 'unswept_no_provider', 'results': []}
        # Configured then vanished mid-sweep → treat as a scan-invalidating fail.
        raise _SerpSweepFailed('serp_not_configured_midsweep')

    diagnostics['pagesUsed'] = pages_used
    # Fail-closed: a sweep whose ONLY outcome was blocked (400) queries is NOT a
    # clean zero-findings result.
    if not swept_any and unswept_any:
        return {'swept': False, 'status': 'unswept', 'results': [], 'diagnostics': diagnostics}
    if not swept_any:
        return {'swept': False, 'status': 'unswept_no_provider', 'results': results, 'diagnostics': diagnostics}
    return {'swept': True, 'status': 'swept', 'results': results, 'diagnostics': diagnostics}


def _serp_hit_to_finding(
    brand_vip_id: str,
    hit: Dict[str, Any],
    full_name: str,
    company_name: str,
    company_domain: str,
    owned_domains: List[str],
    typosquat_domains: List[str],
    brand_tokens: List[str],
    vip_email: str = '',
) -> Optional[Dict[str, Any]]:
    """Map ONE Serper hit → the VIP-exposure finding envelope, or None when the
    host classifier suppresses it (owned/known/tracked) or no signal survives.
    Composes the HOST classifier with the existing CONTENT classifier."""
    url = (hit or {}).get('url') or ''
    if not url:
        return None
    title = _normalize_spaces((hit or {}).get('title') or '')
    snippet = _normalize_spaces((hit or {}).get('snippet') or '')
    host_class = _classify_serp_host(
        url, owned_domains, typosquat_domains, brand_tokens, full_name,
    )
    if host_class and host_class.get('action') == 'suppress':
        return None
    if host_class and host_class.get('action') == 'flag':
        exposure_type = host_class['exposureType']
        severity = host_class['severity']
        risk_score = host_class['riskScore']
        confidence = host_class['confidence']
        category = host_class.get('category')
    else:
        # No host signal → fall back to the CONTENT classifier (name/company
        # keyword match). Skip the hit entirely when neither axis fires — a raw
        # SERP hit with no brand/exec match is noise.
        platform = _detect_platform(url)
        classification = _classify_exposure(
            platform, title, snippet, url, full_name, company_name,
            company_domain, vip_email,
        )
        if not classification:
            return None
        exposure_type = classification['exposureType']
        severity = classification['severity']
        risk_score = classification['riskScore']
        confidence = classification['confidenceScore']
        category = 'CONTENT_MATCH'

    # Residence/municipal DOX is physical-safety PII (a home address in a
    # municipal meeting PDF). A residence-dork hit is elevated to HIGH ONLY when
    # there is a REAL residence signal — a municipal records/meeting portal host,
    # or a street-address / minor-variance pattern in the content. A bare news /
    # podcast / regulatory mention that merely happens to contain the word
    # "address" is NOT a DOX and must not flood HIGH; it is dropped here (generic
    # exec mentions are already covered by the exec cohort). Data-broker/known
    # hosts keep their own verdict (host classifier fired first).
    cohort = (hit or {}).get('_cohort')
    if cohort == 'residence' and category == 'CONTENT_MATCH':
        host = (urlparse(url).hostname or '').lower()
        text = f'{title} {snippet}'.lower()
        # Precise residence-DOX signals ONLY: a municipal records / meeting-portal
        # host, or municipal-property terminology (minor variance / committee of
        # adjustment / zoning ...). A bare street-address regex was tried and
        # cut — it matched COMPANY addresses on financial-industry directories
        # (wealthprofessional / mpamag), flooding false HIGHs.
        residence_signal = (
            _host_in_directory(host, _MUNICIPAL_RECORDS_HOSTS)
            or any(term in text for term in _RESIDENCE_TERMS)
        )
        if not residence_signal:
            return None  # not a real residence exposure — drop, don't HIGH-flood
        exposure_type = 'CONTACT_EXPOSURE'
        severity = 'HIGH'
        risk_score = max(risk_score, 80)
        confidence = max(confidence, 0.6)
        category = 'RESIDENCE_EXPOSURE'

    finding_hash = hashlib.sha256(
        f"{brand_vip_id}|{url}|{exposure_type}".encode('utf-8')
    ).hexdigest()
    platform = _detect_platform(url)
    # Deterministic cohort by URL (#3): the same URL surfaces under multiple
    # dorks (data_broker AND exec), so the DORK that happened to find it is a
    # non-deterministic label. When the HOST classifier fired, pin the emitted
    # cohort to the canonical value implied by hostClass; otherwise fall back to
    # the surfacing dork's cohort.
    dork_cohort = (hit or {}).get('_cohort')
    cohort = _CANONICAL_COHORT_BY_HOSTCLASS.get(category or '', dork_cohort)
    return {
        'findingHash': finding_hash,
        'platform': platform,
        'sourceName': 'Serper SERP',
        'sourceUrl': url,
        'title': title or f'SERP exposure result for {full_name}',
        'contentSnippet': snippet[:1500],
        'exposureType': exposure_type,
        'severity': severity,
        'riskScore': risk_score,
        'confidenceScore': round(float(confidence), 2),
        'status': 'NEW',
        'matchedKeywords': [t for t in [full_name, company_name or company_domain] if t],
        'discoveredAt': datetime.now(timezone.utc).isoformat(),
        'metadata': {
            'engine': 'serper-search',
            'cohort': cohort,
            'dorkCohort': dork_cohort,
            'query': (hit or {}).get('_query'),
            'page': (hit or {}).get('_page'),
            'hostClass': category,
        },
    }


def _slug_matches_name(url: str, full_name: str) -> bool:
    lowered_url = (url or '').lower()
    parts = [part for part in re.split(r'[\s\-_.]+', full_name.lower()) if len(part) > 1]
    return bool(parts) and all(part in lowered_url for part in parts[:2])


def _canonicalize_name_token(token: str) -> str:
    """Map a nickname to its canonical form (mike→michael) for slug matching;
    identity for anything not in the equivalence table."""
    return _NICKNAME_EQUIV.get(token, token)


# Data-broker COMPANY / directory page path markers — brand-level pages
# (company profiles, people-at-company lists) that are NOT a single-person
# attribution, so the wrong-person slug check does NOT apply to them.
_DATA_BROKER_COMPANY_MARKERS = ('/c/', '/companies/', '/company/', '/pic/',
                                '/list/', '/directory/', '/org/', '/team/')


def _data_broker_person_slug_matches(url: str, full_name: str) -> Optional[bool]:
    """For a data-broker hit, decide whether the URL is a PERSON page and, if so,
    whether its person slug plausibly matches `full_name` (nickname-aware).

    Returns:
      - None  → not a person page (company/directory page, or no name given) →
                caller keeps the brand-level data-broker verdict.
      - True  → a person page whose slug matches the VIP → keep the verdict.
      - False → a person page that is clearly a DIFFERENT person (homonym) →
                caller SUPPRESSES the hit (the #2 wrong-person FP class).
    """
    name_parts = [
        _canonicalize_name_token(p)
        for p in re.split(r'[\s\-_.]+', (full_name or '').lower())
        if len(p) > 1
    ]
    if not name_parts:
        return None  # no VIP name to verify against → keep brand-level verdict
    path = (urlparse(url or '').path or '').lower()
    if not path or path == '/':
        return None  # host root, not a person page
    if any(marker in path for marker in _DATA_BROKER_COMPANY_MARKERS):
        return None  # company/directory page → brand-level, not per-person
    # Person-slug WORD tokens from the whole path (…/p/<Name>/<id>,
    # …/<name>-email). Drop numeric ids/hashes and data-broker suffixes that
    # aren't part of the name so an opaque id doesn't look like a wrong person.
    path_stripped = re.sub(r'\.(html?|php|aspx?)$', '', path)
    slug_tokens = {
        _canonicalize_name_token(t)
        for t in re.split(r'[\s\-_./]+', path_stripped)
        if len(t) > 1 and not t.isdigit()
        and t not in {'email', 'phone', 'contact', 'p', 'profile', 'people', 'person'}
    }
    if not slug_tokens:
        return None  # opaque slug (numeric id, hash) → can't disprove → keep
    first, last = name_parts[0], name_parts[-1]
    # Match requires BOTH the VIP first and last name to appear in the slug —
    # a same-surname-different-first (or vice-versa) homonym is suppressed.
    return first in slug_tokens and last in slug_tokens


def _company_tokens(company_name: str, company_domain: str) -> List[str]:
    tokens: List[str] = []
    if company_name:
        tokens.extend(
            [token for token in re.split(r'[\s\-_.]+', company_name.lower()) if len(token) > 2]
        )
    if company_domain:
        root = company_domain.lower().replace('https://', '').replace('http://', '').strip('/')
        root = root.split('/')[0]
        root = root.split(':')[0]
        pieces = [
            piece for piece in root.split('.') if piece and piece not in {'com', 'net', 'org', 'io', 'co'}
        ]
        tokens.extend(pieces[:2])
    return list(dict.fromkeys(tokens))


def _detect_platform(url: str) -> str:
    hostname = (urlparse(url or '').hostname or '').lower()
    for domain, platform in PLATFORM_MAP.items():
        if hostname == domain or hostname.endswith(f'.{domain}'):
            return platform
    return 'WEB'


def _normalize_url(value: str) -> str:
    candidate = _normalize_spaces(value)
    if not candidate:
        return ''
    if not candidate.startswith(('http://', 'https://')):
        candidate = f'https://{candidate}'
    parsed = urlparse(candidate)
    if not parsed.hostname:
        return ''
    return candidate


def _extract_profile_urls(parameters: Dict[str, Any]) -> List[str]:
    urls: List[str] = []
    for key in ['linkedinUrl', 'xUrl', 'twitterUrl', 'instagramUrl', 'websiteUrl']:
        value = parameters.get(key)
        if isinstance(value, str):
            urls.append(value)

    profile_urls = parameters.get('profileUrls')
    if isinstance(profile_urls, list):
        urls.extend([str(value) for value in profile_urls])
    elif isinstance(profile_urls, str):
        urls.extend(profile_urls.split(','))

    normalized = [_normalize_url(value) for value in urls]
    return list(dict.fromkeys([url for url in normalized if url]))


# <title> and <meta> live in <head>; bound the regex scan to the head region so
# the greedy attribute classes can't backtrack across a hostile 200KB body.
_HEAD_SCAN_LIMIT = 65536


def _extract_title(html: str) -> str:
    match = re.search(r'<title[^>]*>(.*?)</title>', (html or '')[:_HEAD_SCAN_LIMIT], re.IGNORECASE | re.DOTALL)
    if not match:
        return ''
    return _normalize_spaces(unescape(re.sub(r'<[^>]+>', '', match.group(1))))


def _extract_meta_description(html: str) -> str:
    """Return the <meta name=description> / og:description content, if any."""
    if not html:
        return ''
    html = html[:_HEAD_SCAN_LIMIT]
    for pattern in (
        # name="description" / property="og:description" in either attribute order
        r'<meta[^>]+(?:name|property)\s*=\s*["\'](?:description|og:description)["\'][^>]*\bcontent\s*=\s*["\']([^"\']*)["\']',
        r'<meta[^>]+\bcontent\s*=\s*["\']([^"\']*)["\'][^>]*(?:name|property)\s*=\s*["\'](?:description|og:description)["\']',
    ):
        match = re.search(pattern, html, re.IGNORECASE | re.DOTALL)
        if match:
            text = _normalize_spaces(unescape(match.group(1)))
            if text:
                return text
    return ''


def _extract_text_excerpt(html: str, limit: int) -> str:
    """Strip scripts/styles/tags, decode entities, collapse whitespace, and
    return the first `limit` chars of clean visible text. Stdlib-only; never
    throws — returns '' on empty/garbled input."""
    if not html:
        return ''
    try:
        cleaned = re.sub(
            r'<(script|style|noscript)\b[^>]*>.*?</\1>',
            ' ',
            html,
            flags=re.IGNORECASE | re.DOTALL,
        )
        # Drop HTML comments, then all remaining tags.
        cleaned = re.sub(r'<!--.*?-->', ' ', cleaned, flags=re.DOTALL)
        cleaned = re.sub(r'<[^>]+>', ' ', cleaned)
        cleaned = unescape(cleaned)
        cleaned = _normalize_spaces(cleaned)
    except Exception:
        return ''
    if limit and limit > 0:
        return cleaned[:limit]
    return cleaned


# Markers that indicate an unauthenticated GET hit a login/consent/block wall
# rather than real profile content (LinkedIn/X/Instagram routinely do this).
#
# Multi-word phrase markers are safe as substring matches — they cannot
# collide with ordinary words. 'access denied' / '403 forbidden' cover real
# block walls without colliding with benign text like "Forbidden City", so the
# bare word 'forbidden' is dropped. The remaining single-word markers
# ('login'/'logon'/'captcha') were previously bare substrings that mis-fired on
# real content ('login' matched "BuabLogin") and suppressed genuine profile
# snippets; they are now matched with word boundaries via a compiled regex.
_LOGIN_WALL_PHRASE_MARKERS = (
    'sign in', 'sign up', 'log in',
    'create an account', 'join now', 'continue with',
    'enable javascript', 'please enable js', 'verify you are human',
    'are you a robot', 'access denied', '403 forbidden',
    'rate limit', 'too many requests', 'page not found',
    'see posts, photos and more', 'something went wrong',
)

_LOGIN_WALL_WORD_RE = re.compile(
    r'\b(?:login|logon|captcha)\b',
    re.IGNORECASE,
)


def _looks_like_login_wall(text: str) -> bool:
    """Heuristic: empty / essentially-no-content, or carries auth/block markers.

    The length floor is deliberately low (24): a short-but-real snippet like
    "Reported transactions: 12,000 shares" is legitimate content, not a wall.
    Walls are caught by the marker list, not by being merely terse."""
    snippet = (text or '').strip()
    if len(snippet) < 24:
        return True
    lowered = snippet.lower()
    if any(marker in lowered for marker in _LOGIN_WALL_PHRASE_MARKERS):
        return True
    return bool(_LOGIN_WALL_WORD_RE.search(snippet))


def _strip_html(value: str) -> str:
    return _normalize_spaces(unescape(re.sub(r'<[^>]+>', ' ', value or '')))


def _unwrap_search_url(url: str) -> str:
    candidate = unescape(url or '').strip()
    if candidate.startswith('//'):
        candidate = f'https:{candidate}'

    parsed = urlparse(candidate)
    if parsed.hostname and parsed.hostname.endswith('duckduckgo.com') and parsed.path.startswith('/l/'):
        target = parse_qs(parsed.query).get('uddg', [''])[0]
        if target:
            return unquote(target)

    return candidate


def _parse_duckduckgo_html(html: str, max_results: int) -> List[Dict[str, str]]:
    """Parse DuckDuckGo HTML-endpoint results into {url, title, content}.

    Robust to DDG's nested-div markup: rather than carving fixed result "blocks"
    (the previous `</div></div>` boundary truncated BEFORE the snippet, so
    `content` came back empty), we locate each result link and take its snippet
    from the segment running up to the NEXT result link. The snippet terminator
    is tolerant of </a>, </div>, or </span> (DDG has used each)."""
    html = html or ''
    results: List[Dict[str, str]] = []
    links = list(re.finditer(
        r'<a[^>]+class="[^"]*result__a[^"]*"[^>]*href="([^"]+)"[^>]*>(.*?)</a>',
        html,
        flags=re.IGNORECASE | re.DOTALL,
    ))
    for i, link in enumerate(links):
        seg_start = link.end()
        seg_end = links[i + 1].start() if i + 1 < len(links) else len(html)
        segment = html[seg_start:seg_end]
        snippet_match = re.search(
            r'class="[^"]*result__snippet[^"]*"[^>]*>(.*?)</(?:a|div|span)>',
            segment,
            flags=re.IGNORECASE | re.DOTALL,
        )
        url = _unwrap_search_url(link.group(1))
        if not url:
            continue
        results.append({
            'url': url,
            'title': _strip_html(link.group(2)),
            'content': _strip_html(snippet_match.group(1) if snippet_match else ''),
        })
        if len(results) >= max_results:
            break

    return results


def _profile_finding(
    brand_vip_id: str,
    profile_url: str,
    full_name: str,
    company_name: str,
    company_domain: str,
    title: str,
    validation: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    platform = _detect_platform(profile_url)
    finding_hash = hashlib.sha256(
        f"{brand_vip_id}|{profile_url}|known-profile".encode('utf-8')
    ).hexdigest()
    validated = bool(validation and validation.get('reachable'))
    page_title = validation.get('title') if validation else ''
    source_name = platform.title() if platform != 'WEB' else 'Known Web Profile'

    # Prefer a real excerpt extracted from the fetched body: meta-description
    # first, then visible-text excerpt. Social profiles frequently return a
    # login/consent wall to unauthenticated GETs — when the extracted content
    # is empty or looks like such a wall, fall back to an honest, concise
    # snippet instead of fabricating page content.
    meta_description = (validation or {}).get('metaDescription') or ''
    text_excerpt = (validation or {}).get('textExcerpt') or ''
    content_source = ''
    if meta_description and not _looks_like_login_wall(meta_description):
        content_snippet = meta_description
        content_source = 'metaDescription'
    elif text_excerpt and not _looks_like_login_wall(text_excerpt):
        content_snippet = text_excerpt
        content_source = 'textExcerpt'
    elif validated:
        content_snippet = (
            f'Profile page for {full_name} is reachable; full content requires '
            f'an authenticated capture (unauthenticated request returned a '
            f'login wall or minimal markup).'
        )
        content_source = 'login-wall-fallback'
    else:
        content_snippet = (
            f'{full_name} has a registered public profile URL that can be tracked '
            f'for impersonation, account changes, and exposure signals.'
        )
        content_source = 'unreachable-fallback'

    excerpt_chars = len(content_snippet)

    return {
        'findingHash': finding_hash,
        'platform': platform,
        'sourceName': source_name,
        'sourceUrl': profile_url,
        'title': page_title or f'Known {source_name} profile for {full_name}',
        'contentSnippet': content_snippet,
        'exposureType': 'SOCIAL_PROFILE' if platform != 'WEB' else 'PUBLIC_PROFILE',
        'severity': 'LOW',
        'riskScore': 30 if validated else 24,
        'confidenceScore': 0.99 if validated else 0.92,
        'status': 'NEW',
        'matchedKeywords': [token for token in [full_name, company_name or company_domain, title] if token],
        'discoveredAt': datetime.now(timezone.utc).isoformat(),
        'metadata': {
            'engine': 'direct-profile',
            'seededFromInput': True,
            'validated': validated,
            'httpStatus': validation.get('httpStatus') if validation else None,
            'finalUrl': validation.get('finalUrl') if validation else profile_url,
            'contentType': validation.get('contentType') if validation else None,
            'metaDescription': meta_description or None,
            'excerptChars': excerpt_chars,
            'contentSource': content_source,
        },
    }


async def _fetch_and_extract(session, url: str, excerpt_limit: int = 1500) -> Dict[str, Any]:
    """GET `url` and pull title / meta-description / text-excerpt from HTML.

    Content-type-guarded (non-HTML bodies like PDF/JSON/image are NOT regex-fed),
    body capped at 200KB, never throws. Used by BOTH the seeded-profile path and
    the public-search path so a discovered page (e.g. a data-broker / news page
    found via search) carries its real content, not just a link + blurb."""
    try:
        async with session.get(url, allow_redirects=True) as resp:
            content_type = (resp.headers.get('Content-Type') or '').lower()
            is_markup = 'html' in content_type or 'xml' in content_type or not content_type
            capped_body = (await resp.text(errors='ignore'))[:200000] if is_markup else ''
            return {
                'reachable': 200 <= resp.status < 400,
                'httpStatus': resp.status,
                'finalUrl': str(resp.url),
                'contentType': content_type or None,
                'title': _extract_title(capped_body),
                'metaDescription': _extract_meta_description(capped_body),
                'textExcerpt': _extract_text_excerpt(capped_body, excerpt_limit),
            }
    except Exception as exc:
        return {
            'reachable': False,
            'error': str(exc),
            'finalUrl': url,
            'title': '',
            'metaDescription': '',
            'textExcerpt': '',
        }


def _best_extracted_content(extracted: Dict[str, Any], fallback: str = '') -> tuple:
    """Pick the best human-readable content from a `_fetch_and_extract` result:
    meta-description, else text excerpt, else the supplied fallback (e.g. the
    search-result blurb). Returns (content, source_label)."""
    meta = (extracted.get('metaDescription') or '').strip()
    if meta and not _looks_like_login_wall(meta):
        return meta, 'metaDescription'
    excerpt = (extracted.get('textExcerpt') or '').strip()
    if excerpt and not _looks_like_login_wall(excerpt):
        return excerpt, 'textExcerpt'
    fb = (fallback or '').strip()
    if fb:
        return fb, 'searchBlurb'
    return '', 'none'


# Unambiguous PII-dump leak words: on a page these have essentially no benign
# meaning, so exact-VIP-name proximity is enough to corroborate. The ambiguous
# common-English words ('breach'/'leak'/'exposed') are NOT here — they need an
# email / @company-domain identifier to earn HIGH ('levee breaches', roof
# 'leak', a 'rule breach' are all benign incidental usages).
_UNAMBIGUOUS_LEAK_WORDS = ('dox', 'doxx', 'combolist', 'pastebin', 'paste')


def _leak_word_corroborated(
    haystack: str,
    full_name: str,
    company_domain: str,
    vip_email: str,
) -> bool:
    """#1 — a leak/breach/dox word only earns HIGH CONTACT_EXPOSURE when the page
    ACTUALLY ties the leak to THIS VIP, not merely mentions a leak word somewhere
    ('levee breaches', a roof 'leak', a Shakespeare 'breach', a 'rule breach').

    Corroboration (any ONE):
      - the VIP's exact email appears in the text, OR
      - an @company-domain mailbox appears in the text (BEC-value convention), OR
      - an UNAMBIGUOUS PII-dump word (dox/combolist/pastebin/paste) appears
        within a small token window of the exact VIP name (a page discussing the
        VIP AND a credential dump in the same breath).
    Mirrors the residence-cohort corroboration gate in `_serp_hit_to_finding`.
    """
    email = _normalize_spaces(vip_email or '').lower().lstrip('@')
    if email and email in haystack:
        return True
    dom = _normalize_spaces(company_domain or '').lower().lstrip('@').split('/')[0].split(':')[0]
    if dom and f'@{dom}' in haystack:
        return True
    name = _normalize_spaces(full_name or '').lower()
    if not name or name not in haystack:
        return False
    # Name / unambiguous-dump-word proximity: the exact name and a PII-dump word
    # must fall within a small token window (co-referential), not merely both
    # present somewhere on a long page.
    tokens = haystack.split()
    name_first = name.split()[0]
    WINDOW = 10
    name_positions = [i for i, t in enumerate(tokens) if name_first in t]
    leak_positions = [
        i for i, t in enumerate(tokens)
        if any(lw in t for lw in _UNAMBIGUOUS_LEAK_WORDS)
    ]
    return any(
        abs(ni - li) <= WINDOW
        for ni in name_positions
        for li in leak_positions
    )


def _classify_exposure(
    platform: str,
    title: str,
    snippet: str,
    url: str,
    full_name: str,
    company_name: str,
    company_domain: str,
    vip_email: str = '',
) -> Dict[str, Any]:
    # Identity matching may use the URL — a name/company legitimately lives in a
    # slug. Exposure CLASSIFICATION must NOT: a benign URL containing
    # 'paste'/'exposed'/'fake' (e.g. /exposed-beams-listing) would otherwise
    # over-fire HIGH severity. So the keyword scans below run against page
    # CONTENT (title + snippet) only, never the URL.
    identity_haystack = _normalize_spaces(f"{title} {snippet} {url}").lower()
    haystack = _normalize_spaces(f"{title} {snippet}").lower()
    exact_name = full_name.lower() in identity_haystack
    company_match = False
    for token in _company_tokens(company_name, company_domain):
        if token in identity_haystack:
            company_match = True
            break

    if not exact_name and not _slug_matches_name(url, full_name):
        return {}

    # #1 — a public mention of a public-company exec on a regulator / news /
    # gov / press / podcast host is NOT a contact-PII exposure. Route it to LOW
    # PUBLIC_MENTION and skip the leak/contact/targeting escalation entirely.
    host = (urlparse(url or '').hostname or '').lower()
    on_public_record_host = _host_in_directory(host, _PUBLIC_RECORD_HOSTS)

    exposure_type = 'SOCIAL_MENTION' if platform != 'WEB' else 'PUBLIC_MENTION'
    severity = 'LOW'
    risk_score = 32
    confidence = 0.45

    if platform in SOCIAL_PROFILE_PATTERNS:
        if any(re.search(pattern, urlparse(url).path or '', re.IGNORECASE) for pattern in SOCIAL_PROFILE_PATTERNS[platform]):
            exposure_type = 'SOCIAL_PROFILE'
            severity = 'LOW'
            risk_score = 28
            confidence = 0.62

    for keyword in EXPOSURE_KEYWORDS['IMPERSONATION']:
        if keyword in haystack:
            exposure_type = 'IMPERSONATION'
            severity = 'HIGH'
            risk_score = 82
            confidence = 0.88
            break

    # Public-record-host mentions stay LOW PUBLIC_MENTION — the leak/contact/
    # targeting escalation below is suppressed for them (a regulator bio naming
    # the exec, a news 'breach' quote, a conference speaker page).
    if exposure_type not in {'IMPERSONATION'} and not on_public_record_host:
        has_leak_word = any(
            keyword in haystack for keyword in EXPOSURE_KEYWORDS['CONTACT_EXPOSURE_LEAK']
        )
        has_contact_noun = any(
            keyword in haystack for keyword in EXPOSURE_KEYWORDS['CONTACT_NOUN']
        )
        if has_leak_word:
            # #1 — a leak word only earns HIGH when it is CORROBORATED as tied to
            # THIS VIP (email / @company-domain / name-within-window) AND the
            # exact VIP name matched. Otherwise the leak word is incidental
            # ('levee breaches', a roof 'leak', a 'rule breach') → cap at LOW
            # PUBLIC_MENTION, never HIGH.
            if exact_name and _leak_word_corroborated(
                haystack, full_name, company_domain, vip_email,
            ):
                exposure_type = 'CONTACT_EXPOSURE'
                severity = 'HIGH'
                risk_score = 78
                confidence = 0.8
            elif has_contact_noun:
                # Uncorroborated leak word but a bare contact noun is present:
                # a contactable page, not a proven leak → MEDIUM (unchanged for
                # the contact-noun class).
                exposure_type = 'CONTACT_EXPOSURE'
                severity = 'MEDIUM'
                risk_score = 52
                confidence = 0.55
            # else: uncorroborated leak word, no contact noun → leave LOW
            # PUBLIC_MENTION (the benign 'breach'/'leak' incidental-word class).
        elif has_contact_noun:
            # A bare contact noun with no leak word: a "Contact Us" page or a
            # bio that lists an email is not a HIGH exposure. Cap at MEDIUM.
            exposure_type = 'CONTACT_EXPOSURE'
            severity = 'MEDIUM'
            risk_score = 52
            confidence = 0.55

    if exposure_type not in {'IMPERSONATION', 'CONTACT_EXPOSURE'} and not on_public_record_host:
        for keyword in EXPOSURE_KEYWORDS['TARGETING_SIGNAL']:
            if keyword in haystack:
                exposure_type = 'TARGETING_SIGNAL'
                severity = 'MEDIUM' if platform == 'WEB' else 'HIGH'
                risk_score = 72 if platform != 'WEB' else 64
                confidence = 0.74
                break

    if company_match:
        confidence += 0.12
        risk_score += 8

    if platform != 'WEB':
        confidence += 0.08

    return {
        'exposureType': exposure_type,
        'severity': severity,
        'riskScore': min(risk_score, 95),
        'confidenceScore': round(min(confidence, 0.99), 2),
        'companyMatched': company_match,
        'exactNameMatched': exact_name,
    }


class BrandMonitorVipExposureTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "brand:monitor_vip_exposure"

    @property
    def description(self) -> str:
        return (
            "Search public web and social profile results for a registered VIP to find "
            "profiles, mentions, targeting signals, and impersonation exposure."
        )

    @property
    def schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "brandVipId": {
                    "type": "string",
                    "description": "Registered VIP identifier",
                },
                "brandMonitorId": {
                    "type": "string",
                    "description": "Brand monitor identifier",
                },
                "companyName": {
                    "type": "string",
                    "description": "Company name for contextual matching",
                },
                "companyDomain": {
                    "type": "string",
                    "description": "Company domain for contextual matching",
                },
                "fullName": {
                    "type": "string",
                    "description": "VIP full name",
                },
                "title": {
                    "type": "string",
                    "description": "VIP title or role",
                },
                "email": {
                    "type": "string",
                    "description": "VIP email if known",
                },
                "linkedinUrl": {
                    "type": "string",
                    "description": "Known LinkedIn URL if already captured",
                },
                "profileUrls": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Known public profile URLs such as LinkedIn, X, Instagram, or personal bio pages",
                },
                "ownedDomains": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Brand-owned/defensive domains. The SERP host classifier suppresses hits on these (never flags an owned property as a combosquat).",
                },
                "typosquatDomains": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Domains already tracked by the typosquat engine. Suppressed from NEW-combosquat flagging so the SERP sweep does not double-surface known squats.",
                },
                "maxResults": {
                    "type": "integer",
                    "description": "Maximum number of findings to return",
                    "default": 15,
                },
            },
            "required": ["brandVipId", "brandMonitorId", "fullName"],
        }

    @property
    def metadata(self) -> Dict[str, Any]:
        return {
            "category": "brand",
            "phase": 4,
            "domain": ["osint", "drp"],
            "input_type": ["person"],
            "output_type": ["vip_exposures"],
            "chainable_after": ["brand:discover_vips"],
            "chainable_before": [],
        }

    async def execute(self, parameters: Dict[str, Any]) -> Any:
        agent = parameters.get('_agent')
        brand_vip_id = parameters.get('brandVipId')
        brand_monitor_id = parameters.get('brandMonitorId')
        full_name = _normalize_spaces(parameters.get('fullName', ''))
        company_name = _normalize_spaces(parameters.get('companyName', ''))
        company_domain = _normalize_spaces(parameters.get('companyDomain', ''))
        title = _normalize_spaces(parameters.get('title', ''))
        vip_email = _normalize_spaces(parameters.get('email', ''))
        profile_urls = _extract_profile_urls(parameters)
        max_results = int(parameters.get('maxResults', 15) or 15)

        # #981 — owned-domain + tracked-typosquat cohorts for the SERP host
        # classifier (combosquat cross-reference). Null-safe: absent/empty threads
        # cleanly (the classifier degrades to KNOWN_DIRECTORY suppression only).
        def _coerce_domains(value: Any) -> List[str]:
            if isinstance(value, str):
                value = [value]
            if not isinstance(value, list):
                return []
            return [str(d).strip().lower() for d in value if d and str(d).strip()]

        owned_domains = _coerce_domains(parameters.get('ownedDomains'))
        typosquat_domains = _coerce_domains(parameters.get('typosquatDomains'))

        # 2026-05-16 — SearxNG decommissioned. The block that used to query
        # SEARXNG_URL for VIP-exposure mentions has been removed; the
        # direct-profile-check path + public-search path (handled below)
        # remain as the only sources for VIP exposure findings.

        if not brand_vip_id or not brand_monitor_id or not full_name:
            return {
                'success': False,
                'error': 'brandVipId, brandMonitorId, and fullName are required',
                'output': {
                    'brandVipId': brand_vip_id,
                    'brandMonitorId': brand_monitor_id,
                    'findings': [],
                    'queriesRun': 0,
                },
            }

        company_hint = company_name or company_domain

        findings: List[Dict[str, Any]] = []
        seen_hashes = set()
        # DDG HTML scraping is OFF by default (explicit opt-in only) and is now
        # the FALLBACK behind the sanctioned SERP_SEARCH (Serper.dev) sweep
        # above (#981). It is an uncredentialed generic-search scrape (ToS/ban
        # exposure) — never a metered vendor — so it stays disabled unless
        # VIP_EXPOSURE_PUBLIC_SEARCH=true AND the SERP sweep did not succeed.
        # Brave/SerpAPI/Tavily remain deferred (2026-05-15 scope); Serper is the
        # admitted SERP vendor. The extraction code below is kept intact.
        public_search_configured = (
            os.environ.get('VIP_EXPOSURE_PUBLIC_SEARCH', 'false').lower() == 'true'
        )
        search_diagnostics = {
            'publicSearchConfigured': public_search_configured,
            'publicSearchQueriesRun': 0,
            'publicSearchResultsSeen': 0,
            'publicSearchFailedQueries': 0,
        }

        # The DDG public-search path builds its own query list. Compute it up
        # front so progress + the result envelope can report the REAL number of
        # search queries that will actually run (no dead/imaginary query count).
        public_queries: List[str] = []
        if public_search_configured:
            public_queries = list(dict.fromkeys([
                query for query in (
                    f'{full_name} {company_hint}'.strip(),
                    f'{full_name} {company_hint} linkedin'.strip(),
                    f'{full_name} {company_hint} email phone'.strip(),
                ) if query
            ]))[:3]

        if agent:
            agent.report_progress(
                current_operation=f"Monitoring exposure for {full_name}",
                current_target=company_hint or full_name,
                items_processed=0,
                total_items=len(profile_urls) + len(public_queries),
            )

        timeout = aiohttp.ClientTimeout(total=20)
        async with aiohttp.ClientSession(timeout=timeout, headers=DEFAULT_HEADERS) as session:
            for profile_url in profile_urls:
                # Content-type-guarded fetch + HTML extraction (shared with the
                # public-search path below).
                validation = await _fetch_and_extract(session, profile_url)

                finding = _profile_finding(
                    brand_vip_id,
                    profile_url,
                    full_name,
                    company_name,
                    company_domain,
                    title,
                    validation,
                )
                seen_hashes.add(finding['findingHash'])
                findings.append(finding)

            # #981 — LIVE SERP sweep (Serper.dev) via the sanctioned SERP_SEARCH
            # provider. This is the PRIMARY exposure source when configured; the
            # DDG path below stays the independently-gated opt-in fallback and
            # runs ONLY when the SERP sweep did NOT succeed (never double-bills a
            # VIP). Fail-closed: a CONFIGURED-but-broken sweep FAILS the job
            # rather than returning a false clean.
            serp_swept = False
            serp_failed = False
            serp_error: Optional[str] = None
            serp_specs = _build_serp_dork_cohorts(
                full_name, company_name, company_domain, owned_domains,
            )
            if serp_specs:
                async def _serp_dispatch(q: str, p: int) -> Dict[str, Any]:
                    return await _dispatch_serper(q, p, session)

                try:
                    serp_out = await _execute_exec_dorks(
                        serp_specs, agent=agent, _dispatch=_serp_dispatch,
                    )
                except _SerpSweepFailed as exc:
                    serp_failed = True
                    serp_error = str(exc)
                    serp_out = {'swept': False, 'status': 'unswept', 'results': []}

                serp_status = serp_out.get('status')
                search_diagnostics['serp'] = {
                    'status': serp_status,
                    'failed': serp_failed,
                    **(serp_out.get('diagnostics') or {}),
                }
                if serp_out.get('swept'):
                    serp_swept = True
                    brand_tokens = _company_tokens(company_name, company_domain)
                    for hit in serp_out.get('results') or []:
                        finding = _serp_hit_to_finding(
                            brand_vip_id, hit, full_name, company_name,
                            company_domain, owned_domains, typosquat_domains,
                            brand_tokens, vip_email,
                        )
                        if not finding or finding['findingHash'] in seen_hashes:
                            continue
                        seen_hashes.add(finding['findingHash'])
                        findings.append(finding)
                elif serp_status == 'unswept':
                    # SERP was configured but could NOT actually sweep (every page
                    # blocked/broken — free-tier 400, persistent 5xx, transport).
                    # Fail-closed: this must NOT be reported as a clean scan.
                    # ('unswept_no_provider' means not configured → fall through.)
                    serp_failed = True
                    serp_error = serp_error or 'serp_unswept'

            # DDG fallback: only when SERP did NOT sweep (fail-closed provider not
            # configured, or the opt-in stopgap explicitly enabled and SERP off).
            if public_queries and not serp_swept:
                # Budget for fetching discovered result pages (to extract real
                # content vs. just the DDG blurb). Bounded so a query with many
                # hits can't fan out unbounded fetches / latency.
                pages_fetched = 0
                max_page_fetches = 8
                # B11 — DDG ban-avoidance hardening. The 0.35s inter-query sleep
                # used previously was below DDG's empirical anti-bot threshold;
                # we now jitter 2–5s between requests. DDG is intentionally NOT
                # routed through `checkout_provider()` because it is an
                # uncredentialed HTML scrape; the DRP vendor scope (locked
                # 2026-05-15 in feedback_drp_vendor_scope.md) admits only
                # HIKER_API / SCRAPECREATORS / TWITTERAPI_IO. Adding
                # DUCKDUCKGO_SEARCH to the IntegrationProvider enum would
                # require schema migration + Integration row + plan quota and
                # contradicts the "no new vendors" rule.
                for query in public_queries:
                    try:
                        search_diagnostics['publicSearchQueriesRun'] += 1
                        async with session.get(
                            'https://html.duckduckgo.com/html/',
                            params={'q': query},
                        ) as resp:
                            # Honor Retry-After on 429 / 202 (DDG sometimes
                            # returns a soft-rate-limit 202 with the same
                            # header semantics as 429). Cap the wait at 10s
                            # so a malicious / runaway header can't pin us.
                            if resp.status in (202, 429):
                                retry_after_header = resp.headers.get('Retry-After')
                                wait_s = 5.0
                                if retry_after_header:
                                    try:
                                        wait_s = min(float(retry_after_header), 10.0)
                                    except (ValueError, TypeError):
                                        pass
                                search_diagnostics['publicSearchFailedQueries'] += 1
                                if agent:
                                    agent.append_output(
                                        f"[VipExposure] DDG rate-limit HTTP {resp.status} "
                                        f"on query '{query}', backing off {wait_s:.1f}s"
                                    )
                                await asyncio.sleep(wait_s)
                                continue
                            if resp.status != 200:
                                search_diagnostics['publicSearchFailedQueries'] += 1
                                continue
                            # Cap the DDG body before parsing (parity with the
                            # 200KB profile-body cap) so a pathological page
                            # can't pin the regex parser.
                            html = (await resp.text(errors='ignore'))[:500000]
                    except Exception as exc:
                        search_diagnostics['publicSearchFailedQueries'] += 1
                        if agent:
                            agent.append_output(f"[VipExposure] Public search failed for query '{query}': {exc}")
                        continue

                    public_results = _parse_duckduckgo_html(html, 8)
                    search_diagnostics['publicSearchResultsSeen'] += len(public_results)
                    for item in public_results:
                        source_url = item.get('url', '') or ''
                        title_text = item.get('title', '') or ''
                        snippet = item.get('content', '') or ''
                        platform = _detect_platform(source_url)
                        classification = _classify_exposure(
                            platform,
                            title_text,
                            snippet,
                            source_url,
                            full_name,
                            company_name,
                            company_domain,
                            vip_email,
                        )
                        if not classification:
                            continue

                        finding_hash = hashlib.sha256(
                            f"{brand_vip_id}|{source_url}|{classification['exposureType']}".encode('utf-8')
                        ).hexdigest()
                        if finding_hash in seen_hashes:
                            continue
                        seen_hashes.add(finding_hash)

                        # Fetch the DISCOVERED page and extract its real content
                        # — the DDG result blurb is frequently empty/thin (that's
                        # the "Public Web Search finding shows only a link" gap).
                        # Falls back to the blurb, then to nothing. Bounded by the
                        # per-run fetch budget. Same uncredentialed direct GET as
                        # the profile path (no new vendor).
                        content = snippet
                        content_source = 'searchBlurb' if snippet else 'none'
                        page_meta: Dict[str, Any] = {}
                        if pages_fetched < max_page_fetches:
                            pages_fetched += 1
                            extracted = await _fetch_and_extract(session, source_url)
                            content, content_source = _best_extracted_content(extracted, snippet)
                            page_meta = {
                                'pageHttpStatus': extracted.get('httpStatus'),
                                'pageContentType': extracted.get('contentType'),
                                'pageReachable': extracted.get('reachable'),
                            }

                        findings.append({
                            'findingHash': finding_hash,
                            'platform': platform,
                            'sourceName': platform.title() if platform != 'WEB' else 'Public Web Search',
                            'sourceUrl': source_url,
                            'title': title_text or f'Public result for {full_name}',
                            'contentSnippet': content[:1500],
                            'exposureType': classification['exposureType'],
                            'severity': classification['severity'],
                            'riskScore': classification['riskScore'],
                            'confidenceScore': classification['confidenceScore'],
                            'status': 'NEW',
                            'matchedKeywords': [token for token in [full_name, company_name or company_domain, title] if token],
                            'discoveredAt': datetime.now(timezone.utc).isoformat(),
                            'metadata': {
                                'query': query,
                                'companyMatched': classification['companyMatched'],
                                'exactNameMatched': classification['exactNameMatched'],
                                'engine': 'duckduckgo-html',
                                'contentSource': content_source,
                                # Full extracted/blurb content (capped at 4000 so
                                # a pathological page can't bloat the row); the
                                # 1500-char contentSnippet is the display copy.
                                'fullContent': content[:4000],
                                'excerptChars': len(content[:1500]),
                                **page_meta,
                            },
                        })

                    # Jittered inter-query backoff (2–5s) — stays below DDG's
                    # empirical anti-bot trigger while still making forward
                    # progress on the 3-query budget.
                    await asyncio.sleep(random.uniform(2.0, 5.0))

        # Always retain the reliable seeded profile findings regardless of the
        # cap — sorting by (riskScore, confidence) desc could otherwise drop
        # them under a flood of high-risk search hits. Fill the remaining slots
        # with the top search findings.
        seeded = [
            finding for finding in findings
            if (finding.get('metadata') or {}).get('seededFromInput') is True
        ]
        searched = [
            finding for finding in findings
            if (finding.get('metadata') or {}).get('seededFromInput') is not True
        ]
        searched.sort(key=lambda item: (item['riskScore'], item['confidenceScore']), reverse=True)
        remaining_slots = max(max_results - len(seeded), 0)
        findings = seeded + searched[:remaining_slots]

        # queriesRun reports the REAL number of public searches that ran (the
        # DDG public-search path is the only query source after SearxNG was
        # decommissioned). No imaginary/dead query count.
        queries_run = search_diagnostics['publicSearchQueriesRun']

        if agent:
            agent.append_output(
                f"[VipExposure] {full_name}: collected {len(findings)} finding(s) "
                f"from {queries_run} public search query(ies)"
            )

        # #981 FAIL-CLOSED: a CONFIGURED SERP provider that broke mid-sweep (401 /
        # quota / cost-breaker) invalidates the exposure sweep. Ingestion reads
        # ONLY `output.findings`, so returning success:True with [] would be
        # indexed as a false "clean" result. Unless a fallback (DDG) actually
        # swept, FAIL the job so it is honestly retried, never reported clean.
        ddg_swept = (
            search_diagnostics['publicSearchQueriesRun']
            - search_diagnostics['publicSearchFailedQueries']
        ) > 0
        if serp_failed and not ddg_swept:
            # Fail-closed on the SERP portion, but PRESERVE the independent
            # profile-check findings already collected (seeded from input,
            # orthogonal to the SERP sweep) — the failure is SERP's, not theirs.
            # success:False so the job is honestly retried (the SERP sweep never
            # ran clean); the findings ride along for the caller / observability.
            return {
                'success': False,
                'error': (
                    f'SERP exposure sweep failed ({serp_error or "unknown"}); '
                    f'refusing to report a clean result'
                ),
                'output': {
                    'brandVipId': brand_vip_id,
                    'brandMonitorId': brand_monitor_id,
                    'fullName': full_name,
                    'findings': findings,
                    'queriesRun': queries_run,
                    'searchDiagnostics': search_diagnostics,
                },
            }

        return {
            'success': True,
            'output': {
                'brandVipId': brand_vip_id,
                'brandMonitorId': brand_monitor_id,
                'fullName': full_name,
                'findings': findings,
                'queriesRun': queries_run,
                'searchDiagnostics': search_diagnostics,
            },
        }


def get_tool():
    return BrandMonitorVipExposureTool()
