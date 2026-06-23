"""
Typosquat Detection Tool
Generates domain permutations using 10 algorithms and checks for registered
look-alike domains that may be used for phishing or brand abuse.
"""

import asyncio
import html
import json
import logging
import os
import re
import sys
import time
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

# Ensure agent/ is on sys.path so `from lib.integration_credentials import ...`
# works when the plugin is loaded via spec_from_file_location.
_parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _parent_dir not in sys.path:
    sys.path.append(_parent_dir)

from plugin_interface import ToolPlugin
from lib.integration_credentials import (  # noqa: E402
    checkout_provider,
    reconcile_call,
    QuotaExceededError,
    IntegrationCredentialsError,
)

# RDAP-primary domain-age capture. asyncwhois (v1.1.12, pure-python / ARM-safe —
# unlike the cryptography 48.x SIGILL case) wraps whodap RDAP with a port-43
# WHOIS fallback in one async client. RDAP exposes the registration date as a
# clean ISO `events[].eventAction=="registration".eventDate`, which sidesteps the
# port-43 first-match-`created:` artifact (e.g. the CIRA `.ca` 1987 banner line).
# Imported guardedly so the tool still loads if the dependency is briefly absent
# during a partial agent rebuild (a requirements bump needs rebuild+recreate of
# all 5 agents, not just a restart).
try:
    import asyncwhois  # noqa: E402
    from asyncwhois.parse import TLDBaseKeys as _AwKeys  # noqa: E402
except Exception:  # pragma: no cover - import-time resilience only
    asyncwhois = None
    _AwKeys = None

logger = logging.getLogger(__name__)


# Homoglyph substitution lookup table
HOMOGLYPH_MAP = {
    'a': ['@', '\u0430', '4'],           # Cyrillic a, digit 4
    'b': ['d', '6'],
    'c': ['\u0441', '('],                # Cyrillic c
    'd': ['b', 'cl'],
    'e': ['\u0435', '3', '\u03b5'],      # Cyrillic e, digit 3, Greek epsilon
    'f': ['ph'],
    'g': ['9', 'q'],
    'h': ['lh'],
    'i': ['1', '!', 'l', '\u0456'],      # digit 1, Cyrillic i
    'k': ['lc'],
    'l': ['1', 'I', '|'],
    'm': ['rn', 'nn'],
    'n': ['r', '\u0578'],
    'o': ['0', '\u03bf', '\u043e'],       # digit 0, Greek omicron, Cyrillic o
    'p': ['\u0440'],                      # Cyrillic r
    'q': ['g'],
    'r': ['\u0433'],
    's': ['5', '$'],
    't': ['+', '7'],
    'u': ['\u03c5', '\u0446'],            # Greek upsilon, Cyrillic tse
    'v': ['u'],
    'w': ['vv', 'uu'],
    'x': ['\u0445'],                      # Cyrillic ha
    'y': ['\u0443'],                      # Cyrillic u
    'z': ['2'],
}

# Common phishing subdomains
PHISHING_SUBDOMAINS = [
    'login-', 'secure-', 'account-', 'mail-', 'webmail-', 'my-',
    'signin-', 'auth-', 'update-', 'verify-', 'support-', 'help-',
]

# Alternative TLDs for TLD swap
ALTERNATIVE_TLDS = [
    '.com', '.net', '.org', '.io', '.co', '.xyz', '.biz', '.info',
    '.uk', '.de', '.fr', '.jp', '.ru', '.cn', '.br', '.in',
    '.app', '.dev', '.tech', '.online', '.site', '.top',
]

# Suspicious TLDs for risk scoring
SUSPICIOUS_TLDS = {'.xyz', '.tk', '.top', '.club', '.buzz', '.gq', '.ml', '.cf'}

# Risk-keyword amplifier for combosquat scoring: tokens that co-occurring with
# a brand token in the candidate SLD signal a clear phishing/attack purpose
# (brand-prefix + attack-suffix pattern, e.g. accerta-health-login.com).
# Tighter than COMBOSQUATTING_KEYWORDS — only tokens with direct attack intent.
_COMBOSQUAT_RISK_KEYWORDS: frozenset = frozenset({
    'login', 'secure', 'verify', 'verification', 'account', 'support',
    'portal', 'claim', 'claims', 'benefits', 'health', 'billing',
    'update', 'signin', 'sso',
})

# Combosquatting keywords (common phishing/brand-abuse terms)
COMBOSQUATTING_KEYWORDS = [
    'login', 'secure', 'account', 'verify', 'update', 'signin', 'support',
    'help', 'banking', 'mail', 'pay', 'wallet', 'auth', 'confirm', 'alert',
    'service', 'billing', 'payment', 'transfer', 'reset', 'recovery', 'unlock',
    'activate', 'setup', 'register', 'mobile', 'app', 'download', 'free',
    'promo', 'offer', 'win', 'prize', 'gift', 'rewards', 'customer', 'member',
    'access', 'portal', 'dashboard', 'admin', 'manage', 'control', 'center',
    'online', 'web', 'cloud', 'team', 'corp',
]


class TyposquatDetectTool(ToolPlugin):
    """
    Detects potential typosquatting domains by generating permutations of a
    target domain using 11 different algorithms and checking DNS registration,
    web presence, and SSL certificates. Produces risk-scored results.
    """

    @property
    def name(self) -> str:
        return "typosquat:detect"

    @property
    def description(self) -> str:
        return (
            "Detect typosquatting domains by generating permutations using 13 algorithms "
            "(homoglyph, transposition, omission, doubling, hyphen insertion, TLD swap, "
            "subdomain prepend, bitsquatting, vowel swap, addition, combosquatting, "
            "soundsquatting, punycode/IDN) and "
            "checking DNS registration, web presence, and SSL certificates. Returns risk-scored results."
        )

    @property
    def schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "Single domain to check for typosquatting (e.g., example.com)"
                },
                "domains": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Multiple domains to check"
                },
                "techniques": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "Which permutation techniques to use. Options: homoglyph, "
                        "transposition, omission, doubling, hyphen, tld_swap, subdomain, "
                        "bitsquatting, vowel_swap, addition, combosquatting, soundsquatting, "
                        "punycode_idn. Default: all"
                    )
                },
                "checkDns": {
                    "type": "boolean",
                    "description": "Whether to resolve DNS for generated domains (default: true)",
                    "default": True
                },
                "maxVariations": {
                    "type": "integer",
                    "description": "Maximum number of permutations to generate (default: 500)",
                    "default": 500
                },
                "brandMonitorId": {
                    "type": "string",
                    "description": "Optional brand monitor ID to link results to"
                },
                "entropyLevel": {
                    "type": "string",
                    "description": "Preset entropy level: LOW (homoglyph + TLD swap only), MEDIUM (+ transposition, omission, subdomain), HIGH (all 13 techniques), CUSTOM (use enabledTechniques)",
                    "default": "HIGH"
                },
                "enabledTechniques": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Explicit list of techniques to use (overrides entropyLevel). Options: homoglyph, transposition, omission, doubling, hyphen_insertion, tld_swap, subdomain_prepend, bitsquatting, vowel_swap, addition, combosquatting, soundsquatting, punycode_idn"
                },
                "maxEditDistance": {
                    "type": "integer",
                    "description": "Maximum Levenshtein edit distance for generated domains (filters out domains too different from original)",
                    "default": 5
                },
                "customTlds": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Custom TLD list for TLD swap technique (overrides default)"
                }
            },
            "required": []
        }

    @property
    def metadata(self) -> Dict[str, Any]:
        return {
            'category': 'recon',
            'phase': 1,
            'domain': ['dns', 'osint'],
            'input_type': ['domain'],
            'output_type': ['domains', 'findings'],
            'chainable_after': [],
            'chainable_before': ['system:dns_resolve', 'gowitness:screenshot'],
        }

    # -- Permutation algorithms ------------------------------------------------

    @staticmethod
    def _split_domain(domain: str) -> Tuple[str, str]:
        """Split a domain into name and TLD parts.

        Handles multi-part TLDs like .co.uk. Returns (name, tld) where tld
        includes the leading dot (e.g., '.com').
        """
        domain = domain.lower().strip().rstrip('.')
        known_double_tlds = [
            '.co.uk', '.co.jp', '.co.in', '.co.kr', '.co.nz',
            '.com.au', '.com.br', '.com.cn', '.com.mx', '.com.sg',
            '.org.uk', '.net.uk', '.ac.uk',
        ]
        for dtld in known_double_tlds:
            if domain.endswith(dtld):
                name = domain[:-len(dtld)]
                return (name, dtld)
        parts = domain.rsplit('.', 1)
        if len(parts) == 2:
            return (parts[0], '.' + parts[1])
        return (domain, '.com')

    def _homoglyph(self, name: str, tld: str) -> List[Tuple[str, str]]:
        """Character substitution using look-alike characters."""
        results: List[Tuple[str, str]] = []
        for i, ch in enumerate(name):
            subs = HOMOGLYPH_MAP.get(ch, [])
            for s in subs:
                candidate = name[:i] + s + name[i + 1:]
                # Only keep candidates that form valid-ish domain labels
                if self._is_valid_label(candidate):
                    results.append((candidate + tld, 'HOMOGLYPH'))
        # Multi-char patterns: rn->m, vv->w
        for orig, repl in [('rn', 'm'), ('vv', 'w'), ('m', 'rn'), ('w', 'vv')]:
            idx = 0
            while True:
                idx = name.find(orig, idx)
                if idx == -1:
                    break
                candidate = name[:idx] + repl + name[idx + len(orig):]
                if self._is_valid_label(candidate):
                    results.append((candidate + tld, 'HOMOGLYPH'))
                idx += 1
        return results

    def _transposition(self, name: str, tld: str) -> List[Tuple[str, str]]:
        """Swap each pair of adjacent characters."""
        results: List[Tuple[str, str]] = []
        for i in range(len(name) - 1):
            candidate = name[:i] + name[i + 1] + name[i] + name[i + 2:]
            if candidate != name:
                results.append((candidate + tld, 'TRANSPOSITION'))
        return results

    def _omission(self, name: str, tld: str) -> List[Tuple[str, str]]:
        """Remove one character at a time."""
        results: List[Tuple[str, str]] = []
        for i in range(len(name)):
            candidate = name[:i] + name[i + 1:]
            if candidate:  # Don't allow empty labels
                results.append((candidate + tld, 'OMISSION'))
        return results

    def _doubling(self, name: str, tld: str) -> List[Tuple[str, str]]:
        """Double each character one at a time."""
        results: List[Tuple[str, str]] = []
        for i in range(len(name)):
            candidate = name[:i] + name[i] + name[i] + name[i + 1:]
            results.append((candidate + tld, 'DOUBLING'))
        return results

    def _hyphen_insertion(self, name: str, tld: str) -> List[Tuple[str, str]]:
        """Insert a hyphen between each adjacent pair of characters."""
        results: List[Tuple[str, str]] = []
        for i in range(1, len(name)):
            # Don't insert next to an existing hyphen
            if name[i - 1] == '-' or name[i] == '-':
                continue
            candidate = name[:i] + '-' + name[i:]
            results.append((candidate + tld, 'HYPHEN_INSERTION'))
        return results

    def _tld_swap(self, name: str, tld: str, custom_tlds: List[str] = None) -> List[Tuple[str, str]]:
        """Replace TLD with common alternatives."""
        results: List[Tuple[str, str]] = []
        tld_list = custom_tlds if custom_tlds else ALTERNATIVE_TLDS
        for alt_tld in tld_list:
            # Ensure TLD has leading dot
            if not alt_tld.startswith('.'):
                alt_tld = '.' + alt_tld
            if alt_tld != tld:
                results.append((name + alt_tld, 'TLD_SWAP'))
        return results

    def _subdomain_prepend(self, name: str, tld: str) -> List[Tuple[str, str]]:
        """Prepend common phishing subdomains."""
        results: List[Tuple[str, str]] = []
        for prefix in PHISHING_SUBDOMAINS:
            candidate = prefix + name
            if self._is_valid_label(candidate):
                results.append((candidate + tld, 'SUBDOMAIN_PREPEND'))
        return results

    def _bitsquatting(self, name: str, tld: str) -> List[Tuple[str, str]]:
        """Single bit-flip on each character, keeping valid domain chars."""
        results: List[Tuple[str, str]] = []
        valid_chars = set('abcdefghijklmnopqrstuvwxyz0123456789-')
        for i, ch in enumerate(name):
            ascii_val = ord(ch)
            for bit in range(8):
                flipped = ascii_val ^ (1 << bit)
                if 0 < flipped < 128:
                    flipped_ch = chr(flipped)
                    if flipped_ch in valid_chars and flipped_ch != ch:
                        candidate = name[:i] + flipped_ch + name[i + 1:]
                        if self._is_valid_label(candidate):
                            results.append((candidate + tld, 'BITSQUATTING'))
        return results

    def _vowel_swap(self, name: str, tld: str) -> List[Tuple[str, str]]:
        """Replace each vowel with every other vowel."""
        vowels = 'aeiou'
        results: List[Tuple[str, str]] = []
        for i, ch in enumerate(name):
            if ch in vowels:
                for v in vowels:
                    if v != ch:
                        candidate = name[:i] + v + name[i + 1:]
                        results.append((candidate + tld, 'VOWEL_SWAP'))
        return results

    def _addition(self, name: str, tld: str) -> List[Tuple[str, str]]:
        """Append a single character (a-z, 0-9) before the TLD."""
        results: List[Tuple[str, str]] = []
        for ch in 'abcdefghijklmnopqrstuvwxyz0123456789':
            candidate = name + ch
            results.append((candidate + tld, 'ADDITION'))
        return results

    def _soundsquatting(self, name: str, tld: str) -> List[Tuple[str, str]]:
        """Generate phonetically similar domain variants via sound-alike substitutions."""
        # Ordered longest-first to prefer multi-char matches
        SOUND_PAIRS = [
            ('tion', 'shun'), ('shun', 'tion'),
            ('igh', 'y'), ('y', 'igh'),
            ('ph', 'f'), ('f', 'ph'),
            ('ck', 'k'), ('k', 'ck'),
            ('ai', 'ay'), ('ay', 'ai'),
            ('ee', 'ea'), ('ea', 'ee'),
            ('oo', 'u'), ('u', 'oo'),
            ('qu', 'kw'), ('kw', 'qu'),
            ('x', 'ks'), ('ks', 'x'),
            ('c', 'k'), ('k', 'c'),
            ('s', 'z'), ('z', 's'),
            ('w', 'wh'), ('wh', 'w'),
        ]
        results: List[Tuple[str, str]] = []
        for orig, repl in SOUND_PAIRS:
            idx = 0
            while True:
                idx = name.find(orig, idx)
                if idx == -1:
                    break
                candidate = name[:idx] + repl + name[idx + len(orig):]
                if candidate != name and self._is_valid_label(candidate):
                    results.append((candidate + tld, 'SOUNDSQUATTING'))
                idx += 1
        return results

    def _punycode_idn(self, name: str, tld: str) -> List[Tuple[str, str]]:
        """Generate IDN homoglyph variants using Unicode confusable characters.

        Produces single-character substitutions with visually similar Unicode
        characters, then converts to punycode (xn--...) for DNS-valid domains.
        """
        # Latin -> Unicode confusable mappings
        CONFUSABLES = {
            'a': ['\u0430'],           # Cyrillic a
            'c': ['\u0441'],           # Cyrillic es
            'e': ['\u0435'],           # Cyrillic ie
            'o': ['\u043e'],           # Cyrillic o
            'p': ['\u0440'],           # Cyrillic er
            'x': ['\u0445'],           # Cyrillic ha
            'y': ['\u0443'],           # Cyrillic u
            'i': ['\u0456'],           # Cyrillic i (Ukrainian)
            'l': ['\u04cf'],           # Cyrillic palochka
            's': ['\u0455'],           # Cyrillic dze
            'h': ['\u04bb'],           # Cyrillic shha
            'j': ['\u0458'],           # Cyrillic je
            'g': ['\u0261'],           # Latin small script g
            'n': ['\u0578'],           # Armenian now
            'u': ['\u057d'],           # Armenian seh (visual match in some fonts)
            'd': ['\u0501'],           # Cyrillic komi de
            'q': ['\u051b'],           # Cyrillic qa
            'w': ['\u051d'],           # Cyrillic we
        }
        results: List[Tuple[str, str]] = []
        seen: set = set()
        for i, ch in enumerate(name):
            subs = CONFUSABLES.get(ch, [])
            for s in subs:
                unicode_name = name[:i] + s + name[i + 1:]
                try:
                    punycode = unicode_name.encode('idna').decode('ascii')
                except (UnicodeError, UnicodeDecodeError):
                    continue
                # punycode should start with xn-- for it to be an IDN variant
                if punycode.startswith('xn--') and punycode not in seen:
                    seen.add(punycode)
                    results.append((punycode + tld, 'PUNYCODE_IDN'))
        return results

    def _combosquatting(self, name: str, tld: str) -> List[Tuple[str, str]]:
        """Combine brand name with common phishing keywords.

        Generates 4 patterns per keyword per TLD:
        brand-keyword.tld, keyword-brand.tld, brandkeyword.tld, keywordbrand.tld
        """
        results: List[Tuple[str, str]] = []
        for kw in COMBOSQUATTING_KEYWORDS:
            candidates = [
                f'{name}-{kw}',   # brand-keyword
                f'{kw}-{name}',   # keyword-brand
                f'{name}{kw}',    # brandkeyword
                f'{kw}{name}',    # keywordbrand
            ]
            for candidate in candidates:
                if self._is_valid_label(candidate):
                    results.append((candidate + tld, 'COMBOSQUATTING'))
        return results

    @staticmethod
    def _is_valid_label(label: str) -> bool:
        """Check if a string is a roughly valid DNS label."""
        if not label or len(label) > 63:
            return False
        if label.startswith('-') or label.endswith('-'):
            return False
        allowed = set('abcdefghijklmnopqrstuvwxyz0123456789-')
        return all(c in allowed for c in label)

    # -- Utility ---------------------------------------------------------------

    @staticmethod
    def _levenshtein(s1: str, s2: str) -> int:
        """Compute the Levenshtein edit distance between two strings."""
        if len(s1) < len(s2):
            return TyposquatDetectTool._levenshtein(s2, s1)
        if len(s2) == 0:
            return len(s1)
        prev_row = list(range(len(s2) + 1))
        for i, c1 in enumerate(s1):
            curr_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = prev_row[j + 1] + 1
                deletions = curr_row[j] + 1
                substitutions = prev_row[j] + (c1 != c2)
                curr_row.append(min(insertions, deletions, substitutions))
            prev_row = curr_row
        return prev_row[-1]

    @staticmethod
    def _damerau_levenshtein(s1: str, s2: str) -> int:
        """Compute the Damerau-Levenshtein (optimal string alignment) distance.

        Unlike plain Levenshtein, an adjacent transposition counts as a SINGLE
        edit (distance 1) rather than two substitutions (distance 2).
        Transposition is the single most common typosquat technique, so it must
        score as a 1-character near-miss — otherwise a live transposition
        lookalike is under-weighted against unrelated, more-distant domains.
        """
        len1, len2 = len(s1), len(s2)
        if len1 == 0:
            return len2
        if len2 == 0:
            return len1
        # d[i][j] = distance between s1[:i] and s2[:j]
        d = [[0] * (len2 + 1) for _ in range(len1 + 1)]
        for i in range(len1 + 1):
            d[i][0] = i
        for j in range(len2 + 1):
            d[0][j] = j
        for i in range(1, len1 + 1):
            for j in range(1, len2 + 1):
                cost = 0 if s1[i - 1] == s2[j - 1] else 1
                d[i][j] = min(
                    d[i - 1][j] + 1,          # deletion
                    d[i][j - 1] + 1,          # insertion
                    d[i - 1][j - 1] + cost,   # substitution
                )
                # Transposition of two adjacent characters
                if (i > 1 and j > 1
                        and s1[i - 1] == s2[j - 2]
                        and s1[i - 2] == s2[j - 1]):
                    d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
        return d[len1][len2]

    # -- DNS / HTTP / SSL checks -----------------------------------------------

    async def _dig_records(self, domain: str, rrtype: str) -> Tuple[List[str], str]:
        """Query one DNS record type and return ``(records, header_status)``.

        ``header_status`` is the rcode from dig's ``->>HEADER<<-`` line
        (``NOERROR`` / ``NXDOMAIN`` / ``SERVFAIL`` / ``REFUSED`` / ...), or
        ``TIMEOUT`` if the lookup itself failed. The status lets the caller tell
        a genuine NXDOMAIN (name does not exist → unregistered) apart from a
        SERVFAIL/timeout (resolver couldn't answer → registration UNKNOWN, do
        NOT force ``is_registered=False``).
        """
        rrtype_u = rrtype.upper()
        try:
            proc = await asyncio.create_subprocess_exec(
                'dig', '+noall', '+answer', '+comment',
                '+time=3', '+tries=1', domain, rrtype_u,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
            text = stdout.decode('utf-8', errors='replace')
            status = 'UNKNOWN'
            records: List[str] = []
            for line in text.split('\n'):
                stripped = line.strip()
                if '->>HEADER<<-' in stripped:
                    m = re.search(r'status:\s*([A-Z]+)', stripped)
                    if m:
                        status = m.group(1)
                    continue
                if not stripped or stripped.startswith(';'):
                    continue
                # Answer line: "name  ttl  IN  <TYPE>  <rdata...>". Only keep
                # rows whose type matches the query (skips CNAME chain rows).
                parts = stripped.split()
                if len(parts) >= 5 and parts[3].upper() == rrtype_u:
                    rdata = parts[4]
                    if rrtype_u == 'A':
                        # Validate IPv4: exactly 4 octets in range.
                        octets = rdata.split('.')
                        if len(octets) == 4 and all(
                            o.isdigit() and 0 <= int(o) <= 255 for o in octets
                        ):
                            records.append(rdata)
                    elif rrtype_u == 'NS':
                        records.append(rdata.rstrip('.').lower())
                    else:
                        records.append(rdata)
            return records, status
        except (asyncio.TimeoutError, Exception):
            return [], 'TIMEOUT'

    async def _dns_probe(self, domain: str) -> Dict[str, Any]:
        """Determine registration from A / AAAA / NS / MX records.

        A domain is REGISTERED if ANY of A, AAAA, NS, or MX records resolve
        (hardened beyond the old A-record-only test — a parked/MX-only/IPv6-only
        lookalike that resolves no A record is still registered).

        Registration verdict:
          - any record present                       -> is_registered=True
          - NXDOMAIN on any query (name-level)       -> is_registered=False
          - definitive NOERROR but no records (NODATA) -> is_registered=False
          - only SERVFAIL / REFUSED / timeout        -> is_registered=False,
                                                        registration_unknown=True

        ``registration_unknown`` is the SERVFAIL/timeout marker. The agent has no
        DB visibility so it cannot "preserve prior" itself; it surfaces the flag
        (mirroring the existing ``whois_failed`` merge-don't-clobber pattern) so
        the backend can avoid forcing a previously-registered row to unregistered
        on a transient resolver failure.
        """
        (a_recs, a_st), (aaaa_recs, aaaa_st), (ns_recs, ns_st), mx_recs = (
            await asyncio.gather(
                self._dig_records(domain, 'A'),
                self._dig_records(domain, 'AAAA'),
                self._dig_records(domain, 'NS'),
                self._mx_lookup(domain),
            )
        )
        mx_recs = [m for m in (mx_recs or []) if m and m.strip()]
        found = bool(a_recs or aaaa_recs or ns_recs or mx_recs)
        statuses = {a_st, aaaa_st, ns_st}
        if found:
            is_registered, registration_unknown = True, False
        elif 'NXDOMAIN' in statuses:
            # Name does not exist — definitively unregistered.
            is_registered, registration_unknown = False, False
        elif 'NOERROR' in statuses:
            # The resolver answered authoritatively with no matching records
            # (NODATA) — definitive, not a failure.
            is_registered, registration_unknown = False, False
        else:
            # Only SERVFAIL / REFUSED / TIMEOUT / UNKNOWN were seen — we could
            # not determine existence. Do NOT force False.
            is_registered, registration_unknown = False, True
        return {
            'a': a_recs,
            'aaaa': aaaa_recs,
            'ns': ns_recs,
            'mx': mx_recs,
            'is_registered': is_registered,
            'registration_unknown': registration_unknown,
        }

    async def _check_http(self, domain: str) -> Dict[str, Any]:
        """Check if domain serves web content with redirect chain tracking.

        Returns dict with: has_content, status_code, redirect_chain, final_url.
        Follows Location headers manually up to 10 hops.
        """
        result = {
            'has_content': False,
            'status_code': 0,
            'redirect_chain': [],
            'final_url': f'http://{domain}',
        }
        current_url = f'http://{domain}'
        max_hops = 10

        try:
            for hop in range(max_hops):
                proc = await asyncio.create_subprocess_exec(
                    'curl', '-sI',
                    '--connect-timeout', '3', '--max-time', '5',
                    '-o', '-',
                    current_url,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
                headers_text = stdout.decode('utf-8', errors='replace')

                # Parse status code from first line
                status_code = 0
                location = None
                for line in headers_text.split('\n'):
                    line = line.strip()
                    if line.upper().startswith('HTTP/') and ' ' in line:
                        parts = line.split(None, 2)
                        if len(parts) >= 2 and parts[1].isdigit():
                            status_code = int(parts[1])
                    elif line.lower().startswith('location:'):
                        location = line.split(':', 1)[1].strip()

                result['redirect_chain'].append({
                    'url': current_url,
                    'status_code': status_code,
                })

                # If not a redirect, stop
                if status_code < 300 or status_code >= 400 or not location:
                    result['has_content'] = 200 <= status_code <= 399
                    result['status_code'] = status_code
                    result['final_url'] = current_url
                    break

                # Resolve relative Location URLs (e.g. "/home") against the
                # current URL so we never fabricate a bogus host like
                # "http://home/". urljoin handles absolute, root-relative, and
                # path-relative redirects correctly.
                location = urljoin(current_url, location)

                current_url = location
            else:
                # Exhausted max hops
                result['status_code'] = status_code
                result['final_url'] = current_url

        except (asyncio.TimeoutError, Exception):
            pass

        return result

    async def _check_ssl(self, domain: str) -> bool:
        """Check if domain has an SSL certificate on port 443."""
        try:
            proc = await asyncio.create_subprocess_exec(
                'timeout', '3', 'openssl', 's_client',
                '-connect', f'{domain}:443', '-servername', domain,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                stdin=asyncio.subprocess.PIPE,
            )
            # Send empty input so openssl doesn't hang
            await asyncio.wait_for(proc.communicate(input=b''), timeout=5)
            return proc.returncode == 0
        except (asyncio.TimeoutError, Exception):
            return False

    @staticmethod
    def _normalize_whois_field(value: Optional[str]) -> Optional[str]:
        """Normalize a WHOIS field value, returning None for privacy-redacted values."""
        if value is None:
            return None
        value = value.strip()
        if not value:
            return None
        redaction_patterns = [
            "redacted for privacy",
            "data protected",
            "gdpr masked",
            "not disclosed",
            "registration private",
            "contact privacy",
            "whoisguard protected",
            "identity protection",
            "perfect privacy",
            "domains by proxy",
            "privacy service provided",
            "statutory masking enabled",
            "redacted",
            "not applicable",
            "data redacted",
        ]
        value_lower = value.lower()
        for pattern in redaction_patterns:
            if pattern in value_lower:
                return None
        return value

    async def _whois_lookup(self, domain: str, _retry: bool = True) -> Dict[str, Any]:
        """Lookup WHOIS data for a domain. Retries once on timeout.

        On a genuine lookup FAILURE (timeout after retry, or an exception) the
        returned dict carries ``whois_failed: True`` so the backend can PRESERVE
        previously-persisted WHOIS data instead of clobbering it with nulls. A
        successful lookup that simply has no registrar (e.g. a privacy-redacted
        or sparse TLD) returns ``whois_failed: False`` — that empty IS authentic
        and may be written.
        """
        empty = {'registrar': None, 'created': None, 'expires': None, 'nameservers': [],
                 'registrant_email': None, 'registrant_org': None, 'registrant_name': None,
                 'registrant_country': None, 'whois_failed': True}
        try:
            proc = await asyncio.create_subprocess_exec(
                'whois', domain,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
            text = stdout.decode('utf-8', errors='replace')

            registrar = None
            created = None
            expires = None
            nameservers = []
            registrant_email = None
            registrant_org = None
            registrant_name = None
            registrant_country = None

            for line in text.split('\n'):
                line_lower = line.lower().strip()
                if not registrar and ('registrar:' in line_lower or 'registrar name:' in line_lower):
                    registrar = line.split(':', 1)[1].strip()
                if not created and ('creation date:' in line_lower or 'created:' in line_lower or 'registered on:' in line_lower):
                    created = line.split(':', 1)[1].strip()
                if not expires and ('expir' in line_lower and 'date' in line_lower):
                    expires = line.split(':', 1)[1].strip()
                if 'name server:' in line_lower or 'nserver:' in line_lower:
                    ns = line.split(':', 1)[1].strip().lower()
                    if ns and ns not in nameservers:
                        nameservers.append(ns)
                if not registrant_email and (line_lower.startswith('registrant email:') or line_lower.startswith('registrant contact email:')):
                    registrant_email = self._normalize_whois_field(line.split(':', 1)[1])
                if not registrant_org and (line_lower.startswith('registrant organization:') or line_lower.startswith('registrant org:') or line_lower.startswith('org-name:')):
                    registrant_org = self._normalize_whois_field(line.split(':', 1)[1])
                if not registrant_name and line_lower.startswith('registrant name:') and 'org' not in line_lower:
                    registrant_name = self._normalize_whois_field(line.split(':', 1)[1])
                if not registrant_country and line_lower.startswith('registrant country:'):
                    registrant_country = self._normalize_whois_field(line.split(':', 1)[1])

            result = {
                'registrar': registrar,
                'created': created,
                'expires': expires,
                'nameservers': nameservers[:4],
                'registrant_email': registrant_email,
                'registrant_org': registrant_org,
                'registrant_name': registrant_name,
                'registrant_country': registrant_country,
                'whois_failed': False,
            }
            logger.info(f"[Typosquat] WHOIS {domain}: registrar={registrar}, created={created}, ns={len(nameservers)}, output_len={len(text)}")
            return result
        except asyncio.TimeoutError:
            if _retry:
                logger.warning(f"[Typosquat] WHOIS timeout for {domain}, retrying...")
                await asyncio.sleep(2)
                return await self._whois_lookup(domain, _retry=False)
            logger.warning(f"[Typosquat] WHOIS timeout for {domain} after retry, skipping")
            return empty
        except Exception as e:
            logger.warning(f"[Typosquat] WHOIS error for {domain}: {e}")
            return empty

    @staticmethod
    def _to_iso(value: Any) -> Optional[str]:
        """Normalize an asyncwhois date (datetime / list / str) to clean ISO.

        Emits ``%Y-%m-%dT%H:%M:%SZ`` so the value matches the first format the
        scorer (`_score_result`) and the backend `parseWhoisDate` already accept.
        """
        if value is None:
            return None
        if isinstance(value, (list, tuple)):
            value = next((v for v in value if v is not None), None)
            if value is None:
                return None
        if isinstance(value, datetime):
            return value.strftime('%Y-%m-%dT%H:%M:%SZ')
        text = str(value).strip()
        return text or None

    async def _rdap_throttle(self) -> None:
        """SECONDARY in-process token-bucket smoother for RDAP/WHOIS calls.

        Not the primary limiter (that is the cross-process checkout); this just
        paces bursts within a single container so a large registered-domain
        batch does not hammer registry RDAP endpoints from one agent at once.
        """
        async with self._rdap_lock:
            now = time.monotonic()
            elapsed = now - self._rdap_last_refill
            self._rdap_last_refill = now
            self._rdap_tokens = min(
                self._RDAP_BUCKET_CAPACITY,
                self._rdap_tokens + elapsed * self._RDAP_REFILL_PER_SEC,
            )
            if self._rdap_tokens < 1.0:
                wait = (1.0 - self._rdap_tokens) / self._RDAP_REFILL_PER_SEC
                await asyncio.sleep(wait)
                self._rdap_tokens = 0.0
            else:
                self._rdap_tokens -= 1.0

    async def _rdap_created(self, domain: str) -> Optional[str]:
        """RDAP-primary registration-date lookup → clean ISO string or None.

        Reads RDAP `events[].eventAction=="registration".eventDate` (asyncwhois
        surfaces it as the parsed ``CREATED`` key) which is a clean ISO date and
        bypasses the port-43 first-match `created:` artifact. Returns None for
        ccTLDs lacking RDAP (no IANA bootstrap entry) — the caller then falls
        back to the existing hardened port-43 `_whois_lookup` `created`.

        Rate-limited through the cross-process ProviderQuotaService seam
        (synthetic 'RDAP' provider). If the backend has no RDAP provider row
        (keyless provider), checkout raises IntegrationCredentialsError and we
        proceed best-effort under the local smoother only. A QuotaExceededError
        (tenant cap hit) skips the lookup so we never breach a configured cap.
        """
        if asyncwhois is None:
            return None

        lease: Optional[str] = None
        try:
            checkout = await checkout_provider('RDAP', requested_units=1)
            lease = checkout.get('leaseToken')
        except QuotaExceededError:
            # Respect a configured cap — skip the lookup (port-43 fallback still
            # runs in _whois_lookup, so we are not blind on age).
            return None
        except IntegrationCredentialsError:
            # No 'RDAP' provider configured (keyless) or transient backend error
            # — fall through to a best-effort lookup paced by the local smoother.
            lease = None
        except Exception:
            lease = None

        await self._rdap_throttle()

        created_iso: Optional[str] = None
        success = False
        try:
            _query, parsed = await asyncwhois.aio_rdap(domain)
            if parsed:
                created = None
                if _AwKeys is not None:
                    created = parsed.get(_AwKeys.CREATED)
                if created is None:
                    created = parsed.get('created')
                created_iso = self._to_iso(created)
            success = created_iso is not None
        except Exception as e:
            # ccTLD without RDAP, network error, parse miss — fall back silently.
            logger.debug(f"[Typosquat] RDAP age lookup failed for {domain}: {e}")
        finally:
            if lease:
                try:
                    await reconcile_call(
                        'RDAP', lease, units=1, success=success,
                        error_code=None if success else 'rdap_no_date',
                    )
                except Exception:
                    pass

        return created_iso

    async def _mx_lookup(self, domain: str) -> List[str]:
        """Lookup MX records for a domain."""
        try:
            proc = await asyncio.create_subprocess_exec(
                'dig', 'MX', '+short', domain,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
            text = stdout.decode('utf-8', errors='replace').strip()
            mx_records = []
            for line in text.split('\n'):
                line = line.strip()
                if line and ' ' in line:
                    # MX format: "10 mail.example.com."
                    parts = line.split(None, 1)
                    if len(parts) == 2:
                        mx_records.append(parts[1].rstrip('.'))
            return mx_records[:5]
        except (asyncio.TimeoutError, Exception):
            return []

    async def _get_page_title(self, domain: str) -> Optional[str]:
        """Fetch page title via curl."""
        try:
            proc = await asyncio.create_subprocess_exec(
                'curl', '-sL', '--connect-timeout', '3', '--max-time', '5',
                '-o', '-', f'http://{domain}',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
            html_text = stdout.decode('utf-8', errors='replace')
            match = re.search(r'<title[^>]*>(.*?)</title>', html_text, re.IGNORECASE | re.DOTALL)
            if match:
                return html.unescape(match.group(1).strip())[:255]
        except (asyncio.TimeoutError, Exception):
            pass
        return None

    # SECONDARY RDAP/WHOIS smoother (see __init__): ~3 lookups/sec sustained,
    # burst up to 5. This is NOT the primary limiter — the cross-process
    # ProviderQuotaService checkout is (CLAUDE.md: the 5 agents do not coordinate
    # in-process). This only paces bursts inside one container.
    _RDAP_REFILL_PER_SEC = 3.0
    _RDAP_BUCKET_CAPACITY = 5.0

    def __init__(self):
        super().__init__()
        # PhishTank rate limiter: 10 req/min (free tier)
        # Lock-based to prevent race conditions across concurrent executions
        self._pt_lock = asyncio.Lock()
        self._pt_last_reset = 0.0
        self._pt_count = 0

        # OpenPhish feed cache with lock and TTL (3600s = 1 hour, matches feed update interval)
        self._openphish_lock = asyncio.Lock()
        self._openphish_cache: Optional[Set[str]] = None
        self._openphish_cache_time = 0.0

        # VirusTotal rate limiter: 4 req/min (free tier)
        # Lock-based to prevent race conditions across concurrent executions
        self._vt_lock = asyncio.Lock()
        self._vt_last_reset = 0.0
        self._vt_count = 0

        # RDAP/WHOIS age-capture rate limiting. The PRIMARY limiter is the
        # cross-process ProviderQuotaService seam (checkout_provider('RDAP')) so
        # all 5 agent containers coordinate per CLAUDE.md — a bare in-process
        # semaphore does NOT coordinate across containers. The token bucket
        # below is only a SECONDARY in-process smoother for bursts within one
        # container, and the sole limiter when the backend has no 'RDAP' provider
        # row configured (keyless → checkout raises and we fall through to
        # local-only best-effort smoothing).
        self._rdap_lock = asyncio.Lock()
        self._rdap_tokens = float(self._RDAP_BUCKET_CAPACITY)
        self._rdap_last_refill = time.monotonic()

    async def _check_virustotal(self, domain: str) -> Optional[Dict[str, Any]]:
        """Check domain reputation via VirusTotal API v3.

        Returns detection stats dict or None if VT_API_KEY is not set or on error.
        Rate-limited to 4 requests per minute (free tier).

        TODO(T2.7 — tracked in roadmaps/core-platform.md "Split agent/tools/
        typosquat_detect.py" entry): Migrate to ProviderQuotaService.checkout
        once VIRUSTOTAL is added to the IntegrationProvider enum. The in-process
        asyncio.Lock below only synchronizes inside ONE agent container; with
        5 agents the effective rate is 20/min, not 4/min — risking a VT ban.
        Deferred from the 2026-05-19 cleanup pass because (a) the enum addition
        + Prisma migration falls under the locked "large refactors land as
        separate PRs" decision, and (b) wiring checkout() without an Integration
        row makes the call fail-closed for tenants that haven't configured a VT
        key — a behavior change, not a cleanup. The roadmap entry covers both.
        """
        api_key = os.environ.get('VT_API_KEY')
        if not api_key:
            return None

        # Rate limiting: 4 requests per 60 seconds (lock-based for concurrency safety)
        async with self._vt_lock:
            now = time.time()
            if now - self._vt_last_reset >= 60:
                self._vt_last_reset = now
                self._vt_count = 0
            if self._vt_count >= 4:
                wait_time = 60 - (now - self._vt_last_reset)
                if wait_time > 0:
                    await asyncio.sleep(wait_time)
                self._vt_last_reset = time.time()
                self._vt_count = 0
            self._vt_count += 1

        try:
            proc = await asyncio.create_subprocess_exec(
                'curl', '-s', '--connect-timeout', '5', '--max-time', '10',
                '-H', f'x-apikey: {api_key}',
                f'https://www.virustotal.com/api/v3/domains/{domain}',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
            data = json.loads(stdout.decode('utf-8', errors='replace'))
            attrs = data.get('data', {}).get('attributes', {})
            stats = attrs.get('last_analysis_stats', {})
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            harmless = stats.get('harmless', 0)
            undetected = stats.get('undetected', 0)
            total = malicious + suspicious + harmless + undetected
            result = {
                'malicious': malicious,
                'suspicious': suspicious,
                'total': total,
            }
            logger.info(f"[Typosquat] VT {domain}: malicious={malicious}, suspicious={suspicious}, total={total}")
            return result
        except (asyncio.TimeoutError, json.JSONDecodeError, Exception) as e:
            logger.warning(f"[Typosquat] VT error for {domain}: {e}")
            return None

    async def _check_phishtank(self, domain: str) -> bool:
        """Check if domain is in PhishTank database.

        Uses PhishTank API (POST checkurl). Requires PHISHTANK_API_KEY env var.
        Rate-limited to 10 requests per minute (free tier).
        Returns True if domain is a verified phish, False otherwise.

        TODO(T2.7 — tracked in roadmaps/core-platform.md "Split agent/tools/
        typosquat_detect.py" entry): Migrate to ProviderQuotaService.checkout
        once PHISHTANK is added to the IntegrationProvider enum. Same
        cross-container rate-limit problem as VirusTotal above (5 agents ×
        10/min = effective 50/min, free tier limit is 10/min). Deferred from
        the 2026-05-19 cleanup pass per the same reasoning as VirusTotal above.
        """
        api_key = os.environ.get('PHISHTANK_API_KEY')
        if not api_key:
            return False

        # Rate limiting: 10 requests per 60 seconds (lock-based for concurrency safety)
        async with self._pt_lock:
            now = time.time()
            if now - self._pt_last_reset >= 60:
                self._pt_last_reset = now
                self._pt_count = 0
            if self._pt_count >= 10:
                wait_time = 60 - (now - self._pt_last_reset)
                if wait_time > 0:
                    await asyncio.sleep(wait_time)
                self._pt_last_reset = time.time()
                self._pt_count = 0
            self._pt_count += 1

        try:
            proc = await asyncio.create_subprocess_exec(
                'curl', '-s', '--connect-timeout', '5', '--max-time', '10',
                '-X', 'POST',
                '-d', f'url=http://{domain}&format=json&app_key={api_key}',
                'http://checkurl.phishtank.com/checkurl/',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
            data = json.loads(stdout.decode('utf-8', errors='replace'))
            results = data.get('results', {})
            in_database = results.get('in_database', False)
            verified = results.get('verified', False)
            if in_database and verified:
                logger.warning(f"[Typosquat] PhishTank MATCH: {domain} is a verified phish")
                return True
            return False
        except (asyncio.TimeoutError, json.JSONDecodeError, Exception) as e:
            logger.warning(f"[Typosquat] PhishTank error for {domain}: {e}")
            return False

    async def _load_openphish_feed(self) -> Set[str]:
        """Download OpenPhish feed and cache it with TTL.

        Feed URL: https://openphish.com/feed.txt (updated hourly).
        Cache TTL: 3600 seconds (1 hour).
        Uses asyncio.Lock to prevent concurrent fetch races.
        Returns set of URLs from the feed.
        """
        now = time.time()
        # Fast path: cache is valid (no lock needed for read — worst case we re-fetch once)
        if self._openphish_cache is not None and (now - self._openphish_cache_time) < 3600:
            return self._openphish_cache

        async with self._openphish_lock:
            # Re-check inside lock (another coroutine may have populated it)
            now = time.time()
            if self._openphish_cache is not None and (now - self._openphish_cache_time) < 3600:
                return self._openphish_cache

            try:
                proc = await asyncio.create_subprocess_exec(
                    'curl', '-s', '--connect-timeout', '5', '--max-time', '15',
                    'https://openphish.com/feed.txt',
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=20)
                text = stdout.decode('utf-8', errors='replace').strip()
                urls = set()
                for line in text.split('\n'):
                    line = line.strip()
                    if line:
                        urls.add(line)
                self._openphish_cache = urls
                self._openphish_cache_time = time.time()
                logger.info(f"[Typosquat] OpenPhish feed loaded: {len(urls)} URLs")
                return urls
            except (asyncio.TimeoutError, Exception) as e:
                logger.warning(f"[Typosquat] OpenPhish feed error: {e}")
                self._openphish_cache = set()
                self._openphish_cache_time = time.time()
                return self._openphish_cache

    async def _check_openphish(self, domain: str) -> bool:
        """Check if domain appears in any URL in the OpenPhish feed.

        Returns True if domain is found in feed, False otherwise.
        """
        feed = await self._load_openphish_feed()
        if not feed:
            return False

        domain_lower = domain.lower()
        for url in feed:
            if domain_lower in url.lower():
                logger.warning(f"[Typosquat] OpenPhish MATCH: {domain} found in feed")
                return True
        return False

    async def _check_spf(self, domain: str) -> Dict[str, Any]:
        """Check SPF record for a domain via dig TXT.

        Returns dict with: has_spf, spf_record, spf_policy.
        """
        result = {'has_spf': False, 'spf_record': None, 'spf_policy': None}
        try:
            proc = await asyncio.create_subprocess_exec(
                'dig', 'TXT', '+short', domain,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
            text = stdout.decode('utf-8', errors='replace').strip()
            for line in text.split('\n'):
                line = line.strip().strip('"')
                if 'v=spf1' in line.lower():
                    result['has_spf'] = True
                    result['spf_record'] = line
                    # Extract policy qualifier
                    for policy in ['-all', '~all', '+all', '?all']:
                        if policy in line.lower():
                            result['spf_policy'] = policy
                            break
                    break
        except (asyncio.TimeoutError, Exception) as e:
            logger.warning(f"[Typosquat] SPF check error for {domain}: {e}")
        return result

    async def _check_dmarc(self, domain: str) -> Dict[str, Any]:
        """Check DMARC record for a domain via dig TXT _dmarc.{domain}.

        Returns dict with: has_dmarc, dmarc_record, dmarc_policy.
        """
        result = {'has_dmarc': False, 'dmarc_record': None, 'dmarc_policy': None}
        try:
            proc = await asyncio.create_subprocess_exec(
                'dig', 'TXT', '+short', f'_dmarc.{domain}',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
            text = stdout.decode('utf-8', errors='replace').strip()
            for line in text.split('\n'):
                line = line.strip().strip('"')
                if 'v=dmarc1' in line.lower():
                    result['has_dmarc'] = True
                    result['dmarc_record'] = line
                    # Extract policy (p=none|quarantine|reject)
                    match = re.search(r'p\s*=\s*(none|quarantine|reject)', line, re.IGNORECASE)
                    if match:
                        result['dmarc_policy'] = match.group(1).lower()
                    break
        except (asyncio.TimeoutError, Exception) as e:
            logger.warning(f"[Typosquat] DMARC check error for {domain}: {e}")
        return result

    async def _check_dkim(self, domain: str) -> Dict[str, Any]:
        """Check DKIM records for a domain by trying common selectors.

        Tries selectors: default, google, selector1, selector2, k1.
        Returns dict with: has_dkim, dkim_selector.
        """
        result: Dict[str, Any] = {'has_dkim': False, 'dkim_selector': None}
        selectors = ['default', 'google', 'selector1', 'selector2', 'k1']
        for selector in selectors:
            try:
                proc = await asyncio.create_subprocess_exec(
                    'dig', 'TXT', '+short', f'{selector}._domainkey.{domain}',
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
                text = stdout.decode('utf-8', errors='replace').strip()
                if text and 'v=dkim1' in text.lower():
                    result['has_dkim'] = True
                    result['dkim_selector'] = selector
                    break
            except (asyncio.TimeoutError, Exception):
                continue
        return result

    def _score_result(
        self,
        original: str,
        candidate: str,
        is_registered: bool,
        has_web: bool,
        has_ssl: bool,
        page_title: Optional[str] = None,
        mx_records: Optional[List[str]] = None,
        brand_keywords: Optional[List[str]] = None,
        whois_created: Optional[str] = None,
        vt_detections: Optional[Dict[str, Any]] = None,
        final_url: Optional[str] = None,
        phishtank_match: bool = False,
        openphish_match: bool = False,
        email_security: Optional[Dict[str, Any]] = None,
    ) -> Tuple[int, str]:
        """Calculate structural risk score (0-75) and risk level for a candidate domain.

        CRITICAL is reserved for AI-confirmed phishing — structural scoring caps at HIGH.
        Conservative scoring: only flag HIGH when actual threat indicators present.
        """
        score = 0
        # Drop empty/blank MX entries (e.g. dig returning [""]) before any
        # mail-capability test — a blank MX is NOT email-capable and must not
        # inflate the score or surface a false Email signal downstream.
        mx_records = [m for m in (mx_records or []) if m and m.strip()]
        if is_registered:
            score += 10
        if has_web:
            score += 5
        if has_ssl:
            score += 3

        # String similarity: Damerau-Levenshtein on full domain (graduated
        # scoring). Damerau makes a transposition cost 1 (not 2), and the
        # weights below are raised so a close lexical near-miss is a primary
        # driver of risk — closer to the dominant phishing signal it actually
        # represents — rather than being out-weighted by infra signals.
        dist = self._damerau_levenshtein(original, candidate)
        if dist == 1:
            score += 15
        elif dist == 2:
            score += 10
        elif dist == 3:
            score += 5

        # Brand-label identity: candidate's 2LD label exactly equals the brand's
        # 2LD label (e.g. tetradg.io vs tetradg.com — a TLD swap of the exact
        # brand name). Full-domain Levenshtein under-weights these vs unrelated
        # 1-char-off near-misses, so award a strong, distance-independent bonus
        # so an exact-name impersonation on another TLD outranks a coincidental
        # near-miss. Additive and cap-coherent with the band thresholds.
        candidate_name, tld = self._split_domain(candidate)
        brand_name, _ = self._split_domain(original)
        if brand_name and candidate_name == brand_name:
            score += 12

        # Combosquat / brand-containment signal: the candidate SLD contains the
        # brand token as a STANDALONE word (split on hyphens/dots), NOT a mere
        # substring — so "accertacontabil" and "corpaccertio" do NOT match.
        # Only fires when there are additional tokens (len > 1), confirming a
        # combosquat "brand-prefix + attack-suffix" pattern rather than an exact
        # TLD-swap already handled by the brand_label_identity check above.
        if brand_name and len(brand_name) >= 4:
            _sld_tokens = [t for t in candidate_name.replace('.', '-').split('-') if t]
            if len(_sld_tokens) > 1 and brand_name in _sld_tokens:
                score += 20
                # Risk-keyword amplifier: brand token co-occurs with a known
                # phishing/attack-suffix token → clear impersonation intent
                if any(tok in _COMBOSQUAT_RISK_KEYWORDS for tok in _sld_tokens):
                    score += 10

        # Suspicious TLD
        if tld in SUSPICIOUS_TLDS:
            score += 10

        # Short length difference
        if abs(len(original) - len(candidate)) <= 2:
            score += 2

        # === ACTUAL THREAT INDICATORS (these justify HIGH) ===
        # Page title contains brand keywords
        if page_title and brand_keywords:
            title_lower = page_title.lower()
            if any(kw.lower() in title_lower for kw in brand_keywords):
                score += 10

        # MX records present = email-capable phishing infrastructure
        if mx_records and len(mx_records) > 0:
            score += 8

        # Recently registered (within 90 days). Track a tighter "fresh" window
        # (<=30 days) separately to drive the interaction bonus below, and a
        # wider <=90d window (is_fresh_90) that the brand-content/active-threat
        # gate below uses as a positive recency signal. Unknown age leaves both
        # False (fail-closed — consistent with the Phase 2 backend null-age cap).
        is_fresh = False
        is_fresh_90 = False
        if whois_created:
            try:
                created_date = None
                # Each entry is (format_string, expected_date_string_length).
                # [:len(fmt)] was wrong — len(fmt) is the pattern length, not the
                # rendered date length (e.g. '%Y-%m-%d' is 8 chars but dates are 10).
                _fmt_widths = [
                    ('%Y-%m-%dT%H:%M:%SZ', 20),
                    ('%Y-%m-%d', 10),
                    ('%d-%b-%Y', 11),
                ]
                for fmt, width in _fmt_widths:
                    try:
                        created_date = datetime.strptime(whois_created.strip()[:width], fmt)
                        break
                    except ValueError:
                        continue
                if created_date:
                    age_days = (datetime.now() - created_date).days
                    if age_days <= 90:
                        score += 5
                        is_fresh_90 = True
                    if age_days <= 30:
                        is_fresh = True
            except Exception:
                pass

        # Interaction bonus: a registered, live (web-serving) near-miss
        # (Damerau distance <= 2) that is ALSO freshly registered is the single
        # highest-signal lookalike pattern — precisely the case the old additive
        # scoring under-weighted (a fresh, live transposition could land LOW).
        # Award a strong combined bonus. Still capped at HIGH below — CRITICAL
        # stays reserved for AI-confirmed phishing.
        if is_registered and has_web and dist <= 2 and is_fresh:
            score += 20

        # Suspicious external redirect: final URL domain differs from typosquat domain
        if final_url:
            try:
                final_host = urlparse(final_url).hostname or ''
                candidate_name = candidate.split('/')[0]  # strip any path
                if final_host and final_host != candidate_name:
                    score += 5
            except Exception:
                pass

        # VirusTotal detections: +15 to +25 risk based on malicious count
        if vt_detections and vt_detections.get('malicious', 0) > 0:
            malicious = vt_detections['malicious']
            if malicious >= 10:
                score += 25
            elif malicious >= 5:
                score += 20
            else:
                score += 15

        # PhishTank verified match: +25 risk, auto HIGH minimum
        if phishtank_match:
            score += 25

        # OpenPhish match: +20 risk
        if openphish_match:
            score += 20

        # Email security scoring (only relevant if MX records exist)
        if mx_records and len(mx_records) > 0 and email_security:
            spf = email_security.get('spf', {})
            dmarc = email_security.get('dmarc', {})
            # Has MX + no SPF: email spoofing possible
            if not spf.get('has_spf', False):
                score += 5
            # Has MX + SPF +all: allows any sender
            elif spf.get('spf_policy') == '+all':
                score += 8
            # Has MX + no DMARC
            if not dmarc.get('has_dmarc', False):
                score += 3
            # Has MX + DMARC p=none (monitoring only)
            elif dmarc.get('dmarc_policy') == 'none':
                score += 2

        # Hard cap: CRITICAL is reserved for AI-confirmed phishing only
        score = min(score, 75)

        # PhishTank match forces at least HIGH
        if phishtank_match and score < 50:
            score = 50

        # === Brand-content / active-threat gate for HIGH (Phase 3) ===
        # Structure-only resemblance (registration + web + SSL + lexical distance
        # + brand-label/combosquat shape + suspicious TLD + email-security gaps)
        # must NOT reach HIGH on its own. A HIGH band requires at least one
        # POSITIVE brand-intent / active-threat / hard-intel signal. This composes
        # with the Phase 2 backend null-age fail-closed cap — it is the agent-side
        # "positive-signal-required-for-HIGH" half of the same calibration.
        #
        # Any ONE of these qualifies a HIGH:
        #   - hard intel: VirusTotal malicious, PhishTank, or OpenPhish
        #   - the brand keyword appears in the live page <title>
        #   - email-capable (MX) AND freshly registered (<=90d)
        #   - freshly registered (<=90d)
        # NOTE: this function has NO kit/cloaking/login inputs (those are separate
        # engines); recall for those is carried by the backend T4 re-promote, so we
        # do NOT reference them here. Unknown registration age leaves is_fresh_90
        # False → treated as NOT fresh (fail-closed). The gate applies to ALL
        # brands regardless of token rarity (rare-vs-common is Phase 4).
        hard_intel = (
            (bool(vt_detections) and vt_detections.get('malicious', 0) > 0)
            or phishtank_match
            or openphish_match
        )
        title_brand_hit = bool(
            page_title and brand_keywords
            and any(kw.lower() in page_title.lower() for kw in brand_keywords)
        )
        has_mx = len(mx_records) > 0
        if (
            score >= 50
            and not hard_intel
            and not title_brand_hit
            and not (has_mx and is_fresh_90)
            and not is_fresh_90
        ):
            # Cap to the MEDIUM ceiling: structure-only cannot reach HIGH.
            score = 49

        if score >= 50:
            level = 'HIGH'
        elif score >= 30:
            level = 'MEDIUM'
        elif score >= 15:
            level = 'LOW'
        else:
            level = 'INFO'

        return (score, level)

    # -- Main execution --------------------------------------------------------

    async def execute(self, parameters: Dict[str, Any]) -> Any:
        """Generate domain permutations, resolve DNS, score and return results."""
        execution_start = time.time()

        # OpenPhish cache uses TTL-based expiry (1 hour) instead of per-execution
        # reset, which caused race conditions when concurrent executions cleared
        # the cache while another execution was using it (BUG-245).

        agent = parameters.get('_agent')
        domain = parameters.get('domain')
        domains = parameters.get('domains', [])
        targets = parameters.get('targets', [])
        techniques = parameters.get('techniques')
        check_dns = parameters.get('checkDns', True)
        max_variations = parameters.get('maxVariations', 500)
        brand_monitor_id = parameters.get('brandMonitorId')
        entropy_level = parameters.get('entropyLevel', 'HIGH').upper()
        enabled_techniques = parameters.get('enabledTechniques')
        max_edit_distance = parameters.get('maxEditDistance', 5)
        custom_tlds = parameters.get('customTlds')

        # Build list of domains to check (accept domain, domains, or targets)
        domain_list: List[str] = []
        if domain:
            domain_list.append(domain.lower().strip())
        if domains:
            domain_list.extend(d.lower().strip() for d in domains)
        if targets:
            domain_list.extend(t.lower().strip() for t in targets)
        if not domain_list:
            return {
                'success': False,
                'error': "Either 'domain', 'domains', or 'targets' parameter is required for typosquat:detect",
                'output': {'results': [], 'total_variations': 0, 'total_registered': 0},
                'raw_output': '',
            }

        # Entropy level -> technique mapping
        entropy_technique_map = {
            'LOW': ['homoglyph', 'tld_swap'],
            'MEDIUM': ['homoglyph', 'tld_swap', 'transposition', 'omission', 'subdomain'],
            'HIGH': [
                'homoglyph', 'transposition', 'omission', 'doubling', 'hyphen',
                'tld_swap', 'subdomain', 'bitsquatting', 'vowel_swap', 'addition',
                'combosquatting', 'soundsquatting', 'punycode_idn',
            ],
        }

        # Determine techniques to use (priority: enabledTechniques > techniques > entropyLevel)
        all_techniques = [
            'homoglyph', 'transposition', 'omission', 'doubling', 'hyphen',
            'tld_swap', 'subdomain', 'bitsquatting', 'vowel_swap', 'addition',
            'combosquatting', 'soundsquatting', 'punycode_idn',
        ]

        # Also accept full-form names and map to short forms
        technique_aliases = {
            'hyphen_insertion': 'hyphen',
            'subdomain_prepend': 'subdomain',
            'punycode': 'punycode_idn',
            'idn': 'punycode_idn',
        }

        if enabled_techniques:
            selected = [technique_aliases.get(t.lower().strip(), t.lower().strip()) for t in enabled_techniques]
        elif techniques:
            selected = [t.lower().strip() for t in techniques]
        elif entropy_level == 'CUSTOM':
            # CUSTOM requires enabledTechniques; fall back to HIGH
            selected = all_techniques
        else:
            selected = entropy_technique_map.get(entropy_level, all_techniques)

        technique_map = {
            'homoglyph': self._homoglyph,
            'transposition': self._transposition,
            'omission': self._omission,
            'doubling': self._doubling,
            'hyphen': self._hyphen_insertion,
            'tld_swap': lambda name, tld: self._tld_swap(name, tld, custom_tlds),
            'subdomain': self._subdomain_prepend,
            'bitsquatting': self._bitsquatting,
            'vowel_swap': self._vowel_swap,
            'addition': self._addition,
            'combosquatting': self._combosquatting,
            'soundsquatting': self._soundsquatting,
            'punycode_idn': self._punycode_idn,
        }

        try:
            # Process the first (or primary) domain for output structure
            primary_domain = domain_list[0]

            # -- Step 1: Generate permutations ---------------------------------
            if agent:
                agent.report_progress(
                    current_operation="Generating domain permutations...",
                    current_target=primary_domain,
                    items_processed=0,
                    total_items=None,
                )

            seen: Set[str] = set()
            # (domain_string, technique_name)
            variations: List[Tuple[str, str]] = []

            for d in domain_list:
                name, tld = self._split_domain(d)
                # Don't include the original domain itself
                seen.add(d)
                for tech_name in selected:
                    fn = technique_map.get(tech_name)
                    if not fn:
                        continue
                    candidates = fn(name, tld)
                    for candidate_domain, technique_label in candidates:
                        if candidate_domain not in seen:
                            seen.add(candidate_domain)
                            variations.append((candidate_domain, technique_label))
                            if len(variations) >= max_variations:
                                break
                    if len(variations) >= max_variations:
                        break
                if len(variations) >= max_variations:
                    break

            # Apply maxEditDistance filter
            if max_edit_distance and max_edit_distance > 0:
                original_count = len(variations)
                filtered = []
                for var_domain, technique in variations:
                    # Compute edit distance against the closest original domain
                    min_dist = min(self._levenshtein(d, var_domain) for d in domain_list)
                    if min_dist <= max_edit_distance:
                        filtered.append((var_domain, technique))
                if len(filtered) < original_count:
                    logger.info(f"[Typosquat] maxEditDistance={max_edit_distance} filtered {original_count - len(filtered)} variations")
                variations = filtered

            logger.info(f"[Typosquat] Generated {len(variations)} unique variations for {len(domain_list)} domain(s)")

            if agent:
                agent.report_progress(
                    current_operation=f"Generated {len(variations)} unique variations using {len(selected)} techniques",
                    current_target=primary_domain,
                    items_processed=len(variations),
                    total_items=len(variations),
                )

            # -- Step 2: DNS resolution ----------------------------------------
            results: List[Dict[str, Any]] = []
            registered_domains: List[str] = []

            if check_dns and variations:
                if agent:
                    agent.report_progress(
                        current_operation=f"Resolving DNS for {len(variations)} domains...",
                        current_target=primary_domain,
                        items_processed=0,
                        total_items=len(variations),
                    )

                # Batch DNS probes, 20 concurrent. Each probe resolves A / AAAA /
                # NS / MX so registration = (A OR AAAA OR NS OR MX), and reports a
                # rcode so NXDOMAIN (unregistered) is distinguished from
                # SERVFAIL/timeout (unknown). The MX from the probe is reused in
                # Step 3 (no second MX lookup for registered domains).
                batch_size = 20
                empty_probe = {
                    'a': [], 'aaaa': [], 'ns': [], 'mx': [],
                    'is_registered': False, 'registration_unknown': True,
                }
                all_probes: List[Dict[str, Any]] = []
                for i in range(0, len(variations), batch_size):
                    batch = variations[i:i + batch_size]
                    tasks = [self._dns_probe(v[0]) for v in batch]
                    batch_results = await asyncio.gather(*tasks, return_exceptions=True)
                    for r in batch_results:
                        if isinstance(r, Exception) or not isinstance(r, dict):
                            all_probes.append(dict(empty_probe))
                        else:
                            all_probes.append(r)

                # MX records captured during the registration probe, reused in
                # Step 3 so registered domains are not MX-looked-up twice.
                probe_mx: Dict[str, List[str]] = {}

                # Build initial results with DNS data
                for idx, (var_domain, technique) in enumerate(variations):
                    probe = all_probes[idx] if idx < len(all_probes) else empty_probe
                    ips = probe.get('a', [])
                    is_registered = probe.get('is_registered', False)
                    if is_registered:
                        registered_domains.append(var_domain)
                    if probe.get('mx'):
                        probe_mx[var_domain] = probe['mx']
                    dist = self._damerau_levenshtein(primary_domain, var_domain)
                    max_len = max(len(primary_domain), len(var_domain))
                    similarity = round(1.0 - (dist / max_len), 2) if max_len > 0 else 0.0
                    results.append({
                        'domain': var_domain,
                        'technique': technique,
                        'is_registered': is_registered,
                        # SERVFAIL/timeout marker — backend should not flip a
                        # previously-registered row to unregistered on a
                        # transient resolver failure (see _dns_probe).
                        'registration_unknown': probe.get('registration_unknown', False),
                        'resolved_ips': ips,
                        'resolved_ipv6': probe.get('aaaa', []),
                        'has_web_content': False,
                        'has_ssl_cert': False,
                        'http_status_code': 0,
                        'risk_score': 0,
                        'risk_level': 'INFO',
                        'similarity': similarity,
                        'page_title': None,
                    })

                logger.info(f"[Typosquat] DNS resolution complete: {len(registered_domains)}/{len(variations)} registered")

                if agent:
                    agent.report_progress(
                        current_operation=f"DNS resolution complete: {len(registered_domains)}/{len(variations)} registered",
                        current_target=primary_domain,
                        items_processed=len(variations),
                        total_items=len(variations),
                    )

                # -- Step 3: Score registered domains --------------------------
                if registered_domains:
                    if agent:
                        agent.report_progress(
                            current_operation=f"Scoring {len(registered_domains)} registered domains...",
                            current_target=primary_domain,
                            items_processed=0,
                            total_items=len(registered_domains),
                        )

                    # Extract brand keywords from primary domain name
                    primary_name, _ = self._split_domain(primary_domain)
                    brand_keywords = [primary_name]
                    # Also add parts split by hyphens (e.g., "my-brand" -> ["my-brand", "my", "brand"])
                    if '-' in primary_name:
                        brand_keywords.extend(p for p in primary_name.split('-') if len(p) >= 3)

                    # HTTP, SSL, MX, page title, VT, PhishTank, OpenPhish, SPF, DMARC, DKIM checks
                    # WHOIS runs in smaller batches (5) to avoid rate limiting/timeouts
                    http_results: Dict[str, Dict[str, Any]] = {}
                    ssl_results: Dict[str, bool] = {}
                    whois_results: Dict[str, Dict[str, Any]] = {}
                    mx_results: Dict[str, List[str]] = {}
                    title_results: Dict[str, Optional[str]] = {}
                    vt_results: Dict[str, Optional[Dict[str, Any]]] = {}
                    pt_results: Dict[str, bool] = {}
                    op_results: Dict[str, bool] = {}
                    spf_results: Dict[str, Dict[str, Any]] = {}
                    dmarc_results: Dict[str, Dict[str, Any]] = {}
                    dkim_results: Dict[str, Dict[str, Any]] = {}

                    # Pre-load OpenPhish feed (cached for entire scan)
                    await self._load_openphish_feed()

                    # Phase 1: HTTP, SSL, MX, title, VT, PhishTank, OpenPhish, SPF, DMARC, DKIM (batch 20)
                    for i in range(0, len(registered_domains), batch_size):
                        batch = registered_domains[i:i + batch_size]
                        http_tasks = [self._check_http(d) for d in batch]
                        ssl_tasks = [self._check_ssl(d) for d in batch]
                        title_tasks = [self._get_page_title(d) for d in batch]
                        vt_tasks = [self._check_virustotal(d) for d in batch]
                        pt_tasks = [self._check_phishtank(d) for d in batch]
                        op_tasks = [self._check_openphish(d) for d in batch]
                        spf_tasks = [self._check_spf(d) for d in batch]
                        dmarc_tasks = [self._check_dmarc(d) for d in batch]
                        dkim_tasks = [self._check_dkim(d) for d in batch]
                        http_batch = await asyncio.gather(*http_tasks, return_exceptions=True)
                        ssl_batch = await asyncio.gather(*ssl_tasks, return_exceptions=True)
                        title_batch = await asyncio.gather(*title_tasks, return_exceptions=True)
                        vt_batch = await asyncio.gather(*vt_tasks, return_exceptions=True)
                        pt_batch = await asyncio.gather(*pt_tasks, return_exceptions=True)
                        op_batch = await asyncio.gather(*op_tasks, return_exceptions=True)
                        spf_batch = await asyncio.gather(*spf_tasks, return_exceptions=True)
                        dmarc_batch = await asyncio.gather(*dmarc_tasks, return_exceptions=True)
                        dkim_batch = await asyncio.gather(*dkim_tasks, return_exceptions=True)
                        for j, d in enumerate(batch):
                            hr = http_batch[j]
                            sr = ssl_batch[j]
                            tr = title_batch[j]
                            vr = vt_batch[j]
                            pr = pt_batch[j]
                            opr = op_batch[j]
                            spfr = spf_batch[j]
                            dmr = dmarc_batch[j]
                            dkr = dkim_batch[j]
                            http_results[d] = hr if not isinstance(hr, Exception) else {'has_content': False, 'status_code': 0, 'redirect_chain': [], 'final_url': f'http://{d}'}
                            ssl_results[d] = sr if not isinstance(sr, Exception) else False
                            # MX was already resolved during the Step-2 registration
                            # probe — reuse it (no second lookup).
                            mx_results[d] = probe_mx.get(d, [])
                            title_results[d] = tr if not isinstance(tr, Exception) else None
                            vt_results[d] = vr if not isinstance(vr, Exception) else None
                            pt_results[d] = pr if not isinstance(pr, Exception) else False
                            op_results[d] = opr if not isinstance(opr, Exception) else False
                            spf_results[d] = spfr if not isinstance(spfr, Exception) else {'has_spf': False, 'spf_record': None, 'spf_policy': None}
                            dmarc_results[d] = dmr if not isinstance(dmr, Exception) else {'has_dmarc': False, 'dmarc_record': None, 'dmarc_policy': None}
                            dkim_results[d] = dkr if not isinstance(dkr, Exception) else {'has_dkim': False, 'dkim_selector': None}

                    # Phase 2: WHOIS + RDAP age (slow TCP, batch 5 to avoid rate
                    # limiting). RDAP is the PRIMARY source for the registration
                    # date (clean ISO from events[].eventAction=="registration"),
                    # falling back to the hardened port-43 `created` for ccTLDs
                    # without RDAP. The backend's field-level merge (`pref`) reads
                    # `whois_created` directly, so the RDAP override lands without
                    # disturbing the `whois_failed` preserve-prior contract.
                    whois_batch_size = 5
                    for i in range(0, len(registered_domains), whois_batch_size):
                        batch = registered_domains[i:i + whois_batch_size]
                        whois_tasks = [self._whois_lookup(d) for d in batch]
                        rdap_tasks = [self._rdap_created(d) for d in batch]
                        whois_batch = await asyncio.gather(*whois_tasks, return_exceptions=True)
                        rdap_batch = await asyncio.gather(*rdap_tasks, return_exceptions=True)
                        for j, d in enumerate(batch):
                            wr = whois_batch[j]
                            # An exception here is a hard WHOIS failure — mark it
                            # so the backend preserves prior data (WP-3) instead
                            # of overwriting persisted registrar/created with null.
                            wr = wr if not isinstance(wr, Exception) else {'registrar': None, 'created': None, 'expires': None, 'nameservers': [], 'whois_failed': True}
                            rd = rdap_batch[j]
                            rdap_created = rd if (rd and not isinstance(rd, Exception)) else None
                            if rdap_created:
                                # Prefer the clean RDAP ISO date over the port-43
                                # `created` (bypasses the first-match `created:`
                                # artifact, e.g. CIRA .ca).
                                wr = {**wr, 'created': rdap_created}
                            whois_results[d] = wr

                    # Update results with HTTP/SSL/VT/PhishTank/OpenPhish/email security data and scoring
                    for r in results:
                        if r['is_registered']:
                            d = r['domain']
                            http_data = http_results.get(d, {'has_content': False, 'status_code': 0, 'redirect_chain': [], 'final_url': f'http://{d}'})
                            has_web = http_data['has_content']
                            http_code = http_data['status_code']
                            has_ssl = ssl_results.get(d, False)
                            whois = whois_results.get(d, {})
                            # Filter empty/blank MX entries so the stored list
                            # (and the frontend Email chip) never sees a falsy
                            # MX that would imply mail capability.
                            mx = [m for m in (mx_results.get(d, []) or []) if m and m.strip()]
                            title = title_results.get(d)
                            vt = vt_results.get(d)
                            pt_match = pt_results.get(d, False)
                            op_match = op_results.get(d, False)
                            spf = spf_results.get(d, {'has_spf': False, 'spf_record': None, 'spf_policy': None})
                            dmarc = dmarc_results.get(d, {'has_dmarc': False, 'dmarc_record': None, 'dmarc_policy': None})
                            dkim = dkim_results.get(d, {'has_dkim': False, 'dkim_selector': None})
                            email_sec = {'spf': spf, 'dmarc': dmarc, 'dkim': dkim}
                            r['has_web_content'] = has_web
                            r['has_ssl_cert'] = has_ssl
                            r['http_status_code'] = http_code
                            r['redirect_chain'] = http_data['redirect_chain']
                            r['final_url'] = http_data['final_url']
                            r['whois_registrar'] = whois.get('registrar')
                            r['whois_created'] = whois.get('created')
                            r['whois_expires'] = whois.get('expires')
                            r['nameservers'] = whois.get('nameservers', [])
                            r['whois_registrant_email'] = whois.get('registrant_email')
                            r['whois_registrant_org'] = whois.get('registrant_org')
                            r['whois_registrant_name'] = whois.get('registrant_name')
                            r['whois_registrant_country'] = whois.get('registrant_country')
                            # WP-3: surface the failure marker so the backend can
                            # merge-don't-replace — a failed lookup must not null
                            # out previously-good registrar/registeredAt metadata.
                            r['whois_failed'] = whois.get('whois_failed', False)
                            r['mx_records'] = mx
                            r['page_title'] = title
                            r['phishtank_match'] = pt_match
                            r['openphish_match'] = op_match
                            r['email_security'] = email_sec
                            if vt:
                                r['vt_detections'] = vt
                            score, level = self._score_result(
                                primary_domain, d,
                                r['is_registered'], has_web, has_ssl,
                                page_title=title,
                                mx_records=mx,
                                brand_keywords=brand_keywords,
                                whois_created=whois.get('created'),
                                vt_detections=vt,
                                final_url=http_data['final_url'],
                                phishtank_match=pt_match,
                                openphish_match=op_match,
                                email_security=email_sec,
                            )
                            r['risk_score'] = score
                            r['risk_level'] = level

                    if agent:
                        agent.report_progress(
                            current_operation="Scoring complete",
                            current_target=primary_domain,
                            items_processed=len(registered_domains),
                            total_items=len(registered_domains),
                        )
            else:
                # No DNS check requested - just build results without resolution
                for var_domain, technique in variations:
                    dist = self._damerau_levenshtein(primary_domain, var_domain)
                    max_len = max(len(primary_domain), len(var_domain))
                    similarity = round(1.0 - (dist / max_len), 2) if max_len > 0 else 0.0
                    results.append({
                        'domain': var_domain,
                        'technique': technique,
                        'is_registered': False,
                        'registration_unknown': False,
                        'resolved_ips': [],
                        'resolved_ipv6': [],
                        'has_web_content': False,
                        'has_ssl_cert': False,
                        'http_status_code': 0,
                        'risk_score': 0,
                        'risk_level': 'INFO',
                        'similarity': similarity,
                        'page_title': None,
                    })

            # Sort by risk score descending
            results.sort(key=lambda r: r['risk_score'], reverse=True)

            execution_end = time.time()
            duration = round(execution_end - execution_start, 2)

            total_registered = sum(1 for r in results if r['is_registered'])
            critical_count = sum(1 for r in results if r['risk_level'] == 'CRITICAL')
            high_count = sum(1 for r in results if r['risk_level'] == 'HIGH')

            summary = (
                f"Typosquat detection for {primary_domain}: "
                f"{len(results)} variations generated, "
                f"{total_registered} registered, "
                f"{critical_count} critical, {high_count} high risk "
                f"({duration}s)"
            )
            logger.info(f"[Typosquat] {summary}")

            return {
                'success': True,
                'output': {
                    'domain': primary_domain,
                    'brandMonitorId': brand_monitor_id,
                    'total_variations': len(results),
                    'total_registered': total_registered,
                    'results': results,
                    'targets': registered_domains,
                    'tool': 'typosquat',
                    'scan_type': 'detect',
                },
                'raw_output': summary,
                'execution_metrics': {
                    'duration_seconds': duration,
                    'techniques_used': selected,
                    'domains_checked': len(domain_list),
                    'variations_generated': len(results),
                    'registered_found': total_registered,
                    'critical_count': critical_count,
                    'high_count': high_count,
                },
            }

        except Exception as e:
            execution_end = time.time()
            duration = round(execution_end - execution_start, 2)
            error_msg = f"Typosquat detection failed for {domain_list}: {e}"
            logger.error(f"[Typosquat] ERROR: {error_msg}", exc_info=True)
            return {
                'success': False,
                'output': {
                    'error': str(e),
                    'results': [],
                    'total_variations': 0,
                    'total_registered': 0,
                },
                'raw_output': error_msg,
                'execution_metrics': {
                    'duration_seconds': duration,
                },
            }


def get_tool():
    return TyposquatDetectTool()
