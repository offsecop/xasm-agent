"""
Typosquat Detection Tool
Generates domain permutations using 10 algorithms and checks for registered
look-alike domains that may be used for phishing or brand abuse.
"""

import asyncio
import logging
import os
import re
import sys
import time
from datetime import datetime
from typing import Dict, Any, List, Optional, Set, Tuple
from urllib.parse import urlparse

# Ensure agent/ is on sys.path so `from lib.integration_credentials import ...`
# works when the plugin is loaded via spec_from_file_location.
_parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _parent_dir not in sys.path:
    sys.path.append(_parent_dir)

from plugin_interface import ToolPlugin
from lib.dns_async import resolve_records  # noqa: E402
from lib.token_rarity import is_common_token  # noqa: E402
from lib.typosquat_enrich_helpers import TyposquatEnrichmentMixin  # noqa: E402

# PERM-3 — PSL-backed eTLD+1 split (replaces the hardcoded 13-entry double-TLD
# list that mis-split unlisted ccTLDs, losing the +12 brand-identity bonus).
# `suffix_list_urls=()` forces the bundled snapshot (no network at runtime / in
# tests). Guarded so the tool still loads if the dep is briefly absent during a
# partial agent rebuild — falls back to the last-label split.
try:
    import tldextract  # noqa: E402
    _TLD_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())
except Exception:  # pragma: no cover - import-time resilience only
    _TLD_EXTRACT = None

# PERM-5 — generation NO-OP floor. A 1-3 char brand label generates a junk,
# high-collision corpus (mirrors the social path's short-token discipline in
# wrapper_helpers); skip permutation generation for labels shorter than this.
MIN_BRAND_LABEL_LEN = 4

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

# Keyboard-adjacency (fat-finger) layouts — G1.
#
# Keyboard-mechanical errors are the empirically DOMINANT registered typo class
# (NDSS 2015, KU Leuven; WTMC 2019 "A Smörgåsbord of Typos" found 28,943
# registered typo domains targeting non-US layouts), yet we generated none.
# Each layout is defined as physical rows with a half-key horizontal stagger;
# adjacency (incl. diagonals) is derived from the grid so a new layout is one
# data entry, not a hand-maintained neighbour map (urlinsane ships ~40 layouts).
_KEYBOARD_GRIDS: Dict[str, List[Tuple[int, str]]] = {
    # (row_offset_in_half_keys, keys_left_to_right)
    'qwerty': [(0, '1234567890'), (1, 'qwertyuiop'), (2, 'asdfghjkl'), (3, 'zxcvbnm')],
    'azerty': [(0, '1234567890'), (1, 'azertyuiop'), (2, 'qsdfghjklm'), (3, 'wxcvbn')],
    'qwertz': [(0, '1234567890'), (1, 'qwertzuiop'), (2, 'asdfghjkl'), (3, 'yxcvbnm')],
}


def _build_adjacency(grid: List[Tuple[int, str]]) -> Dict[str, List[str]]:
    """Derive a per-key physical-neighbour map from a staggered keyboard grid.

    Keys are placed on a grid where each key spans 2 horizontal units and each
    row is offset by its half-key stagger. Two keys are neighbours when they are
    on the same row one key apart (col diff 2) or on an adjacent row within one
    half-key column (col diff <= 1) — i.e. left/right + the four diagonals.
    """
    positions: Dict[str, Tuple[int, int]] = {}
    for row_idx, (offset, keys) in enumerate(grid):
        for col_idx, ch in enumerate(keys):
            positions[ch] = (row_idx, offset + col_idx * 2)
    adjacency: Dict[str, List[str]] = {}
    for ch, (r, c) in positions.items():
        neighbours = []
        for other, (r2, c2) in positions.items():
            if other == ch:
                continue
            dr, dc = abs(r - r2), abs(c - c2)
            if (dr == 0 and dc == 2) or (dr == 1 and dc <= 1):
                neighbours.append(other)
        adjacency[ch] = sorted(neighbours)
    return adjacency


# Precompute adjacency maps once per layout.
KEYBOARD_ADJACENCY: Dict[str, Dict[str, List[str]]] = {
    name: _build_adjacency(grid) for name, grid in _KEYBOARD_GRIDS.items()
}
DEFAULT_KEYBOARD_LAYOUTS = ['qwerty']


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


# -- G2-ext (#451) expanded-coverage data tables ---------------------------------

# Homophone whole-word swaps (soundsquatting beyond the small SOUND_PAIRS set).
# Applied as substring substitutions; bidirectional pairs are listed both ways.
HOMOPHONES = {
    'for': 'four', 'four': 'for', 'to': 'two', 'two': 'to', 'too': 'two',
    'ate': 'eight', 'eight': 'ate', 'won': 'one', 'one': 'won',
    'be': 'bee', 'bee': 'be', 'sea': 'see', 'see': 'sea', 'buy': 'by',
    'by': 'buy', 'no': 'know', 'know': 'no', 'right': 'write', 'write': 'right',
    'their': 'there', 'there': 'their', 'your': 'youre', 'mail': 'male',
}

# Common-misspelling substring rules (a curated, registration-practical subset
# of the Wikipedia common-misspellings corpus — domain labels are short, so
# substring rules generalize better than a word-level dictionary).
MISSPELLING_RULES = [
    ('ie', 'ei'), ('ei', 'ie'), ('ance', 'ence'), ('ence', 'ance'),
    ('able', 'ible'), ('ible', 'able'), ('cc', 'c'), ('ss', 's'),
    ('ll', 'l'), ('mm', 'm'), ('nn', 'n'), ('tt', 't'),
    ('our', 'or'), ('or', 'our'), ('ize', 'ise'), ('ise', 'ize'),
    ('yze', 'yse'), ('ph', 'f'),
]

# Cardinal number-word <-> digit swaps (both directions).
CARDINAL_MAP = {
    'zero': '0', 'one': '1', 'two': '2', 'three': '3', 'four': '4',
    'five': '5', 'six': '6', 'seven': '7', 'eight': '8', 'nine': '9',
    'ten': '10',
}

# Ordinal word <-> short-form swaps (both directions).
ORDINAL_MAP = {
    'first': '1st', 'second': '2nd', 'third': '3rd', 'fourth': '4th',
    'fifth': '5th', 'sixth': '6th', 'seventh': '7th', 'eighth': '8th',
    'ninth': '9th', 'tenth': '10th',
}

# ccTLD second-level alternatives for the wrong-SLD technique (.co.uk -> .org.uk).
# Keyed on the public-suffix top label; only multi-label suffixes apply.
CCTLD_SECOND_LEVELS = {
    'uk': ['co', 'org', 'me', 'net', 'ltd', 'plc'],
    'au': ['com', 'net', 'org', 'id'],
    'nz': ['co', 'org', 'net', 'ac'],
    'za': ['co', 'org', 'net', 'web'],
    'br': ['com', 'net', 'org'],
    'jp': ['co', 'or', 'ne', 'ac'],
    'in': ['co', 'net', 'org', 'firm'],
}


class TyposquatDetectTool(ToolPlugin, TyposquatEnrichmentMixin):
    """
    DISCOVERY-ONLY typosquat detector: generates domain permutations using the
    23 permutation algorithms, resolves DNS (A/AAAA/NS/MX) to determine
    registration, and structurally risk-scores each candidate. Emits one
    discovery row per candidate.

    Per-registered-domain ENRICHMENT (HTTP/SSL/RDAP→WHOIS/threat-feeds/email-auth)
    is NOT done here — it runs in the decoupled `typosquat:enrich` queue (#1049).
    This tool still mixes in `TyposquatEnrichmentMixin` because `_dns_probe`
    reuses the mixin's `_mx_lookup`; the heavy enrichment methods are dormant on
    this path and live for `typosquat:enrich`.
    """

    @property
    def name(self) -> str:
        return "typosquat:detect"

    @property
    def description(self) -> str:
        return (
            "Detect typosquatting domains by generating permutations using 23 algorithms "
            "(homoglyph, keyboard adjacency, transposition, omission, doubling, hyphen insertion, "
            "TLD swap, subdomain prepend, bitsquatting, vowel swap, addition, combosquatting, "
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
                        "keyboard_adjacency, transposition, omission, doubling, hyphen, tld_swap, "
                        "subdomain, bitsquatting, vowel_swap, addition, combosquatting, "
                        "soundsquatting, punycode_idn, homophone, misspelling, plural, "
                        "cardinal_swap, ordinal_swap, dot_omission, dot_hyphen, wrong_sld, "
                        "multi_edit. Default: all"
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
                    "description": "Preset entropy level: LOW (homoglyph + TLD swap only), MEDIUM (+ transposition, omission, subdomain), HIGH (all 23 techniques), CUSTOM (use enabledTechniques)",
                    "default": "HIGH"
                },
                "enabledTechniques": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Explicit list of techniques to use (overrides entropyLevel). Options: homoglyph, keyboard_adjacency, transposition, omission, doubling, hyphen_insertion, tld_swap, subdomain_prepend, bitsquatting, vowel_swap, addition, combosquatting, soundsquatting, punycode_idn, homophone, misspelling, plural, cardinal_swap, ordinal_swap, dot_omission, dot_hyphen, wrong_sld, multi_edit"
                },
                "keyboardLayouts": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Locale keyboard layouts for the keyboard_adjacency (fat-finger) technique: qwerty (US, default), azerty (FR), qwertz (DE). Accepts a list or comma string; invalid entries are ignored and fall back to qwerty."
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
        """Split a domain into registrable-name and public-suffix parts.

        Handles multi-part TLDs (.co.uk, .ne.jp) via the PSL. Returns (name, tld)
        where tld includes the leading dot (e.g., '.com'). NOTE: a subdomain is
        dropped (www.brand.com -> ('brand', '.com')) — intended for brand-monitor
        apex inputs; callers needing the full sub-label must not rely on this.
        """
        domain = domain.lower().strip().rstrip('.')
        # PERM-3 — PSL-backed split: the registrable label + the full public
        # suffix (eTLD), so multi-label ccTLDs (.ne.jp, .com.sg, .co.uk) split
        # correctly and the brand-identity bonus fires on the real brand label.
        if _TLD_EXTRACT is not None:
            ext = _TLD_EXTRACT(domain)
            if ext.domain and ext.suffix:
                return (ext.domain, '.' + ext.suffix)
        # Fallback (dep absent, or no recognised suffix): last-label split.
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

    def _keyboard_adjacency(
        self, name: str, tld: str, layouts: Optional[List[str]] = None
    ) -> List[Tuple[str, str]]:
        """Fat-finger fuzzer — substitute and insert physically adjacent keys (G1).

        For each character, emit (a) substitutions with each physically adjacent
        key and (b) an insertion of each adjacent key after that character. Runs
        across the requested locale layouts (default US-QWERTY) so EU-targeted
        typos (German QWERTZ, French AZERTY) are generated for those clients.
        Honours _is_valid_label; the joint max_variations budget is enforced by
        the caller.
        """
        selected = layouts or DEFAULT_KEYBOARD_LAYOUTS
        results: List[Tuple[str, str]] = []
        local_seen: Set[str] = set()
        for layout in selected:
            adjacency = KEYBOARD_ADJACENCY.get(layout)
            if not adjacency:
                continue
            for i, ch in enumerate(name):
                for neighbour in adjacency.get(ch, []):
                    # Substitution: replace ch with an adjacent key.
                    sub = name[:i] + neighbour + name[i + 1:]
                    if sub != name and sub not in local_seen and self._is_valid_label(sub):
                        local_seen.add(sub)
                        results.append((sub + tld, 'KEYBOARD_ADJACENCY'))
                    # Insertion: add an adjacent key right after ch (mis-hit two keys).
                    ins = name[:i + 1] + neighbour + name[i + 1:]
                    if ins not in local_seen and self._is_valid_label(ins):
                        local_seen.add(ins)
                        results.append((ins + tld, 'KEYBOARD_ADJACENCY'))
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

    def _homophone(self, name: str, tld: str) -> List[Tuple[str, str]]:
        """Whole-word homophone swaps (soundsquatting beyond SOUND_PAIRS, G2-ext)."""
        results: List[Tuple[str, str]] = []
        for orig, repl in HOMOPHONES.items():
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

    def _misspelling_dict(self, name: str, tld: str) -> List[Tuple[str, str]]:
        """Common-misspelling substring substitutions (G2-ext)."""
        results: List[Tuple[str, str]] = []
        for orig, repl in MISSPELLING_RULES:
            idx = 0
            while True:
                idx = name.find(orig, idx)
                if idx == -1:
                    break
                candidate = name[:idx] + repl + name[idx + len(orig):]
                if candidate != name and self._is_valid_label(candidate):
                    results.append((candidate + tld, 'MISSPELLING'))
                idx += 1
        return results

    def _plural(self, name: str, tld: str) -> List[Tuple[str, str]]:
        """Plural/singular toggle. Adding a char -> ADDITION; removing -> OMISSION."""
        results: List[Tuple[str, str]] = []
        if name.endswith('s') and len(name) > 1:
            singular = name[:-1]
            if self._is_valid_label(singular):
                results.append((singular + tld, 'OMISSION'))
        else:
            plural = name + 's'
            if self._is_valid_label(plural):
                results.append((plural + tld, 'ADDITION'))
            # English y -> ies pluralization (company -> companies).
            if name.endswith('y') and len(name) > 1:
                ies = name[:-1] + 'ies'
                if self._is_valid_label(ies):
                    results.append((ies + tld, 'ADDITION'))
        return results

    def _cardinal_swap(self, name: str, tld: str) -> List[Tuple[str, str]]:
        """Cardinal number-word <-> digit swaps (one<->1), G2-ext."""
        return self._token_swaps(name, tld, CARDINAL_MAP, 'CARDINAL_SWAP')

    def _ordinal_swap(self, name: str, tld: str) -> List[Tuple[str, str]]:
        """Ordinal word <-> short-form swaps (first<->1st), G2-ext."""
        return self._token_swaps(name, tld, ORDINAL_MAP, 'ORDINAL_SWAP')

    def _token_swaps(
        self, name: str, tld: str, mapping: Dict[str, str], label: str
    ) -> List[Tuple[str, str]]:
        """Bidirectional substring swaps from a word<->token map (helper)."""
        results: List[Tuple[str, str]] = []
        seen: Set[str] = set()
        # Build both directions: word->token and token->word.
        pairs = list(mapping.items()) + [(v, k) for k, v in mapping.items()]
        # Longest source first so multi-char tokens win over their substrings.
        for orig, repl in sorted(pairs, key=lambda p: -len(p[0])):
            idx = 0
            while True:
                idx = name.find(orig, idx)
                if idx == -1:
                    break
                candidate = name[:idx] + repl + name[idx + len(orig):]
                if candidate != name and candidate not in seen and self._is_valid_label(candidate):
                    seen.add(candidate)
                    results.append((candidate + tld, label))
                idx += 1
        return results

    def _dot_omission(self, name: str, tld: str) -> List[Tuple[str, str]]:
        """Omit the separating dot — fold a leading 'www' into the SLD (G2-ext).

        Classified SUBDOMAIN_PREPEND (brand-containing prepend without separator).
        """
        results: List[Tuple[str, str]] = []
        candidate = 'www' + name
        if self._is_valid_label(candidate):
            results.append((candidate + tld, 'SUBDOMAIN_PREPEND'))
        return results

    def _dot_hyphen(self, name: str, tld: str) -> List[Tuple[str, str]]:
        """Dot<->hyphen substitution within the label (G2-ext).

        A hyphenated brand collapses (my-brand -> mybrand) or its hyphen becomes a
        sub-label dot (my-brand -> my.brand); a non-hyphenated brand inserts a
        hyphen at each boundary (covered by _hyphen_insertion, so here we only act
        on names that already carry a hyphen). Classified HYPHEN_INSERTION.
        """
        results: List[Tuple[str, str]] = []
        if '-' in name:
            collapsed = name.replace('-', '')
            if collapsed and self._is_valid_label(collapsed):
                results.append((collapsed + tld, 'HYPHEN_INSERTION'))
            dotted = name.replace('-', '.')
            # dotted creates a sub-label; valid as a full host even if the SLD
            # label itself isn't (each part must be a valid label).
            if all(self._is_valid_label(p) for p in dotted.split('.') if p):
                results.append((dotted + tld, 'HYPHEN_INSERTION'))
        return results

    def _wrong_sld(self, name: str, tld: str) -> List[Tuple[str, str]]:
        """ccTLD wrong second-level-domain swap (.co.uk -> .org.uk), G2-ext.

        Only applies to multi-label public suffixes; classified TLD_SWAP.
        """
        results: List[Tuple[str, str]] = []
        suffix = tld.lstrip('.')
        labels = suffix.split('.')
        if len(labels) < 2:
            return results  # single-label TLD has no second level to vary
        second, top = labels[0], labels[-1]
        for alt in CCTLD_SECOND_LEVELS.get(top, []):
            if alt == second:
                continue
            new_tld = '.' + alt + '.' + top
            results.append((name + new_tld, 'TLD_SWAP'))
        return results

    def _multi_edit(
        self, name: str, tld: str, max_candidates: int = 60
    ) -> List[Tuple[str, str]]:
        """Bounded 2-edit combo: omission + an adjacent transposition (G2-ext).

        Two simultaneous single edits catch lookalikes a 1-edit generator misses.
        HARD-capped (max_candidates) to avoid the combinatorial explosion.
        """
        results: List[Tuple[str, str]] = []
        seen: Set[str] = set()
        # First edit: each single-char omission. Second edit: an adjacent
        # transposition on the result. Bounded by max_candidates.
        for i in range(len(name)):
            if len(results) >= max_candidates:
                break
            first = name[:i] + name[i + 1:]
            if len(first) < 2:
                continue
            for j in range(len(first) - 1):
                candidate = first[:j] + first[j + 1] + first[j] + first[j + 2:]
                if (
                    candidate != name
                    and candidate not in seen
                    and self._is_valid_label(candidate)
                ):
                    seen.add(candidate)
                    results.append((candidate + tld, 'MULTI_EDIT'))
                    if len(results) >= max_candidates:
                        break
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
        """Query one DNS record type and return ``(records, status)``.

        In-process async resolution (dnspython) — NO ``dig`` subprocess. Status
        is the legacy rcode contract (``NOERROR`` / ``NXDOMAIN`` / ``SERVFAIL`` /
        ``TIMEOUT``) so the caller can tell a genuine NXDOMAIN (name does not
        exist → unregistered) from a SERVFAIL/timeout (resolver couldn't answer →
        registration UNKNOWN, do NOT force ``is_registered=False``). UDP-first
        with a TCP fallback for UDP-blocked resolvers — see ``lib.dns_async``.
        """
        return await resolve_records(domain, rrtype)

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
        # 2LD label (e.g. brand.io vs brand.com — a TLD swap of the exact
        # brand name). Full-domain Levenshtein under-weights these vs unrelated
        # 1-char-off near-misses, so award a strong, distance-independent bonus
        # so an exact-name impersonation on another TLD outranks a coincidental
        # near-miss. Additive and cap-coherent with the band thresholds.
        #
        # Phase 4 (P1-4 #825) — TOKEN-RARITY DAMPENER. For a COMMON-WORD brand
        # (an ordinary dictionary word — `is_common_token`, wordfreq Zipf
        # across en/es/fr/pt/de/it) an exact name match collides with the
        # ordinary use of the word (unrelated businesses that simply own the
        # word on another TLD), so the identity bonus is dampened to +6. A RARE
        # (coined) brand keeps the full +12 — the same match is highly specific
        # there. Fail-open: a missing wordfreq reads RARE (full bonus).
        candidate_name, tld = self._split_domain(candidate)
        brand_name, _ = self._split_domain(original)
        brand_is_common = bool(brand_name) and is_common_token(brand_name)
        if brand_name and candidate_name == brand_name:
            score += 6 if brand_is_common else 12

        # Combosquat / brand-containment signal: the candidate SLD contains the
        # brand token as a STANDALONE word (split on hyphens/dots), NOT a mere
        # substring — so "accertacontabil" and "corpaccertio" do NOT match.
        # Only fires when there are additional tokens (len > 1), confirming a
        # combosquat "brand-prefix + attack-suffix" pattern rather than an exact
        # TLD-swap already handled by the brand_label_identity check above.
        #
        # Phase 4 (P1-4 #825) — rarity-aware containment. A COMMON brand word
        # standing alone next to a NEUTRAL token ("mode-hub", "sol-garden") is
        # the dictionary-collision shape, not impersonation — dampened to +6.
        # The SECOND ANCHOR (a risk/attack-suffix keyword co-occurring in the
        # SLD) restores the full +20 (+10 amplifier): "mode-login" is an attack
        # shape regardless of how common "mode" is. RARE brand tokens keep the
        # full +20 unconditionally (containment of a coined name IS the signal).
        if brand_name and len(brand_name) >= 4:
            _sld_tokens = [t for t in candidate_name.replace('.', '-').split('-') if t]
            if len(_sld_tokens) > 1 and brand_name in _sld_tokens:
                # Risk-keyword anchor: brand token co-occurs with a known
                # phishing/attack-suffix token → clear impersonation intent
                _has_risk_kw = any(
                    tok in _COMBOSQUAT_RISK_KEYWORDS for tok in _sld_tokens
                )
                if brand_is_common and not _has_risk_kw:
                    score += 6
                else:
                    score += 20
                    if _has_risk_kw:
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
            # POST-1 — skip the "missing posture" weights when the lane is UNSWEPT
            # (blind resolver / dig timeout); a non-answer must not inflate risk as
            # if the record were confirmed absent.
            if not spf.get('spf_unswept', False):
                # Has MX + no SPF: email spoofing possible
                if not spf.get('has_spf', False):
                    score += 5
                # Has MX + SPF +all: allows any sender
                elif spf.get('spf_policy') == '+all':
                    score += 8
                # POST-2 — neutral (?all) / soft-fail (~all): effectively permits
                # spoofing, previously scored as zero email-posture risk.
                elif spf.get('spf_policy') in ('?all', '~all'):
                    score += 5
            if not dmarc.get('dmarc_unswept', False):
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
        # brands regardless of token rarity — the Phase 4 rarity dampener
        # (P1-4 #825) acts EARLIER, on the identity/containment bonuses above,
        # so a common-word brand rarely reaches this gate on structure alone.
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
        # G1 — locale-aware keyboard layouts for the fat-finger fuzzer. Accept a
        # list or comma string; normalize + validate against known layouts; an
        # empty/invalid selection falls back to US-QWERTY.
        kbd_raw = parameters.get('keyboardLayouts')
        if isinstance(kbd_raw, str):
            kbd_raw = [s for s in re.split(r'[,\s]+', kbd_raw) if s]
        keyboard_layouts = [
            layout for layout in (l.lower().strip() for l in (kbd_raw or []))
            if layout in KEYBOARD_ADJACENCY
        ] or DEFAULT_KEYBOARD_LAYOUTS

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
                'homoglyph', 'keyboard_adjacency', 'transposition', 'omission', 'doubling', 'hyphen',
                'tld_swap', 'subdomain', 'bitsquatting', 'vowel_swap', 'addition',
                'combosquatting', 'soundsquatting', 'punycode_idn',
                # G2-ext (#451) expanded coverage
                'homophone', 'misspelling', 'plural', 'cardinal_swap', 'ordinal_swap',
                'dot_omission', 'dot_hyphen', 'wrong_sld', 'multi_edit',
            ],
        }

        # Determine techniques to use (priority: enabledTechniques > techniques > entropyLevel)
        all_techniques = [
            'homoglyph', 'keyboard_adjacency', 'transposition', 'omission', 'doubling', 'hyphen',
            'tld_swap', 'subdomain', 'bitsquatting', 'vowel_swap', 'addition',
            'combosquatting', 'soundsquatting', 'punycode_idn',
            'homophone', 'misspelling', 'plural', 'cardinal_swap', 'ordinal_swap',
            'dot_omission', 'dot_hyphen', 'wrong_sld', 'multi_edit',
        ]

        # Also accept full-form names and map to short forms
        technique_aliases = {
            'hyphen_insertion': 'hyphen',
            'subdomain_prepend': 'subdomain',
            'punycode': 'punycode_idn',
            'idn': 'punycode_idn',
            # G2-ext aliases
            'misspelling_dict': 'misspelling',
            'homophones': 'homophone',
            'cardinal': 'cardinal_swap',
            'ordinal': 'ordinal_swap',
            'plural_singular': 'plural',
            'multiedit': 'multi_edit',
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
            'keyboard_adjacency': lambda name, tld: self._keyboard_adjacency(name, tld, keyboard_layouts),
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
            # G2-ext (#451) expanded coverage
            'homophone': self._homophone,
            'misspelling': self._misspelling_dict,
            'plural': self._plural,
            'cardinal_swap': self._cardinal_swap,
            'ordinal_swap': self._ordinal_swap,
            'dot_omission': self._dot_omission,
            'dot_hyphen': self._dot_hyphen,
            'wrong_sld': self._wrong_sld,
            'multi_edit': self._multi_edit,
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

            # Resolve eligible domains once. PERM-5 — min-brand-len NO-OP: a 1-3
            # char brand label produces a junk, high-collision corpus (every short
            # permutation resolves to unrelated registered domains), so skip
            # generation for it (mirrors the social short-token discipline; the
            # brand is still covered by exact-match + social monitoring).
            eligible: List[Tuple[str, str, str]] = []
            for d in domain_list:
                name, tld = self._split_domain(d)
                seen.add(d)  # don't include the original domain itself
                if len(name) < MIN_BRAND_LABEL_LEN:
                    logger.info(
                        f"[Typosquat] NO-OP generation for short brand label "
                        f"'{name}' (<{MIN_BRAND_LABEL_LEN} chars) — junk-corpus guard"
                    )
                    continue
                eligible.append((d, name, tld))

            # PERM-1/9 — brand-containment techniques run on a SEPARATE pass that
            # BYPASSES the max_variations budget, so the credential-phish/BEC lures
            # (brand-login / secure-brand / brand-verify) are ALWAYS produced and
            # reach DNS. Previously they were doubly lost: starved by the budget
            # (they sit late in the technique order) AND dropped by the edit-
            # distance filter. Bounded by a generous safety cap.
            EXEMPT_TECH_NAMES = {'combosquatting', 'subdomain'}
            EXEMPT_SAFETY_CAP = max(max_variations * 2, 1000)
            for d, name, tld in eligible:
                for tech_name in selected:
                    if tech_name not in EXEMPT_TECH_NAMES:
                        continue
                    fn = technique_map.get(tech_name)
                    if not fn:
                        continue
                    for candidate_domain, technique_label in fn(name, tld):
                        if candidate_domain not in seen:
                            seen.add(candidate_domain)
                            variations.append((candidate_domain, technique_label))
                    if len(variations) >= EXEMPT_SAFETY_CAP:
                        break
                if len(variations) >= EXEMPT_SAFETY_CAP:
                    break

            # Budgeted-typo pass — the classic character-level techniques
            # (homoglyph / transposition / omission / keyboard-adjacency / …).
            # #1048: give these their OWN budget of `max_variations`, counted
            # independently of the exempt lures already produced above. Counting
            # jointly meant that once the exempt pass (~238 lures) exceeded
            # `max_variations`, this pass broke before generating a single typo —
            # so a low `max_variations` (default 50) silently starved the
            # highest-recall detection classes to ZERO. Now total candidates =
            # exempt lures (bounded by EXEMPT_SAFETY_CAP) + up to `max_variations`
            # typos, and lowering `max_variations` can never zero the typo set.
            exempt_count = len(variations)
            for d, name, tld in eligible:
                if (len(variations) - exempt_count) >= max_variations:
                    break
                for tech_name in selected:
                    if tech_name in EXEMPT_TECH_NAMES:
                        continue
                    fn = technique_map.get(tech_name)
                    if not fn:
                        continue
                    for candidate_domain, technique_label in fn(name, tld):
                        if candidate_domain not in seen:
                            seen.add(candidate_domain)
                            variations.append((candidate_domain, technique_label))
                            if (len(variations) - exempt_count) >= max_variations:
                                break
                    if (len(variations) - exempt_count) >= max_variations:
                        break

            # Apply maxEditDistance filter.
            # PERM-1/9 — EXEMPT brand-containment techniques (COMBOSQUATTING,
            # SUBDOMAIN_PREPEND). They append/prepend whole tokens, so the
            # full-domain edit distance is large by construction (questrade-login
            # = 6, secure-questrade = 7) and the default max of 5 dropped them
            # BEFORE DNS — the resolver never saw the registered brand-login /
            # secure-brand / brand-verify credential-phish/BEC lure class. These
            # techniques are inherently brand-relevant (the brand is a standalone
            # token), so they bypass the lexical-distance filter entirely.
            EDIT_DISTANCE_EXEMPT = {'COMBOSQUATTING', 'SUBDOMAIN_PREPEND'}
            if max_edit_distance and max_edit_distance > 0:
                original_count = len(variations)
                filtered = []
                for var_domain, technique in variations:
                    if technique in EDIT_DISTANCE_EXEMPT:
                        filtered.append((var_domain, technique))
                        continue
                    # #576 — length pre-filter (provably output-identical). Edit
                    # distance is bounded below by the length difference
                    # (damerau(a,b) >= |len(a)-len(b)|), so if the SMALLEST length
                    # gap to any original domain already exceeds maxEditDistance,
                    # the Damerau distance cannot satisfy the threshold — reject
                    # WITHOUT running the O(L²) matrix. This skips the expensive DP
                    # for the length-impossible majority of a ~1500-candidate corpus.
                    min_len_diff = min(abs(len(d) - len(var_domain)) for d in domain_list)
                    if min_len_diff > max_edit_distance:
                        continue
                    # Compute edit distance against the closest original domain.
                    # Damerau (transposition = 1) to match the scorer's distance
                    # metric (_score_result uses _damerau_levenshtein) so a tight
                    # maxEditDistance doesn't pre-drop near-misses the scorer keeps.
                    min_dist = min(self._damerau_levenshtein(d, var_domain) for d in domain_list)
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

            # -- Step 2: DNS probe + structural scoring (DISCOVERY-ONLY) -------
            # #1049 — this tool is now discovery-only. It resolves DNS to
            # establish registration and structurally risk-scores each candidate
            # from DNS/structural signals alone. Per-registered-domain enrichment
            # (HTTP/SSL/WHOIS/RDAP/threat-feeds/email-auth) has moved to the
            # decoupled `typosquat:enrich` queue — doing it here would
            # double-enrich. Enrichment-derived severity (fresh-registration,
            # live-page, hard-intel) is filled in async by that queue; discovery
            # carries structural severity only ("structure now, age fills in").
            results: List[Dict[str, Any]] = []
            registered_domains: List[str] = []

            # Brand keywords from the primary domain name (structural scoring input).
            primary_name, _ = self._split_domain(primary_domain)
            brand_keywords = [primary_name]
            # Also add parts split by hyphens (e.g. "my-brand" -> ["my-brand", "my", "brand"])
            if '-' in primary_name:
                brand_keywords.extend(p for p in primary_name.split('-') if len(p) >= 3)

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
                # SERVFAIL/timeout (unknown). MX from the probe feeds structural
                # scoring (email-capable signal) and is carried on the row.
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

                # Build discovery rows: DNS registration facts + structural score.
                for idx, (var_domain, technique) in enumerate(variations):
                    probe = all_probes[idx] if idx < len(all_probes) else empty_probe
                    ips = probe.get('a', [])
                    is_registered = probe.get('is_registered', False)
                    if is_registered:
                        registered_domains.append(var_domain)
                    # Filter empty/blank MX entries so the stored list (and the
                    # frontend Email chip) never sees a falsy MX implying mail
                    # capability. MX is a DISCOVERY signal (from the probe), not
                    # enrichment.
                    mx = [m for m in (probe.get('mx') or []) if m and m.strip()]
                    dist = self._damerau_levenshtein(primary_domain, var_domain)
                    max_len = max(len(primary_domain), len(var_domain))
                    similarity = round(1.0 - (dist / max_len), 2) if max_len > 0 else 0.0
                    # Structural score from DNS/structural signals only. Enrichment
                    # inputs (has_web/has_ssl/page_title/whois/VT/feeds/email-auth)
                    # are absent → they degrade gracefully to no-bonus in
                    # _score_result, and the HIGH gate caps structure-only at
                    # MEDIUM (49) until the enrich queue supplies a positive signal.
                    score, level = self._score_result(
                        primary_domain, var_domain,
                        is_registered, False, False,
                        mx_records=mx,
                        brand_keywords=brand_keywords,
                    )
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
                        'nameservers': probe.get('ns', []),
                        'mx_records': mx,
                        'risk_score': score,
                        'risk_level': level,
                        'similarity': similarity,
                    })

                logger.info(f"[Typosquat] DNS resolution complete: {len(registered_domains)}/{len(variations)} registered")

                if agent:
                    agent.report_progress(
                        current_operation=f"DNS resolution complete: {len(registered_domains)}/{len(variations)} registered",
                        current_target=primary_domain,
                        items_processed=len(variations),
                        total_items=len(variations),
                    )
            else:
                # No DNS check requested — build unresolved discovery rows.
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
                        'nameservers': [],
                        'mx_records': [],
                        'risk_score': 0,
                        'risk_level': 'INFO',
                        'similarity': similarity,
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
