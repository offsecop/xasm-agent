"""UTS #39 confusables skeleton normalizer (shared DRP util).

Drives confusable / homoglyph detection from the Unicode Consortium
``confusables.txt`` snapshot (vendored under ``agent/lib/data/`` — no network at
runtime, mirroring the ``tldextract(suffix_list_urls=())`` bundled-snapshot
pattern) instead of the hand-maintained 25-entry ``HOMOGLYPH_MAP`` /
18-entry IDN ``CONFUSABLES`` tables that covered ~0.3% of the known confusable
space (see ``docs/drp-dorks-permutations-gap-analysis.md`` G2).

Public surface (consumed by the typosquat generator, the certstream CT matcher,
and social display-name detection):

- ``skeleton(s) -> str``        — UTS #39 skeleton (map each char to its prototype).
- ``is_confusable_with(a, b)``  — equal skeletons.
- ``is_mixed_script(s)``        — chars span more than one non-common script.
- ``is_whole_script_confusable(s, ascii_target)`` — ``s`` is a single non-Latin
  script whose skeleton equals the (Latin/ASCII) target's skeleton — the
  canonical IDN-homograph class (e.g. all-Cyrillic "paypal") that single-script
  maps and mixed-script heuristics both miss.

The skeleton algorithm is the UTS #39 definition
(https://www.unicode.org/reports/tr39/#Confusable_Detection):

    1. Convert X to NFD.
    2. Map each code point to its prototype from confusables.txt (value may be
       a multi-code-point sequence, e.g. ``m -> r n``).
    3. Convert the result to NFD.

NOTE ON GENERATION vs DETECTION: keep the small registration-practical glyph set
in ``typosquat_detect.py`` for *generation* (dnstwist does this deliberately — a
generator should only emit glyphs an attacker could plausibly register); use this
full dataset for *detection / normalization* only.
"""
from __future__ import annotations

import os
import re
import threading
import unicodedata
from typing import Dict, Optional

__all__ = [
    "skeleton",
    "is_confusable_with",
    "is_mixed_script",
    "is_whole_script_confusable",
    "script_of",
    "scripts_in",
    "CONFUSABLES_VERSION",
    "EXPECTED_CONFUSABLES_VERSION",
]

# The vendored snapshot we pin against. Bump this (and the data file) deliberately
# when refreshing — Unicode ships confusables yearly and a silent drift would
# change skeleton() output under every consumer.
EXPECTED_CONFUSABLES_VERSION = "16.0.0"

_DATA_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "confusables.txt")

# Lazily-parsed singleton state (parsing ~6.4k mappings once, on first use).
_MAP: Optional[Dict[str, str]] = None
_VERSION: Optional[str] = None
_LOCK = threading.Lock()

# confusables.txt data line:  XXXX ;\tYYYY [ZZZZ ...] ;\tTYPE\t# comment
_LINE_RE = re.compile(
    r"^([0-9A-Fa-f]{4,6})\s*;\s*((?:[0-9A-Fa-f]{4,6}\s*)+);", re.ASCII
)
_VERSION_RE = re.compile(r"^#\s*Version:\s*([0-9.]+)", re.ASCII)


def _load() -> Dict[str, str]:
    """Parse the vendored confusables.txt into {source_char: prototype_string}.

    Thread-safe, idempotent, offline. Source code points in confusables.txt are
    always single, so the key is a single-character string.
    """
    global _MAP, _VERSION
    if _MAP is not None:
        return _MAP
    with _LOCK:
        if _MAP is not None:  # double-checked under lock
            return _MAP
        mapping: Dict[str, str] = {}
        version: Optional[str] = None
        with open(_DATA_PATH, "r", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("#"):
                    if version is None:
                        m = _VERSION_RE.match(line)
                        if m:
                            version = m.group(1)
                    continue
                m = _LINE_RE.match(line)
                if not m:
                    continue
                source = chr(int(m.group(1), 16))
                target = "".join(chr(int(cp, 16)) for cp in m.group(2).split())
                mapping[source] = target
        _MAP = mapping
        _VERSION = version or "unknown"
    return _MAP


def _version() -> str:
    _load()
    return _VERSION or "unknown"


# Exposed as a module attribute via __getattr__ so it stays lazy (no parse at import).
def __getattr__(name: str):  # pragma: no cover - thin lazy accessor
    if name == "CONFUSABLES_VERSION":
        return _version()
    raise AttributeError(name)


def skeleton(s: str) -> str:
    """Return the UTS #39 skeleton of ``s`` (prototype of each character).

    Two strings are confusable iff their skeletons are equal. Empty in -> empty out.
    """
    if not s:
        return ""
    mapping = _load()
    decomposed = unicodedata.normalize("NFD", s)
    out = [mapping.get(ch, ch) for ch in decomposed]
    return unicodedata.normalize("NFD", "".join(out))


def is_confusable_with(a: str, b: str) -> bool:
    """True iff ``a`` and ``b`` collapse to the same UTS #39 skeleton."""
    return skeleton(a) == skeleton(b)


# --- Script detection -------------------------------------------------------
#
# Python's stdlib does not expose Unicode Script property, so we carry a compact
# range table covering the scripts that actually matter for homoglyph attacks on
# brand/domain/handle strings. COMMON (digits, punctuation, hyphen, symbols) and
# INHERITED (combining marks) are script-neutral and ignored by the mixed-script
# and whole-script checks.
_SCRIPT_RANGES = (
    # (start, end, script) — ordered; first match wins.
    (0x0041, 0x005A, "LATIN"),
    (0x0061, 0x007A, "LATIN"),
    (0x00C0, 0x024F, "LATIN"),   # Latin-1 Supplement + Extended-A/B
    (0x1E00, 0x1EFF, "LATIN"),   # Latin Extended Additional
    (0xFF21, 0xFF3A, "LATIN"),   # Fullwidth Latin uppercase
    (0xFF41, 0xFF5A, "LATIN"),   # Fullwidth Latin lowercase
    (0x0370, 0x03FF, "GREEK"),
    (0x1F00, 0x1FFF, "GREEK"),   # Greek Extended
    (0x0400, 0x04FF, "CYRILLIC"),
    (0x0500, 0x052F, "CYRILLIC"),  # Cyrillic Supplement
    (0x2DE0, 0x2DFF, "CYRILLIC"),
    (0xA640, 0xA69F, "CYRILLIC"),
    (0x0530, 0x058F, "ARMENIAN"),
    (0x0590, 0x05FF, "HEBREW"),
    (0x0600, 0x06FF, "ARABIC"),
    (0x0750, 0x077F, "ARABIC"),
    (0x10A0, 0x10FF, "GEORGIAN"),
    (0x13A0, 0x13FF, "CHEROKEE"),
    (0xAB70, 0xABBF, "CHEROKEE"),  # Cherokee Supplement
    (0x3040, 0x309F, "HIRAGANA"),
    (0x30A0, 0x30FF, "KATAKANA"),
    (0xAC00, 0xD7AF, "HANGUL"),
    (0x1100, 0x11FF, "HANGUL"),
    (0x4E00, 0x9FFF, "HAN"),
    (0x3400, 0x4DBF, "HAN"),
)

# Script-neutral code points that never make a string "mixed-script".
_COMMON_EXTRA = set(ord(c) for c in "0123456789-._")


def script_of(ch: str) -> str:
    """Return a coarse script name for a single character.

    'COMMON' for digits/punctuation/separators/symbols, 'INHERITED' for combining
    marks, otherwise one of the named scripts above (or 'OTHER').
    """
    cp = ord(ch)
    if cp in _COMMON_EXTRA:
        return "COMMON"
    category = unicodedata.category(ch)
    if category.startswith("M"):
        return "INHERITED"
    if category in ("Nd", "Nl", "No", "Pc", "Pd", "Ps", "Pe", "Pi", "Pf", "Po",
                    "Sm", "Sk", "Sc", "So", "Zs", "Cc", "Cf"):
        return "COMMON"
    for start, end, name in _SCRIPT_RANGES:
        if start <= cp <= end:
            return name
    return "OTHER"


def scripts_in(s: str) -> set:
    """Set of named scripts present in ``s`` (excluding COMMON/INHERITED)."""
    out = set()
    for ch in s:
        sc = script_of(ch)
        if sc not in ("COMMON", "INHERITED"):
            out.add(sc)
    return out


def is_mixed_script(s: str) -> bool:
    """True iff ``s`` contains characters from more than one named script.

    e.g. ``paypаl`` (Latin + one Cyrillic 'а') is mixed-script; pure ``paypal``
    is not. Digits, hyphens and dots are script-neutral and never trigger it.
    """
    return len(scripts_in(s)) > 1


def is_whole_script_confusable(s: str, ascii_target: str) -> bool:
    """True iff ``s`` is a single non-target script confusable with ``ascii_target``.

    This is the whole-script homograph class (e.g. an all-Cyrillic rendering of a
    Latin brand) that single-script maps and mixed-script heuristics both miss:
    ``s`` is NOT mixed-script (so the mixed-script detector stays silent) yet its
    skeleton equals the target's. Requires ``s`` to be a single named script
    different from the target's dominant script.
    """
    s_scripts = scripts_in(s)
    if len(s_scripts) != 1:
        return False
    target_scripts = scripts_in(ascii_target)
    # Same-script (e.g. both Latin) is a plain typo, not a whole-script homograph.
    if s_scripts and target_scripts and s_scripts == target_scripts:
        return False
    return skeleton(s) == skeleton(ascii_target)
