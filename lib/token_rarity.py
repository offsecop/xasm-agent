"""Token-rarity signal for brand-token scoring (Phase 4, P1-4 of #825).

The dictionary-word-brand FP class: a brand whose name is an ordinary word
(a common noun / adjective / verb form) collides with the entire ordinary
use of that word — a bare token match is NOT a threat signal for such brands,
while for a coined/rare brand (a made-up brandable string) the same
match is highly specific. This module is the ONE shared rarity primitive both
scoring producers consume:

  - typosquat_detect.py `_score_result` — the combosquat/containment and
    brand-label-identity bonuses are DAMPENED for a COMMON brand token unless a
    second anchor (attack-suffix keyword) corroborates impersonation intent.
  - brand_monitor_vip_exposure.py `_classify_serp_host` — the standalone-token
    combosquat rule (P0-4, #1056) no longer hard-emits IMPERSONATION/HIGH on an
    exact-but-common brand word without a second anchor.

Implementation: wordfreq Zipf frequency across six languages (en/es/fr/pt/de/
it). Two OR'd legs per the Phase-4 roadmap spec:

  frequency leg   max Zipf >= COMMON_ZIPF (2.5) — clearly common words
                  (everyday English nouns/adjectives read ~3-5; a common
                  romance-language verb form reads ~2.6).
  membership leg  max Zipf >= MEMBERSHIP_ZIPF (1.8) for an alphabetic token —
                  the dictionary-membership proxy. Catches lower-frequency but
                  REAL dictionary words the frequency leg misses (an ordinary
                  but uncommon dictionary word reads ~2.0 and must count as
                  common). Coined brandable names read 0.0 and stay RARE.

The roadmap's third leg (char-bigram surprisal) is deliberately deferred: the
two wordfreq legs already separate every calibration case, and a surprisal
model would add an embedded table with no current lock demanding it.

FAIL-OPEN: if wordfreq is unavailable (import error in a stripped env) every
token reads RARE — i.e. scoring behaves exactly as before this module existed.
A missing dep must never dampen real detections.

No brand literals live here (hardcode-tripwire discipline); the thresholds are
calibrated on generic corpus values, not on any client string.
"""

from typing import Dict, Optional

# Zipf >= this in ANY language → unambiguously common.
COMMON_ZIPF = 2.5
# Alphabetic token with Zipf >= this in ANY language → dictionary membership
# proxy (real-but-lower-frequency words like ordinary flower/plant names).
MEMBERSHIP_ZIPF = 1.8
# Languages consulted (wordfreq ships 'best' lists for all six).
LANGS = ("en", "es", "fr", "pt", "de", "it")

# Generic attack-suffix / credential-intent tokens usable as the SECOND ANCHOR
# a common brand word needs before a bare token match scores impersonation.
# Mirrors the intent of typosquat_detect._COMBOSQUAT_RISK_KEYWORDS (which stays
# authoritative for the typosquat engine); this exported set serves consumers
# that have no local list (the VIP exposure tool). Generic by design.
RISK_ANCHOR_TOKENS: frozenset = frozenset({
    "login", "signin", "sso", "secure", "verify", "verification",
    "account", "accounts", "support", "portal", "billing", "payment",
    "payments", "claim", "claims", "update", "wallet", "password",
    "helpdesk", "auth",
})

_wordfreq = None
_wordfreq_failed = False


def _zipf(token: str, lang: str) -> float:
    """wordfreq zipf_frequency with lazy import + fail-open on a missing dep."""
    global _wordfreq, _wordfreq_failed
    if _wordfreq_failed:
        return 0.0
    if _wordfreq is None:
        try:
            import wordfreq as _wf  # type: ignore
            _wordfreq = _wf
        except Exception:
            _wordfreq_failed = True
            return 0.0
    try:
        return float(_wordfreq.zipf_frequency(token, lang))
    except Exception:
        return 0.0


def score_token_rarity(token: str) -> Dict[str, float]:
    """Per-language Zipf frequencies + the max, for a lowercased token.

    Returns {'max': float, '<lang>': float, ...}. All zeros when the token is
    empty/unusable or wordfreq is unavailable (fail-open → RARE).
    """
    tok = (token or "").strip().lower()
    out: Dict[str, float] = {lang: 0.0 for lang in LANGS}
    out["max"] = 0.0
    if not tok:
        return out
    for lang in LANGS:
        z = _zipf(tok, lang)
        out[lang] = z
        if z > out["max"]:
            out["max"] = z
    return out


def is_common_token(token: str, scores: Optional[Dict[str, float]] = None) -> bool:
    """True when the token reads COMMON (ordinary language) — see module doc.

    A common brand token loses rarity protection: a bare match on it needs a
    second anchor before it counts as impersonation evidence. Tokens shorter
    than 3 chars are always treated as common (a 1-2 char token collides with
    everything). Non-alphabetic tokens never take the membership leg (a Zipf
    hit on '123' is corpus noise, not dictionary membership).
    """
    tok = (token or "").strip().lower()
    if not tok:
        return False
    if len(tok) < 3:
        return True
    s = scores if scores is not None else score_token_rarity(tok)
    mx = s.get("max", 0.0)
    if mx >= COMMON_ZIPF:
        return True
    return tok.isalpha() and mx >= MEMBERSHIP_ZIPF
