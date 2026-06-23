"""Shared vendor-wrapper helpers.

Canonical implementations of the four utility helpers that were duplicated
across nine vendor-wrapper tools in `agent/tools/` (HikerAPI brand/vip,
ScrapeCreators ads/reddit/reddit_search/threads_search/tiktok_search/
youtube_search/youtube_deep_dive). Module-level functions — no class.

Phase 3a consolidation, recorded in `audit/phase-3a-report.md`.

Phase 8 (2026-05-19) added `resolve_targets`, hoisted from 6 verbatim copies
across `nmap_*.py`, `katana_enumerate.py`, `gowitness_screenshot.py`, and
`origami_browser_dast.py`. Two tools intentionally diverge and keep local
copies: `testssl_scan.py` strips whitespace, and `dns_resolve.py` applies
hostname normalization across more parameter keys.
"""

from __future__ import annotations

import json
import re
from difflib import SequenceMatcher
from typing import Any, Dict, List, Optional, Tuple


def first(d: Dict[str, Any], *keys: str) -> Any:
    """Return the first non-None value among `d[keys[0]]`, `d[keys[1]]`, ...

    Tolerates non-dict input (returns None) — the most-defensive shape from
    `hiker_brand.py` / `hiker_vip.py` is the canonical one.
    """
    if not isinstance(d, dict):
        return None
    for k in keys:
        v = d.get(k)
        if v is not None:
            return v
    return None


def similarity(a: str, b: str) -> float:
    """Lowercased SequenceMatcher ratio. Same body in hiker_brand / hiker_vip."""
    return SequenceMatcher(None, (a or '').lower(), (b or '').lower()).ratio()


def build_account(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize a HikerAPI account dict (full envelope OR lite shape).

    Identical body across `hiker_brand.py` and `hiker_vip.py`.
    """
    if not isinstance(raw, dict):
        return {}
    inner = raw.get('user') if isinstance(raw.get('user'), dict) else raw
    if not isinstance(inner, dict):
        inner = {}
    raw_pk = first(inner, 'pk', 'id')
    username = str(first(inner, 'username', 'user_name') or '')
    profile_url = (
        f'https://www.instagram.com/{username}/' if username else ''
    )
    follower_count_raw = first(inner, 'follower_count', 'followers')
    follower_count: Optional[int] = (
        int(follower_count_raw) if isinstance(follower_count_raw, (int, float)) else None
    )
    media_count_raw = first(inner, 'media_count', 'post_count')
    media_count: Optional[int] = (
        int(media_count_raw) if isinstance(media_count_raw, (int, float)) else None
    )
    bio_raw = first(inner, 'biography', 'bio')
    biography: Optional[str] = bio_raw[:500] if isinstance(bio_raw, str) else None
    return {
        'handle': username,
        'display_name': first(inner, 'full_name', 'name') or '',
        'profile_url': profile_url,
        'profile_pic_url': first(inner, 'profile_pic_url', 'profile_pic_url_hd') or '',
        'follower_count': follower_count,
        'biography': biography,
        'is_verified': bool(first(inner, 'is_verified', 'verified') or False),
        'is_private': bool(first(inner, 'is_private', 'private') or False),
        'pk': int(raw_pk) if raw_pk not in (None, '') else None,
        'media_count': media_count,
        'account_type': first(inner, 'account_type'),
    }


# Bucket constants used by classify_account. Re-exported by callers so they
# don't have to re-declare them locally.
B_LEGIT = 'legit'
B_BRAND_ADJ = 'brand_adjacent'
B_IMPERSONATOR = 'impersonator'
B_SQUAT = 'squat_candidate'


# Social-handle separators. Generalizes the typosquat SLD tokenizer
# (`typosquat_detect.py` ~L1085, which splits on hyphens/dots) to the
# separators that show up in social handles / display names.
_HANDLE_SEP_RE = re.compile(r'[._\-\s]+')


def _tokenize_handle(h: str) -> List[str]:
    """Split a social handle / display string into STANDALONE tokens.

    Lowercase, split on dot/underscore/hyphen/whitespace, drop empties. This is
    the typosquat combosquat tokenizer (split candidate into standalone tokens,
    test membership) generalized to social separators — so that the brand token
    `accerta` is a member of `acerta.contabil` but NOT of the single token
    `accertacontabil`. Token MEMBERSHIP, never raw substring.
    """
    return [t for t in _HANDLE_SEP_RE.split((h or '').lower()) if t]


def _has_brand_signal(
    handle: str,
    display_name: str,
    bio: str,
    subject: str,
    subject_handle: str,
) -> bool:
    """True iff the account carries a corroborating brand signal.

    Token-boundary (NOT raw-substring) port of the typosquat combosquat block.
    TRUE iff ANY of:
      (a) `subject_handle` is a STANDALONE token of the handle or display name
          (token membership, not substring);
      (b) `subject` (brand name) appears as a whole word (`\\b` regex) in the
          display name or bio;
      (c) whole-handle near-miss: `SequenceMatcher(handle, subject_handle)
          .ratio() >= 0.87` AND `abs(len(handle) - len(subject_handle)) <= 2`
          (the length guard kills prefix-brand inflation for short brands).
    """
    subj_handle = (subject_handle or '').lower().strip()
    subj = (subject or '').lower().strip()
    h = (handle or '').lower()
    dn = (display_name or '').lower()
    b = (bio or '').lower()

    # (a) brand handle as a standalone token of the handle or the display name.
    if subj_handle and (
        subj_handle in _tokenize_handle(h) or subj_handle in _tokenize_handle(dn)
    ):
        return True

    # (b) brand name as a whole word in the display name or bio.
    if subj:
        word = re.compile(r'\b' + re.escape(subj) + r'\b')
        if (dn and word.search(dn)) or (b and word.search(b)):
            return True

    # (c) whole-handle near-miss within a tight edit window.
    if subj_handle and h:
        if (
            SequenceMatcher(None, h, subj_handle).ratio() >= 0.87
            and abs(len(h) - len(subj_handle)) <= 2
        ):
            return True

    return False


def classify_account(
    acct: Dict[str, Any],
    subject: str,
    subject_handle: str,
    *,
    is_brand: bool,
    benign_tokens: Optional[List[str]] = None,
) -> Tuple[str, str, float]:
    """3-bucket classifier from the Phase 4 SMM playbook §5. Order matters.

    Returns `(bucket, reason, similarity_score)`.

    Identical body across `hiker_brand.py` and `hiker_vip.py`.

    WP-5 (2026-06-11) — coincidental-common-word filter: `benign_tokens` is a
    per-monitor list of common words that collide with the brand on raw string
    ratio (e.g. the Portuguese word `acerta` vs the brand `accerta`). A handle
    that IS such a benign word is down-ranked from `impersonator` to
    `brand_adjacent` UNLESS it also carries a corroborating brand signal
    (brand stem as a literal substring of the handle, brand token in the
    display name, or brand token in the bio). A raw similarity ratio alone is
    not enough to accuse an unrelated account of impersonation.
    """
    username = acct.get('handle') or ''
    sim = similarity(username, subject_handle)
    handle_lower = username.lower()
    subj_lower = subject_handle.lower()
    display_lower = (acct.get('display_name') or '').lower()
    follower = acct.get('follower_count') or 0
    media = acct.get('media_count') or 0
    is_verified = bool(acct.get('is_verified'))
    is_private = bool(acct.get('is_private'))
    bio = acct.get('biography') or ''
    account_type = acct.get('account_type')

    # Token-boundary brand-stem test (replaces the raw `subj_lower in
    # handle_lower` substring checks): the brand handle must be a STANDALONE
    # token of the candidate handle, so a prefix-brand like `mode` does NOT
    # match the unrelated `modernartdaily`.
    handle_tokens = _tokenize_handle(handle_lower)
    subj_handle_in_handle = bool(subj_lower) and subj_lower in handle_tokens

    if is_verified:
        return (B_LEGIT, 'verified account (is_verified=true)', sim)
    if handle_lower == subj_lower:
        return (B_LEGIT, 'exact handle match (and unverified — likely canonical)', sim)
    if is_brand and subj_handle_in_handle and follower > 1000:
        return (B_LEGIT, 'brand stem in handle + significant follower count', sim)

    if is_brand:
        bio_contains = bool(bio and subject.lower() in bio.lower())
        if (subj_handle_in_handle or bio_contains) and follower > 100 and media > 10:
            return (
                B_BRAND_ADJ,
                'brand stem in handle/bio + non-trivial activity',
                sim,
            )

    low_content = media <= 1
    personal = (account_type == 'PERSONAL' or account_type == 1 or account_type is None) and not is_verified
    low_followers = follower < 200
    if sim >= 0.7 and (personal or low_content or is_private) and (low_followers or low_content):
        # Similarity WITHOUT resemblance is `brand_adjacent` by default. A raw
        # SequenceMatcher ratio >= 0.7 collides unrelated / common-word / prefix
        # accounts with the brand; require a corroborating brand signal (brand
        # handle as a standalone token, brand name as a whole word in
        # display/bio, OR a whole-handle near-miss within a tight edit window)
        # before accusing an account of impersonation. Token-boundary, never
        # raw substring — the same generalization the typosquat combosquat block
        # uses so `accertacontabil` is not mistaken for `accerta`.
        has_signal = _has_brand_signal(
            handle_lower, display_lower, bio, subject, subject_handle
        )

        # `benign_tokens` is now an EXTRA suppressor (not the only mechanism): a
        # handle that IS a benign common-word token is coincidental even if it
        # somehow scraped a weak signal.
        benign = {
            t.strip().lower()
            for t in (benign_tokens or [])
            if t and str(t).strip()
        }
        handle_token = handle_lower.strip('._')
        is_coincidental_word = bool(benign) and any(
            t in benign for t in [handle_lower, handle_token, *handle_tokens]
        )

        # A real brand signal (brand handle as a standalone token, brand name as
        # a whole word in display/bio, or a tight whole-handle near-miss) is
        # genuine corroboration and OVERRIDES the benign common-word suppressor:
        # if the account actually references the brand it is not a coincidental
        # collision. So benign only suppresses the NO-signal case below; once
        # `has_signal` is true the account is an impersonator regardless of a
        # benign-token handle. (`is_coincidental_word` still annotates the
        # no-signal reason for operator clarity.)
        if not has_signal:
            return (
                B_BRAND_ADJ,
                (
                    f"handle similarity={sim:.2f} but `{handle_lower}` carries "
                    f"NO corroborating brand signal (handle/display-name/bio do "
                    f"not reference the brand and it is not a whole-handle "
                    f"near-miss)"
                    f"{' — benign common-word token' if is_coincidental_word else ''}"
                    f" — down-ranked from impersonator"
                ),
                sim,
            )
        reason = (
            f"handle similarity={sim:.2f}, "
            f"{'personal ' if personal else ''}"
            f"{'low-content ' if low_content else ''}"
            f"{'private ' if is_private else ''}"
            f"{'low-followers' if low_followers else ''}"
        ).strip()
        return (B_IMPERSONATOR, reason, sim)

    return (B_BRAND_ADJ, f'handle similarity={sim:.2f} (default bucket)', sim)


def resolve_targets(parameters: Dict[str, Any]) -> List[Any]:
    """Resolve a `target`/`targets` parameter pair into a flat list.

    Canonical implementation shared by scan-style tools (nmap_*, katana,
    gowitness, origami_browser_dast). Behavior:

    - If `parameters['targets']` is present and truthy:
      - JSON-string  -> parsed list (or `[raw]` on parse error)
      - list         -> returned as-is
      - other        -> `[str(value)]`
    - Else if `parameters['target']` is present and truthy:
      - returned as `[parameters['target']]`
    - Else: empty list.

    Tools that need extra normalization (hostname canonicalization, .strip(),
    multi-key fallback) should keep their own `_resolve_targets` rather than
    extend this signature.
    """
    if 'targets' in parameters and parameters['targets']:
        targets_param = parameters['targets']
        if isinstance(targets_param, str):
            try:
                return json.loads(targets_param)
            except json.JSONDecodeError:
                return [targets_param]
        elif isinstance(targets_param, list):
            return targets_param
        else:
            return [str(targets_param)]
    elif 'target' in parameters and parameters['target']:
        return [parameters['target']]
    return []


__all__ = [
    'first',
    'similarity',
    'build_account',
    'classify_account',
    '_tokenize_handle',
    '_has_brand_signal',
    'resolve_targets',
    'B_LEGIT',
    'B_BRAND_ADJ',
    'B_IMPERSONATOR',
    'B_SQUAT',
]
