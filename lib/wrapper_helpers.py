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

# G6 (#455) — UTS #39 confusables skeleton for display-name homoglyph detection.
# Degrade gracefully if the vendored snapshot is somehow unavailable (the social
# classifier must never hard-fail on an optional enrichment signal).
try:  # pragma: no cover - import guard
    from lib.confusables import skeleton as _skeleton, is_mixed_script as _is_mixed_script
except Exception:  # pragma: no cover
    _skeleton = None
    _is_mixed_script = None


# #875 — eTLD+1 registrable-domain extraction, mirroring the backend
# `registrableDomain()` (brand-handle.ts). Used to compare a HikerAPI account's
# declared profile website (`external_url`) against the monitor's ownedDomains.
# Degrades to a last-two-labels split if the `tldextract` PSL snapshot is
# unavailable, so the social classifier never hard-fails on this signal.
try:  # pragma: no cover - import guard
    import tldextract as _tldextract  # type: ignore

    _TLD_EXTRACT = _tldextract.TLDExtract(suffix_list_urls=())
except Exception:  # pragma: no cover
    _TLD_EXTRACT = None


def registrable_domain(value: Any) -> str:
    """Return the eTLD+1 registrable domain of a URL / host, or '' if none.

    Tolerant of a scheme, path, query, port, trailing dot, and surrounding
    whitespace — the raw HikerAPI `external_url` is passed through verbatim. A
    bare label with no dot (e.g. 'localhost') returns '' (not a registrable
    domain) so it can never spuriously match an owned domain.
    """
    if not isinstance(value, str):
        return ''
    s = value.strip().lower()
    if not s:
        return ''
    s = re.sub(r'^[a-z]+://', '', s)
    s = s.split('/')[0].split('?')[0].split('#')[0]
    s = s.split(':')[0]  # strip a :port
    s = s.rstrip('.')
    if not s or '.' not in s:
        return ''
    if _TLD_EXTRACT is not None:
        try:
            ext = _TLD_EXTRACT(s)
            # A known public suffix (`brand.co.uk` → domain='brand', suffix='co.uk').
            if ext.domain and ext.suffix:
                return f'{ext.domain}.{ext.suffix}'
            # No public suffix resolved (an unlisted/reserved TLD, depending on
            # the tldextract snapshot version): fall through to the last-two-labels
            # heuristic — which matches the backend `tldts` behavior of treating an
            # unlisted TLD as a single-label registrable suffix (`brand.test`).
        except Exception:  # pragma: no cover
            pass
    # Fallback: last two dotted labels. Correct for single-label suffixes (the
    # `.test` fixture case, and any unlisted TLD tldts also collapses this way);
    # imperfect only for a genuine multi-part TLD that tldextract failed to
    # resolve, which the PSL-backed path above already handles.
    labels = [p for p in s.split('.') if p]
    if len(labels) < 2:
        return ''
    return '.'.join(labels[-2:])


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
        # #875 — the account's declared profile website. The one deterministic
        # ownership signal a legitimate chapter/affiliate account carries; the
        # backend compares its registrable domain against the monitor's
        # ownedDomains. Absent-safe: '' when the vendor omits it.
        'external_url': first(inner, 'external_url', 'website') or '',
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


# G6 (#455) — per-platform handle-constraint rules. Generation runs against the
# broadest charset (IG/TikTok: a-z 0-9 . _); each platform then FILTERS +
# REMAPS so we don't waste paid vendor calls on candidates that platform can't
# even host, and so an IG `your.brand` impostor is searched as the correct
# cross-platform variant (`your_brand` on X, `yourbrand` on LinkedIn).
# Sources: help.x.com/en/managing-your-account/x-username-rules, platform docs.
_ALNUM = set('abcdefghijklmnopqrstuvwxyz0123456789')
PLATFORM_HANDLE_RULES: Dict[str, Dict[str, Any]] = {
    # IG/TikTok: letters, digits, period, underscore.
    'instagram': {'allowed': _ALNUM | {'.', '_'}, 'min_len': 1, 'max_len': 30},
    'tiktok': {'allowed': _ALNUM | {'.', '_'}, 'min_len': 2, 'max_len': 24},
    # X: letters, digits, underscore only; max 15; no '.'/'-'.
    'x': {'allowed': _ALNUM | {'_'}, 'min_len': 1, 'max_len': 15},
    'twitter': {'allowed': _ALNUM | {'_'}, 'min_len': 1, 'max_len': 15},
    # Telegram: letters, digits, underscore; must start with a letter, end
    # alphanumeric; min 5.
    'telegram': {'allowed': _ALNUM | {'_'}, 'min_len': 5, 'max_len': 32,
                 'start_alpha': True, 'end_alnum': True},
    # LinkedIn vanity: lowercase alphanumeric only (no separators).
    'linkedin': {'allowed': _ALNUM, 'min_len': 3, 'max_len': 100},
    # Facebook: letters, digits, period; min 5.
    'facebook': {'allowed': _ALNUM | {'.'}, 'min_len': 5, 'max_len': 50},
}

# Separator each platform tolerates when remapping a handle from another platform
# (the char a stripped '.'/'-' collapses to). None => strip the separator.
_PLATFORM_REMAP_SEP: Dict[str, Optional[str]] = {
    'instagram': '_', 'tiktok': '_', 'x': '_', 'twitter': '_',
    'telegram': '_', 'linkedin': None, 'facebook': '.',
}


def is_valid_handle_for_platform(handle: str, platform: str) -> bool:
    """True iff `handle` satisfies `platform`'s username constraints."""
    rule = PLATFORM_HANDLE_RULES.get((platform or '').lower())
    if not rule or not handle:
        return False
    h = handle.lower()
    if not (rule['min_len'] <= len(h) <= rule['max_len']):
        return False
    if any(c not in rule['allowed'] for c in h):
        return False
    if rule.get('start_alpha') and not h[0].isalpha():
        return False
    if rule.get('end_alnum') and not h[-1].isalnum():
        return False
    return True


def remap_handle(handle: str, to_platform: str) -> str:
    """Remap a handle's separators to a target platform's allowed form.

    An IG `your.brand` becomes `your_brand` on X/Telegram (no '.') and
    `yourbrand` on LinkedIn (no separators). Non-separator characters are left
    untouched; the result is NOT guaranteed valid (caller filters).
    """
    if not handle:
        return ''
    sep = _PLATFORM_REMAP_SEP.get((to_platform or '').lower(), '_')
    replacement = sep if sep is not None else ''
    return _HANDLE_SEP_RE.sub(replacement, handle.lower()).strip('._-')


def filter_handles_for_platform(handles: List[str], platform: str) -> List[str]:
    """Remap each handle to `platform` then keep only the platform-valid ones.

    Order-preserving + deduped. The cross-platform remap means a candidate that
    was valid on the generation platform still yields its correct variant here.
    """
    out: List[str] = []
    seen: set = set()
    for h in handles:
        remapped = remap_handle(h, platform)
        if remapped and remapped not in seen and is_valid_handle_for_platform(remapped, platform):
            seen.add(remapped)
            out.append(remapped)
    return out


def _is_confusable_display(
    display_name: str, handle: str, subject: str, subject_handle: str
) -> bool:
    """True iff the display name or handle is a UTS #39 homoglyph of the brand.

    A mixed-script string whose skeleton collapses to the brand's (e.g. display
    name `Quеstrade` with a Cyrillic `е`) is a strong impersonation signal that
    raw string-similarity misses — handles are forced ASCII on most platforms,
    but display names are not. Requires the candidate to be mixed-script (so a
    plain-ASCII near-match is left to the similarity path) and NOT literally
    equal to the brand.
    """
    if _skeleton is None or _is_mixed_script is None:
        return False
    targets = [t for t in (subject, subject_handle) if t]
    if not targets:
        return False
    target_skeletons = {_skeleton(t.lower()) for t in targets}
    for cand in (display_name, handle):
        if not cand or not _is_mixed_script(cand):
            continue
        cl = cand.lower()
        if cl in (t.lower() for t in targets):
            continue  # identical text is not a homoglyph
        if _skeleton(cl) in target_skeletons:
            return True
    return False


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
    owned_domains: Optional[List[str]] = None,
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

    # #875 — deterministic ownership gate (highest precedence). An account whose
    # declared profile website (`external_url`) resolves to one of the monitor's
    # own registrable domains is an own/affiliate account, not an impersonator —
    # bucket LEGIT so the agent-side verdict agrees with the backend's
    # `profile_links_owned_domain` override. Mirrors the ad path (#687). The
    # backend re-derives this from the carried `external_url`; classifying it
    # here keeps the two verdicts in sync.
    owned_set = {
        registrable_domain(d)
        for d in (owned_domains or [])
        if isinstance(d, str) and registrable_domain(d)
    }
    if owned_set:
        acct_reg = registrable_domain(acct.get('external_url'))
        if acct_reg and acct_reg in owned_set:
            return (
                B_LEGIT,
                f'profile website ({acct_reg}) is an owned domain — own/affiliate account',
                sim,
            )

    if is_verified:
        return (B_LEGIT, 'verified account (is_verified=true)', sim)
    if handle_lower == subj_lower:
        return (B_LEGIT, 'exact handle match (and unverified — likely canonical)', sim)
    if is_brand and subj_handle_in_handle and follower > 1000:
        return (B_LEGIT, 'brand stem in handle + significant follower count', sim)

    # G6 (#455) — display-name / handle homoglyph (UTS #39). A mixed-script
    # rendering whose skeleton collapses to the brand (e.g. display `Quеstrade`
    # with a Cyrillic `е`) is a strong impersonation signal independent of raw
    # string similarity. Checked AFTER the verified/exact LEGIT gates so a real
    # verified account is never mislabelled.
    if _is_confusable_display(display_lower, username, subject, subject_handle):
        return (
            B_IMPERSONATOR,
            'display-name/handle homoglyph: UTS #39 skeleton matches the brand with mixed-script',
            max(sim, 0.95),
        )

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
    'registrable_domain',
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
