"""#1143 — shared recency/pagination knob parsing for the ScrapeCreators
keyword-search tools (reddit / tiktok / threads / youtube).

The backend seeds SEMANTIC knobs on the drp-vendor workflow steps
(`sort`, `window_days`, `max_pages`, `limit` — resolved from the execution
context, see brand-monitors.service.ts KEYWORD_SEARCH_NETWORKS). Each tool maps
them to its vendor's REAL params here, because the vendors disagree
(verified against ScrapeCreators docs 2026-07, epic #1142):

  reddit  → sort: relevance|new|top|comment_count, timeframe: all|day|week|month|year, cursor `after`
  tiktok  → sort_by: relevance|most-liked|date-posted, date_posted: yesterday|this-week|this-month|last-3-months|last-6-months|all-time, cursor `cursor`
  youtube → sortBy: relevance|popular (NO recency sort), uploadDate: today|this_week|this_month|this_year, cursor `continuationToken`
  threads → start_date/end_date (YYYY-MM-DD) ONLY; no sort, NO pagination
  twitter → since_time/until_time (epoch seconds) on advanced_search; the
            vendor's archive reaches full history, not just recent tweets
            (verified against twitterapi.io docs 2026-07)

Everything here is defensive: knobs arrive through Handlebars templates that
resolve to real numbers on orchestrated runs but may be missing/None/strings on
manual workflow runs — an invalid value degrades to the pre-#1143 behavior
(single page, vendor defaults), never to an error.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple

# Hard ceiling on pagination depth — a mis-templated max_pages can never turn
# one workflow step into an unbounded paid-call fan-out.
MAX_PAGES_CAP = 5
# Hard ceiling on the post budget a single step may accumulate.
MAX_LIMIT_CAP = 200

_SORT_VALUES = ('new', 'relevance', 'top')


def _to_int(value: Any) -> Optional[int]:
    """Coerce int-ish values ('30', 30, 30.0); anything else → None."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            return None
    return None


def parse_search_knobs(
    parameters: Dict[str, Any],
    *,
    default_limit: int = 50,
) -> Dict[str, Any]:
    """Parse the semantic knobs off a step's parameters.

    Returns {'limit': int, 'window_days': Optional[int], 'max_pages': int,
    'sort': Optional[str]} with every value clamped/validated. Missing or
    garbage input yields the conservative defaults (max_pages=1 == pre-#1143
    single-call behavior).
    """
    limit = _to_int(parameters.get('limit'))
    if limit is None or limit < 1:
        limit = default_limit
    limit = min(limit, MAX_LIMIT_CAP)

    window_days = _to_int(parameters.get('window_days'))
    if window_days is not None and window_days < 1:
        window_days = None

    # Optional end anchor (days before now the window ENDS). Only the
    # absolute-date-range vendors (threads) consume it; 0/negative/garbage
    # degrades to None == "end at now" (the pre-existing behavior).
    end_days_ago = _to_int(parameters.get('end_days_ago'))
    if end_days_ago is not None and end_days_ago < 1:
        end_days_ago = None

    max_pages = _to_int(parameters.get('max_pages'))
    if max_pages is None or max_pages < 1:
        max_pages = 1
    max_pages = min(max_pages, MAX_PAGES_CAP)

    sort_raw = parameters.get('sort')
    sort = sort_raw.strip().lower() if isinstance(sort_raw, str) else None
    if sort not in _SORT_VALUES:
        sort = None

    return {
        'limit': limit,
        'window_days': window_days,
        'end_days_ago': end_days_ago,
        'max_pages': max_pages,
        'sort': sort,
    }


def reddit_timeframe(window_days: Optional[int]) -> Optional[str]:
    """window_days → reddit `timeframe` enum (None → omit the param).

    #1510 — the > 366 → 'all' branch is reachable on orchestrated runs since
    the backend gave reddit the archive window ceiling
    (HISTORICAL_BACKFILL_WINDOW_CEILING_BY_TOOL, engine.types.ts): an operator
    deliberately requesting a deeper-than-a-year backfill gets the vendor's
    all-time bucket. HONEST LIMITATION: 'all' WIDENS RECALL to all-time — it
    is not date filtering; the vendor cannot target a past slice, and results
    may be older than the requested window. ≤ 366-day windows are untouched
    ('year' or narrower), so default behavior is byte-identical.
    """
    if window_days is None:
        return None
    if window_days <= 1:
        return 'day'
    if window_days <= 7:
        return 'week'
    if window_days <= 31:
        return 'month'
    if window_days <= 366:
        return 'year'
    return 'all'


def reddit_sort(sort: Optional[str]) -> Optional[str]:
    """Semantic sort → reddit `sort` enum (both support new/relevance/top)."""
    return sort if sort in ('new', 'relevance', 'top') else None


def tiktok_date_posted(window_days: Optional[int]) -> Optional[str]:
    """window_days → tiktok `date_posted` enum (None → omit)."""
    if window_days is None:
        return None
    if window_days <= 1:
        return 'yesterday'
    if window_days <= 7:
        return 'this-week'
    if window_days <= 31:
        return 'this-month'
    if window_days <= 92:
        return 'last-3-months'
    if window_days <= 183:
        return 'last-6-months'
    return 'all-time'


def tiktok_sort_by(sort: Optional[str]) -> Optional[str]:
    """Semantic sort → tiktok `sort_by` enum ('top' ⇒ most-liked)."""
    if sort == 'new':
        return 'date-posted'
    if sort == 'relevance':
        return 'relevance'
    if sort == 'top':
        return 'most-liked'
    return None


def youtube_upload_date(window_days: Optional[int]) -> Optional[str]:
    """window_days → youtube `uploadDate` enum (>366 → omit = all time)."""
    if window_days is None:
        return None
    if window_days <= 1:
        return 'today'
    if window_days <= 7:
        return 'this_week'
    if window_days <= 31:
        return 'this_month'
    if window_days <= 366:
        return 'this_year'
    return None


def twitter_time_bounds(
    window_days: Optional[int],
    *,
    end_days_ago: Optional[int] = None,
    now: Optional[datetime] = None,
) -> Tuple[Optional[int], Optional[int]]:
    """(window_days, end_days_ago) → epoch-seconds `(since_time, until_time)`
    for twitterapi.io advanced_search (computed agent-side — step templates
    can't carry absolute timestamps, they'd go stale).

    `end_days_ago` (#1506) slides the window's END that many days into the
    past — mirror of `threads_date_range`: the bounded slice is
    [now - end_days_ago - window_days, now - end_days_ago]. The vendor's
    archive reaches full history, so an anchored slice genuinely sweeps it.
    None/0 end anchor → `until` omitted and `since` computed off now — the
    pre-#1506 behavior, byte-identical vendor params. None window → no lower
    bound (with an anchor the slice is bounded above only)."""
    ref = now or datetime.now(timezone.utc)
    # Narrow inline rather than via an `anchored` flag — a bool alias does not
    # carry the None-narrowing through to `timedelta(days=...)`.
    anchored = False
    if end_days_ago is not None and end_days_ago > 0:
        anchored = True
        ref = ref - timedelta(days=end_days_ago)
    until = int(ref.timestamp()) if anchored else None
    since = None
    if window_days is not None:
        since = int((ref - timedelta(days=window_days)).timestamp())
    return (since, until)


def threads_date_range(
    window_days: Optional[int],
    *,
    end_days_ago: Optional[int] = None,
    now: Optional[datetime] = None,
) -> Tuple[Optional[str], Optional[str]]:
    """window_days → (start_date, end_date) as YYYY-MM-DD, computed agent-side
    (the step template can't carry absolute dates — they'd go stale).

    `end_days_ago` slides the window's END that many days into the past
    (None/0 → end at now), letting a historical backfill target a BOUNDED
    slice [now-end_days_ago-window_days, now-end_days_ago]. NOTE the vendor
    cap: the Threads search endpoint returns AT MOST ~10 un-paginated results
    per call regardless of range width — a windowed sweep bounds recency, it
    does not raise volume.
    """
    if window_days is None:
        return (None, None)
    ref = now or datetime.now(timezone.utc)
    if end_days_ago is not None and end_days_ago > 0:
        ref = ref - timedelta(days=end_days_ago)
    start = (ref - timedelta(days=window_days)).strftime('%Y-%m-%d')
    end = ref.strftime('%Y-%m-%d')
    return (start, end)


def _serper_cdr_date(d: datetime) -> str:
    """Google `cdr:` boundary date — M/D/YYYY with NO leading zeros (the
    format live-verified against Serper 2026-07: `cd_min:6/1/2020`)."""
    return f'{d.month}/{d.day}/{d.year}'


def serper_tbs(
    window_days: Optional[int],
    *,
    end_days_ago: Optional[int] = None,
    now: Optional[datetime] = None,
) -> Optional[str]:
    """window_days → Google `tbs` time-bounded-search string for Serper.dev
    (None → omit = all time). Used by the brand-mention sentiment cohorts so
    SERP rows are recent and more likely to carry a vendor `date` string —
    live-measured 2026-07: the same query returned 1/10 dated results with no
    `tbs` vs 8/10 inside a `cdr:` range, so bounding the window also shrinks
    the undated blind spot.

    Two shapes (#1505, both live-verified — Serper echoes `tbs` back in
    `searchParameters`):
      - `end_days_ago` set (>0) → an ABSOLUTE date range
        `cdr:1,cd_min:M/D/YYYY,cd_max:M/D/YYYY` over
        [now - end_days_ago - window_days, now - end_days_ago], computed
        agent-side (step templates can't carry absolute dates — they'd go
        stale). A window wider than a year is allowed here — an anchored
        historical slice is bounded by construction.
      - no end anchor → trailing-recency `qdr:` buckets, with MONTH
        MULTIPLIERS (`qdr:m2`…`qdr:m11`, verified `qdr:m6`) so a 32–366-day
        window no longer collapses to a full year (`qdr:y` previously turned
        a 60-day request into 365 days silently); >366 days → None (all time).
    """
    if window_days is None:
        return None
    if end_days_ago is not None and end_days_ago > 0:
        ref = (now or datetime.now(timezone.utc)) - timedelta(days=end_days_ago)
        start = ref - timedelta(days=window_days)
        return f'cdr:1,cd_min:{_serper_cdr_date(start)},cd_max:{_serper_cdr_date(ref)}'
    if window_days <= 1:
        return 'qdr:d'
    if window_days <= 7:
        return 'qdr:w'
    if window_days <= 31:
        return 'qdr:m'
    if window_days <= 366:
        # ceil(days/31) months; 12 "months" spans the full year → qdr:y.
        months = -(-window_days // 31)
        return 'qdr:y' if months >= 12 else f'qdr:m{months}'
    return None
