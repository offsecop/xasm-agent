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
        'max_pages': max_pages,
        'sort': sort,
    }


def reddit_timeframe(window_days: Optional[int]) -> Optional[str]:
    """window_days → reddit `timeframe` enum (None → omit the param)."""
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


def threads_date_range(
    window_days: Optional[int],
    *,
    now: Optional[datetime] = None,
) -> Tuple[Optional[str], Optional[str]]:
    """window_days → (start_date, end_date) as YYYY-MM-DD, computed agent-side
    (the step template can't carry absolute dates — they'd go stale)."""
    if window_days is None:
        return (None, None)
    ref = now or datetime.now(timezone.utc)
    start = (ref - timedelta(days=window_days)).strftime('%Y-%m-%d')
    end = ref.strftime('%Y-%m-%d')
    return (start, end)
