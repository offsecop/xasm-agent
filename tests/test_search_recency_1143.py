"""#1143 — knob parsing + vendor bucket maps for the SC keyword-search tools.

The backend seeds SEMANTIC knobs (sort / window_days / max_pages / limit); the
tools map them to each vendor's REAL enum values. These locks pin:
  - defensive parsing (template garbage degrades to single-page defaults);
  - the hard caps (a mis-templated max_pages can never exceed MAX_PAGES_CAP);
  - the verified per-vendor enum bucketing (epic #1142 capability table).
"""

import unittest
from datetime import datetime, timezone

from lib.search_recency import (
    MAX_LIMIT_CAP,
    MAX_PAGES_CAP,
    parse_search_knobs,
    reddit_sort,
    reddit_timeframe,
    threads_date_range,
    tiktok_date_posted,
    tiktok_sort_by,
    youtube_upload_date,
)


class ParseSearchKnobsTests(unittest.TestCase):
    def test_defaults_match_pre_1143_single_call_behavior(self):
        knobs = parse_search_knobs({})
        self.assertEqual(knobs['limit'], 50)
        self.assertIsNone(knobs['window_days'])
        self.assertIsNone(knobs['end_days_ago'])
        self.assertEqual(knobs['max_pages'], 1)
        self.assertIsNone(knobs['sort'])

    def test_end_days_ago_parses_and_degrades(self):
        self.assertEqual(parse_search_knobs({'end_days_ago': 90})['end_days_ago'], 90)
        self.assertEqual(parse_search_knobs({'end_days_ago': '45'})['end_days_ago'], 45)
        # 0 == "end at now" == absent; garbage/negative degrade the same way.
        self.assertIsNone(parse_search_knobs({'end_days_ago': 0})['end_days_ago'])
        self.assertIsNone(parse_search_knobs({'end_days_ago': -3})['end_days_ago'])
        self.assertIsNone(
            parse_search_knobs({'end_days_ago': '{{ json searchEndDaysAgo }}'})['end_days_ago'],
        )

    def test_accepts_ints_and_numeric_strings(self):
        knobs = parse_search_knobs(
            {'limit': '75', 'window_days': 30, 'max_pages': '3', 'sort': 'NEW'},
        )
        self.assertEqual(knobs['limit'], 75)
        self.assertEqual(knobs['window_days'], 30)
        self.assertEqual(knobs['max_pages'], 3)
        self.assertEqual(knobs['sort'], 'new')

    def test_garbage_degrades_to_defaults(self):
        # Unresolved Handlebars templates / None / nonsense must never throw.
        knobs = parse_search_knobs(
            {
                'limit': '{{ json searchLimit }}',
                'window_days': None,
                'max_pages': 'lots',
                'sort': 'best',
            },
        )
        self.assertEqual(knobs['limit'], 50)
        self.assertIsNone(knobs['window_days'])
        self.assertEqual(knobs['max_pages'], 1)
        self.assertIsNone(knobs['sort'])

    def test_hard_caps(self):
        knobs = parse_search_knobs({'limit': 10_000, 'max_pages': 99})
        self.assertEqual(knobs['limit'], MAX_LIMIT_CAP)
        self.assertEqual(knobs['max_pages'], MAX_PAGES_CAP)

    def test_negative_and_zero_values_degrade(self):
        knobs = parse_search_knobs({'limit': 0, 'window_days': -5, 'max_pages': 0})
        self.assertEqual(knobs['limit'], 50)
        self.assertIsNone(knobs['window_days'])
        self.assertEqual(knobs['max_pages'], 1)


class VendorBucketTests(unittest.TestCase):
    def test_reddit_timeframe_buckets(self):
        self.assertIsNone(reddit_timeframe(None))
        self.assertEqual(reddit_timeframe(1), 'day')
        self.assertEqual(reddit_timeframe(7), 'week')
        self.assertEqual(reddit_timeframe(30), 'month')
        self.assertEqual(reddit_timeframe(90), 'year')
        self.assertEqual(reddit_timeframe(365), 'year')
        # #1510 boundary lock — ≤ 366 stays 'year' (default behavior
        # byte-identical); the first day past it reaches the vendor's
        # all-time bucket (recall widener, NOT a date slice).
        self.assertEqual(reddit_timeframe(366), 'year')
        self.assertEqual(reddit_timeframe(367), 'all')
        self.assertEqual(reddit_timeframe(1000), 'all')

    def test_reddit_sort_passthrough_only_for_supported(self):
        self.assertEqual(reddit_sort('new'), 'new')
        self.assertEqual(reddit_sort('relevance'), 'relevance')
        self.assertEqual(reddit_sort('top'), 'top')
        self.assertIsNone(reddit_sort(None))

    def test_tiktok_buckets(self):
        self.assertIsNone(tiktok_date_posted(None))
        self.assertEqual(tiktok_date_posted(1), 'yesterday')
        self.assertEqual(tiktok_date_posted(7), 'this-week')
        self.assertEqual(tiktok_date_posted(30), 'this-month')
        self.assertEqual(tiktok_date_posted(90), 'last-3-months')
        self.assertEqual(tiktok_date_posted(180), 'last-6-months')
        self.assertEqual(tiktok_date_posted(999), 'all-time')
        self.assertEqual(tiktok_sort_by('new'), 'date-posted')
        self.assertEqual(tiktok_sort_by('relevance'), 'relevance')
        self.assertEqual(tiktok_sort_by('top'), 'most-liked')
        self.assertIsNone(tiktok_sort_by(None))

    def test_youtube_buckets_omit_beyond_a_year(self):
        self.assertIsNone(youtube_upload_date(None))
        self.assertEqual(youtube_upload_date(1), 'today')
        self.assertEqual(youtube_upload_date(7), 'this_week')
        self.assertEqual(youtube_upload_date(30), 'this_month')
        self.assertEqual(youtube_upload_date(90), 'this_year')
        # >366 days: the vendor has no wider filter — omit (all time).
        self.assertIsNone(youtube_upload_date(1000))

    def test_threads_date_range_is_agent_computed(self):
        ref = datetime(2026, 7, 9, 12, 0, tzinfo=timezone.utc)
        start, end = threads_date_range(30, now=ref)
        self.assertEqual(start, '2026-06-09')
        self.assertEqual(end, '2026-07-09')
        self.assertEqual(threads_date_range(None), (None, None))

    def test_threads_date_range_end_anchor_slides_window_into_the_past(self):
        ref = datetime(2026, 7, 9, 12, 0, tzinfo=timezone.utc)
        # 30-day window ending 60 days ago: [ref-90d, ref-60d].
        start, end = threads_date_range(30, end_days_ago=60, now=ref)
        self.assertEqual(start, '2026-04-10')
        self.assertEqual(end, '2026-05-10')
        # None/0 end anchor == the pre-existing "end at now" behavior.
        self.assertEqual(
            threads_date_range(30, end_days_ago=None, now=ref),
            threads_date_range(30, now=ref),
        )
        self.assertEqual(
            threads_date_range(30, end_days_ago=0, now=ref),
            threads_date_range(30, now=ref),
        )
        # No window ⇒ no range, anchor or not.
        self.assertEqual(threads_date_range(None, end_days_ago=60), (None, None))


if __name__ == '__main__':
    unittest.main()
