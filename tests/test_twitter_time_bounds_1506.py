"""#1144/#1506 X historical wiring — semantic knobs → epoch bounds mapping.

The backend seeds the SEMANTIC `window_days` (#1144) and `end_days_ago`
(#1506) knobs on twitterapi:pattern_scan steps (`{{ json searchWindowDays }}`
/ `{{ json searchEndDaysAgo }}`); the agent maps them to the vendor's REAL
epoch `since_time`/`until_time` params here. twitterapi.io advanced_search
accepts both and reaches full archive depth (verified against vendor docs
2026-07), so an anchored backfill window genuinely sweeps history.

Supersedes test_twitter_since_time_1144.py — `twitter_since_time` was
replaced outright by `twitter_time_bounds` (no compat alias).
"""

import os
import sys
import unittest
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from lib.search_recency import twitter_time_bounds
from tools.twitterapi_pattern import resolve_time_bounds


class TwitterTimeBoundsTests(unittest.TestCase):
    def test_maps_window_days_to_epoch_since(self):
        ref = datetime(2026, 7, 9, 12, 0, tzinfo=timezone.utc)
        since, until = twitter_time_bounds(30, now=ref)
        expected = int(datetime(2026, 6, 9, 12, 0, tzinfo=timezone.utc).timestamp())
        self.assertEqual(since, expected)
        # No end anchor → no upper bound — the pre-#1506 vendor params.
        self.assertIsNone(until)

    def test_none_window_no_anchor_omits_both(self):
        self.assertEqual(twitter_time_bounds(None), (None, None))

    def test_wide_backfill_window_is_supported(self):
        # Full-archive vendor: a 365-day window must map cleanly, not clamp.
        ref = datetime(2026, 7, 9, 0, 0, tzinfo=timezone.utc)
        since, until = twitter_time_bounds(365, now=ref)
        expected = int(datetime(2025, 7, 9, 0, 0, tzinfo=timezone.utc).timestamp())
        self.assertEqual(since, expected)
        self.assertIsNone(until)

    def test_end_anchor_slides_both_bounds_into_the_past(self):
        # #1506 — [now - end - window, now - end], mirroring threads_date_range.
        ref = datetime(2026, 7, 9, 0, 0, tzinfo=timezone.utc)
        since, until = twitter_time_bounds(30, end_days_ago=90, now=ref)
        expected_until = int(datetime(2026, 4, 10, 0, 0, tzinfo=timezone.utc).timestamp())
        expected_since = int(datetime(2026, 3, 11, 0, 0, tzinfo=timezone.utc).timestamp())
        self.assertEqual(until, expected_until)
        self.assertEqual(since, expected_since)
        assert until is not None
        self.assertLess(until, int(ref.timestamp()))  # strictly in the past

    def test_zero_or_negative_anchor_degrades_to_trailing(self):
        ref = datetime(2026, 7, 9, 0, 0, tzinfo=timezone.utc)
        base = twitter_time_bounds(30, now=ref)
        self.assertEqual(twitter_time_bounds(30, end_days_ago=0, now=ref), base)
        self.assertEqual(twitter_time_bounds(30, end_days_ago=-5, now=ref), base)

    def test_anchor_without_window_bounds_above_only(self):
        ref = datetime(2026, 7, 9, 0, 0, tzinfo=timezone.utc)
        since, until = twitter_time_bounds(None, end_days_ago=7, now=ref)
        self.assertIsNone(since)
        self.assertEqual(
            until, int(datetime(2026, 7, 2, 0, 0, tzinfo=timezone.utc).timestamp()),
        )


class ResolveTimeBoundsTests(unittest.TestCase):
    """Tool-seam precedence: explicit `since`/`until` params EACH win over
    the knob-derived values; garbage knobs degrade, never error."""

    def test_knobs_derive_both_bounds(self):
        since, until = resolve_time_bounds({'window_days': 30, 'end_days_ago': 90})
        self.assertIsNotNone(since)
        self.assertIsNotNone(until)
        assert since is not None and until is not None
        self.assertEqual(until - since, 30 * 86400)  # window width preserved

    def test_explicit_since_wins_until_still_derived(self):
        out = resolve_time_bounds({
            'since': 1234567890, 'window_days': 30, 'end_days_ago': 90,
        })
        self.assertEqual(out[0], 1234567890)
        self.assertIsNotNone(out[1])  # anchor still bounds above

    def test_explicit_until_wins_since_still_derived(self):
        out = resolve_time_bounds({
            'until': 1234567890, 'window_days': 30,
        })
        self.assertEqual(out[1], 1234567890)
        self.assertIsNotNone(out[0])

    def test_template_garbage_degrades_to_unbounded(self):
        out = resolve_time_bounds({
            'window_days': '{{ json searchWindowDays }}',
            'end_days_ago': '{{ json searchEndDaysAgo }}',
        })
        self.assertEqual(out, (None, None))

    def test_continuous_scan_shape_has_no_upper_bound(self):
        # window_days=30, end_days_ago=0 — the continuous-cadence template
        # resolution — must produce byte-identical vendor params to pre-#1506
        # (since only, no until_time).
        since, until = resolve_time_bounds({'window_days': 30, 'end_days_ago': 0})
        self.assertIsNotNone(since)
        self.assertIsNone(until)


if __name__ == '__main__':
    unittest.main()
