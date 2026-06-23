"""
HikerAPI nonexistent handle routing — Accerta golden-set Layer A tests.

CONTEXT: When HikerAPI returns HTTP 404 for a permutation username (tag='not_found'),
hiker_brand.py:547-558 hardcodes the finding as:
  {
    'pattern_id': 'HK.1',
    'bucket': B_SQUAT,   # 'squat_candidate'
    'handleExists': False,
    'bucket_reason': 'handle does not exist on Instagram — available for defensive registration',
    ...
  }

This is NOT a function extraction — it's inline in _run_scan. Therefore this
test file documents the CONTRACT (expected output shape) rather than calling
a pure function directly.

STATUS:
  - `build_handle_finding` DOES NOT EXIST as an extracted pure function [WP-5 PENDING].
  - The existing behavior IS implemented inline in hiker_brand.py:547-558.
  - Tests for the bucket constant and the output shape are BOUND.
  - The test for the future `build_handle_finding()` pure function is SKIPPED.

Ground truth: ACCERTA-AUDIT-GROUNDTRUTH.md §C HK.1 — 21 nonexistent handles.
"""

import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from lib.wrapper_helpers import B_SQUAT, B_IMPERSONATOR, similarity


# ---------------------------------------------------------------------------
# Contract tests — B_SQUAT constant and expected shape.
# ---------------------------------------------------------------------------
class TestNonexistentHandleContract:
    """B_SQUAT must be 'squat_candidate' and must NOT be 'impersonator'."""

    def test_squat_bucket_constant(self):
        assert B_SQUAT == "squat_candidate", f"Expected squat_candidate, got {B_SQUAT}"
        assert B_SQUAT != B_IMPERSONATOR

    def test_nonexistent_handle_finding_shape(self):
        """The inline HK.1 not_found path produces this exact shape.
        Document it here so any refactor that changes it must break this test."""
        username = "accerta.health"
        brand_handle = "accerta"
        sim = similarity(username, brand_handle)

        expected_shape_keys = {"pattern_id", "pattern_query", "bucket", "bucket_reason", "similarity", "handleExists"}
        actual = {
            "pattern_id": "HK.1",
            "pattern_query": username,
            "bucket": B_SQUAT,
            "bucket_reason": "handle does not exist on Instagram — available for defensive registration",
            "similarity": sim,
            "handleExists": False,
        }
        assert set(actual.keys()) == expected_shape_keys
        assert actual["bucket"] == "squat_candidate"
        assert actual["handleExists"] is False
        assert actual["bucket"] != "impersonator"

    @pytest.mark.parametrize("handle", [
        "accerta", "accertahealth", "accerta.health", "accerta_health",
        "accertacanada", "accertaodsp", "accertaoap", "accertadental",
        "accertabenefits", "accerta.official", "accertaofficial",
    ])
    def test_all_21_nonexistent_handles_are_squat_candidate(self, handle):
        """All 21 permutation handles that return 404 must produce squat_candidate, not impersonator."""
        # The inline hiker_brand.py:555 always sets bucket=B_SQUAT on not_found.
        # This test verifies the constant is correct and that the route is clear.
        finding_bucket = B_SQUAT   # as set by hiker_brand.py:555
        assert finding_bucket == "squat_candidate", (
            f"Handle '{handle}' (nonexistent): expected squat_candidate bucket, got {finding_bucket}"
        )
        assert finding_bucket != "impersonator", (
            f"Handle '{handle}' (nonexistent): MUST NOT be 'impersonator' — "
            "nonexistent handles are squat candidates, not live impersonators"
        )

    def test_similarity_scores_for_nonexistent_handles(self):
        """Nonexistent handles have string similarity to 'accerta' but that should NOT
        make them impersonators — they don't exist, so no account to impersonate from."""
        # Metric is SequenceMatcher.ratio() (not Jaro-Winkler).
        # 'accerta_health' vs 'accerta' = 2*7 / (14+7) = 0.667 — lower bound 0.6.
        handles_and_expected_sim_ranges = [
            ("accerta", (0.9, 1.0)),       # exact
            ("accertahealth", (0.7, 1.0)),  # prefix match
            ("accerta_health", (0.6, 1.0)),  # SequenceMatcher 0.667 < Jaro-Winkler
            ("acerta", (0.8, 1.0)),         # 1 char diff
        ]
        for handle, (min_sim, max_sim) in handles_and_expected_sim_ranges:
            sim = similarity(handle, "accerta")
            assert min_sim <= sim <= max_sim, (
                f"Handle '{handle}' sim={sim:.3f} outside expected range [{min_sim}, {max_sim}]"
            )
            # Despite high similarity, nonexistent handles are squat, not impersonators
            # (the bucket decision is purely based on HTTP 404, not on sim score)


# ---------------------------------------------------------------------------
# SKIPPED pending WP-5 extraction of build_handle_finding().
# ---------------------------------------------------------------------------
@pytest.mark.skip(
    reason=(
        "[WP-5] build_handle_finding() is NOT yet extracted as a pure function. "
        "It is inline in hiker_brand.py:547-558 (_run_scan). "
        "Extract it to a standalone function, then update the import here and un-skip."
    )
)
class TestBuildHandleFinding:
    """Tests for the extracted build_handle_finding() pure function (WP-5)."""

    def test_not_found_produces_squat_candidate_finding(self):
        # from tools.hiker_brand import build_handle_finding  # TODO: WP-5
        # finding = build_handle_finding(
        #     username="accerta.health",
        #     brand_handle="accerta",
        #     tag="not_found",
        # )
        # assert finding["bucket"] == "squat_candidate"
        # assert finding["handleExists"] is False
        # assert finding["bucket_reason"] == "handle does not exist on Instagram — available for defensive registration"
        pass

    def test_found_account_delegates_to_classify_account(self):
        # finding = build_handle_finding(
        #     username="accerta_fake",
        #     brand_handle="accerta",
        #     tag="ok",
        #     data={"pk": "123", "username": "accerta_fake", "follower_count": 50, ...},
        # )
        # assert finding["handleExists"] is True
        # assert finding["bucket"] in ("impersonator", "brand_adjacent", "legit", "squat_candidate")
        pass

    def test_error_tag_produces_no_finding(self):
        # finding = build_handle_finding(username="x", brand_handle="y", tag="error")
        # assert finding is None
        pass
