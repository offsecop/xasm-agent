"""
classify_account — GENERIC calibration Layer A tests.

Binds to: classify_account() from agent/lib/wrapper_helpers.py

Proves the classifier generalizes beyond any one client brand: fictitious
brands (Mode Apparel / Sol / Lumenfield), benign_tokens=[] throughout (NO
curated suppression list). These lock the SAME invariants the accerta pack
tests, but with brands chosen to stress the failure modes the calibration
fixes target:

  - PREFIX/SUBSTRING ≠ RESEMBLANCE: brand "mode" is a prefix of "modernartdaily"
    and a substring of many words — it must NOT make an unrelated account an
    impersonator (token-boundary brand-stem test).
  - SHORT BRAND: "sol" (3 chars) collides as a substring with countless handles
    ("solutionshub", "console", "solar") — short brands must not over-accuse.
  - GENUINE RESEMBLANCE STILL FIRES: "mode.support" (standalone 'mode' token +
    official-claim) and "lumenfie1d" (leet near-miss of "lumenfield") must NOT
    be classified as legit.
"""

import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from lib.wrapper_helpers import classify_account, B_LEGIT, B_BRAND_ADJ, B_IMPERSONATOR


def make_acct(
    handle: str,
    display_name: str = "",
    biography: str = "",
    follower_count: int = 0,
    media_count: int = 0,
    is_verified: bool = False,
    is_private: bool = False,
    account_type=None,
) -> dict:
    return {
        "handle": handle,
        "display_name": display_name,
        "biography": biography,
        "follower_count": follower_count,
        "media_count": media_count,
        "is_verified": is_verified,
        "is_private": is_private,
        "account_type": account_type,
    }


# ---------------------------------------------------------------------------
# PREFIX/SUBSTRING ≠ RESEMBLANCE — brand "mode" must not over-accuse.
# ---------------------------------------------------------------------------
class TestPrefixNotImpersonator:
    @pytest.mark.parametrize("handle,display_name,bio,followers,media", [
        # 'mode' is a prefix of 'modern' — coincidental, unrelated account.
        ("modernartdaily", "Modern Art Daily", "daily modern art", 2300, 540),
        # high-reach unrelated account, no brand token at all.
        ("solutionshub", "Solutions Hub", "Business solutions & consulting", 8500, 300),
    ])
    def test_prefix_substring_not_impersonator(self, handle, display_name, bio, followers, media):
        acct = make_acct(handle, display_name, bio, followers, media)
        bucket, reason, sim = classify_account(
            acct, "Mode Apparel", "modeapparel", is_brand=True, benign_tokens=[]
        )
        assert bucket != B_IMPERSONATOR, (
            f"'{handle}' is a coincidental prefix/substring collision, not an "
            f"impersonator. Got {bucket}: {reason}"
        )


# ---------------------------------------------------------------------------
# SHORT BRAND — "sol" (3 chars) collides as a substring; must not over-accuse.
# ---------------------------------------------------------------------------
class TestShortBrandCollision:
    @pytest.mark.parametrize("handle,display_name,bio,followers,media", [
        ("solutionshub", "Solutions Hub", "Business solutions", 8500, 300),
        ("console.gaming", "Console Gaming", "Reviews and news", 4100, 220),
        ("solar_living", "Solar Living", "Off-grid solar tips", 600, 90),
    ])
    def test_short_brand_substring_not_impersonator(self, handle, display_name, bio, followers, media):
        acct = make_acct(handle, display_name, bio, followers, media)
        bucket, reason, sim = classify_account(
            acct, "Sol", "sol", is_brand=True, benign_tokens=[]
        )
        assert bucket != B_IMPERSONATOR, (
            f"Short-brand 'sol' substring collision '{handle}' must NOT be an "
            f"impersonator. Got {bucket}: {reason}"
        )


# ---------------------------------------------------------------------------
# Exact handle → legit (canonical, unverified).
# ---------------------------------------------------------------------------
class TestCanonicalExactMatch:
    def test_exact_handle_is_legit(self):
        acct = make_acct("modeapparel", "Mode Apparel", "Official store", 50000, 800)
        bucket, reason, sim = classify_account(
            acct, "Mode Apparel", "modeapparel", is_brand=True, benign_tokens=[]
        )
        assert bucket == B_LEGIT, f"Exact handle match should be legit, got {bucket}: {reason}"


# ---------------------------------------------------------------------------
# Genuine resemblance still fires — must NOT be downranked to legit.
# ---------------------------------------------------------------------------
class TestGenuineResemblanceNotLegit:
    def test_official_claim_lookalike_not_legit(self):
        # standalone 'mode' token + official-claim ('help'/'support') + low activity.
        acct = make_acct(
            handle="mode.support",
            display_name="Mode Apparel Help",
            biography="",
            follower_count=12,
            media_count=3,
        )
        bucket, reason, sim = classify_account(
            acct, "Mode Apparel", "modeapparel", is_brand=True, benign_tokens=[]
        )
        assert bucket != B_LEGIT, (
            f"Low-activity official-claim lookalike must not be legit. Got {bucket}: {reason}"
        )

    def test_leet_near_miss_not_legit(self):
        # 'lumenfie1d' is a 1-char (l→1) leet near-miss of 'lumenfield'.
        acct = make_acct(
            handle="lumenfie1d",
            display_name="",
            biography="",
            follower_count=0,
            media_count=0,
        )
        bucket, reason, sim = classify_account(
            acct, "Lumenfield", "lumenfield", is_brand=True, benign_tokens=[]
        )
        assert bucket != B_LEGIT, (
            f"Leet near-miss throwaway must not be legit. Got {bucket}: {reason}"
        )
