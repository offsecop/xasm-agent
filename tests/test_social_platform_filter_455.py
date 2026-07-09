"""G6 (#455) — social-handle per-platform filter + cross-platform remap +
UTS #39 display-name confusable detection.

FICTITIOUS brands only (lumenfield / modeapparel) so the run.ts hardcode
tripwire can never trip.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from lib.wrapper_helpers import (
    is_valid_handle_for_platform,
    remap_handle,
    filter_handles_for_platform,
    classify_account,
    B_IMPERSONATOR,
    B_BRAND_ADJ,
    B_LEGIT,
)
from tools.hiker_brand import _gen_brand_permutations, _MAX_BRAND_PERMUTATIONS
from tools.hiker_vip import _gen_vip_permutations


class TestPlatformFilter:
    def test_x_constraints(self):
        cands = ['your.brand', 'your-brand', 'toolongbrandnamehandle', 'ok_brand']
        out = filter_handles_for_platform(cands, 'x')
        for h in out:
            assert '.' not in h and '-' not in h
            assert len(h) <= 15
        assert 'toolongbrandnamehandle' not in out  # 22 chars > 15

    def test_linkedin_constraints(self):
        cands = ['your.brand', 'my-brand', 'Brand_X']
        out = filter_handles_for_platform(cands, 'linkedin')
        for h in out:
            assert h.isalnum() and h.islower()  # lowercase alphanumeric only

    def test_telegram_constraints(self):
        # Telegram: starts with a letter, ends alphanumeric, min length 5.
        assert is_valid_handle_for_platform('janedoe', 'telegram')
        assert not is_valid_handle_for_platform('1janedoe', 'telegram')   # starts digit
        assert not is_valid_handle_for_platform('jane_', 'telegram')      # ends separator
        assert not is_valid_handle_for_platform('jane', 'telegram')       # < 5

    def test_cross_platform_remap(self):
        assert remap_handle('your.brand', 'x') == 'your_brand'
        assert remap_handle('your.brand', 'linkedin') == 'yourbrand'
        assert remap_handle('your-brand', 'telegram') == 'your_brand'

    def test_generator_platform_filter_and_cap(self):
        # Brand generator yields X-valid handles and still honours the cap.
        out = _gen_brand_permutations('Mode Apparel', 'modeapparel', platform='x')
        assert len(out) <= _MAX_BRAND_PERMUTATIONS
        for h in out:
            assert is_valid_handle_for_platform(h, 'x')
        # Instagram (default) is unchanged and non-empty.
        assert len(_gen_brand_permutations('Mode Apparel', 'modeapparel')) > 0

    def test_vip_generator_platform_filter(self):
        out = _gen_vip_permutations('janedoe', platform='linkedin')
        for h in out:
            assert is_valid_handle_for_platform(h, 'linkedin')


class TestDisplayNameConfusable:
    def test_cyrillic_display_name_is_impersonator(self):
        # Display name 'Lumеnfield' with a Cyrillic 'е' + low followers.
        acct = {
            'handle': 'lumenfeld_x',
            'display_name': 'Lumеnfield',  # Cyrillic е
            'follower_count': 12,
            'media_count': 0,
            'account_type': 'PERSONAL',
        }
        bucket, reason, _ = classify_account(acct, 'Lumenfield', 'lumenfield', is_brand=True)
        assert bucket == B_IMPERSONATOR
        assert 'homoglyph' in reason.lower()

    def test_benign_ascii_display_name_stays_brand_adjacent(self):
        # A benign common-word display name with no brand signal is NOT escalated.
        acct = {
            'handle': 'modernart',
            'display_name': 'Modern Art Daily',
            'follower_count': 50,
            'media_count': 0,
            'account_type': 'PERSONAL',
        }
        bucket, _, _ = classify_account(acct, 'Mode', 'mode', is_brand=True)
        assert bucket == B_BRAND_ADJ

    def test_verified_homoglyph_not_flagged(self):
        # A verified account is LEGIT before the homoglyph rule runs.
        acct = {
            'handle': 'lumenfield',
            'display_name': 'Lumеnfield',
            'is_verified': True,
            'follower_count': 100000,
        }
        bucket, _, _ = classify_account(acct, 'Lumenfield', 'lumenfield', is_brand=True)
        assert bucket == B_LEGIT
