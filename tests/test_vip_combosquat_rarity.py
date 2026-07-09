"""Phase 4 (P1-4 #825) — rarity-aware VIP-exposure standalone-token rule
(calib_rarity_vip_* locks on the REAL `_classify_serp_host`).

The P0-4 rule (#1056) requires the brand as a STANDALONE token before the
COMBOSQUAT hard-emit; Phase 4 makes it rarity-aware: an exact-but-COMMON brand
word ('mode' — the zinnia/vertex/vital collision class) additionally needs a
SECOND anchor (another brand token, or a credential/attack-suffix token)
before IMPERSONATION/HIGH. A bare common-word collision defers to the content
classifier (None), it is NOT suppressed. RARE (coined) brands are unaffected.

FICTITIOUS brands only: 'mode' / 'apparel' (mode.test) and 'lumenfield'.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from tools.brand_monitor_vip_exposure import (  # noqa: E402
    _classify_serp_host,
    _combosquat_second_anchor_present,
)


def classify(url, brand_tokens):
    return _classify_serp_host(
        url,
        owned_domains=['mode.test', 'lumenfield.test'],
        typosquat_domains=[],
        brand_tokens=brand_tokens,
        full_name='Jane Synth',
    )


class TestCommonWordPrecision:
    def test_bare_common_word_label_defers_to_content_classifier(self):
        # 'mode-outlet' — the common brand word standing alone next to a
        # NEUTRAL token: the ordinary-language collision. Must NOT hard-emit
        # IMPERSONATION/HIGH; defers (None), never 'suppress'.
        assert classify('https://mode-outlet.test/shop', ['mode']) is None

    def test_bare_common_word_exact_label_still_needs_anchor(self):
        assert classify('https://mode-store.test/', ['mode']) is None


class TestCommonWordRecall:
    def test_common_word_with_risk_anchor_flags_high(self):
        got = classify('https://mode-login.test/verify', ['mode'])
        assert got is not None and got['action'] == 'flag'
        assert got['severity'] == 'HIGH'
        assert got['category'] == 'COMBOSQUAT'

    def test_common_word_with_second_brand_token_flags_high(self):
        # Multi-word brand confirmation: 'mode' + 'apparel' both standalone.
        got = classify('https://mode-apparel-outlet.test/', ['mode', 'apparel'])
        assert got is not None and got['action'] == 'flag'
        assert got['severity'] == 'HIGH'


class TestRareBrandControl:
    def test_rare_brand_standalone_token_still_flags_without_anchor(self):
        # Coined brand: self-anchoring — pre-Phase-4 behavior preserved.
        got = classify('https://lumenfield-hub.test/', ['lumenfield'])
        assert got is not None and got['action'] == 'flag'
        assert got['severity'] == 'HIGH'


class TestSecondAnchorHelper:
    def test_no_matched_token_returns_false(self):
        assert not _combosquat_second_anchor_present('orchardgate', ['mode'])

    def test_rare_token_is_self_anchoring(self):
        assert _combosquat_second_anchor_present('lumenfield-hub', ['lumenfield'])

    def test_common_token_without_anchor_returns_false(self):
        assert not _combosquat_second_anchor_present('mode-outlet', ['mode'])

    def test_common_token_with_risk_token_returns_true(self):
        assert _combosquat_second_anchor_present('mode-support', ['mode'])
