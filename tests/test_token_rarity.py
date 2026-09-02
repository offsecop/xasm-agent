"""Phase 4 (P1-4 #825) — lib/token_rarity.py unit locks, BOTH directions,
driving the REAL wordfreq library (no mocks — the thresholds are calibrated
against the real Zipf tables, so a wordfreq data change that moves a
calibration token across a threshold must surface here, not in prod).

FICTITIOUS brands only for the RARE direction (lumenfield / finetre-class
coined names). The COMMON direction uses ordinary dictionary words — plain
English/romance-language vocabulary, not client identifiers.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from lib.token_rarity import (  # noqa: E402
    is_common_token,
    score_token_rarity,
    RISK_ANCHOR_TOKENS,
    COMMON_ZIPF,
    MEMBERSHIP_ZIPF,
)


class TestCommonDirection:
    """Ordinary words MUST read common — the dictionary-collision FP class."""

    def test_high_frequency_words_are_common(self):
        # The frequency leg (Zipf >= COMMON_ZIPF in some language).
        for w in ('vital', 'mode', 'sol', 'vertex', 'gap', 'stripe'):
            assert is_common_token(w), f'{w} must read COMMON'

    def test_lower_frequency_dictionary_word_is_common(self):
        # The membership leg: 'zinnia' (an ordinary flower name) sits BELOW the
        # frequency threshold (Zipf ~2.0 en) but must still read common —
        # exactly the roadmap gotcha the multi-signal combiner exists for.
        s = score_token_rarity('zinnia')
        assert s['max'] < COMMON_ZIPF, 'precondition: zinnia is below the frequency leg'
        assert s['max'] >= MEMBERSHIP_ZIPF
        assert is_common_token('zinnia')

    def test_romance_language_word_is_common(self):
        # Multi-language: an Italian verb form invisible to the EN list alone.
        s = score_token_rarity('accerta')
        assert s['it'] > 0.0
        assert is_common_token('accerta')

    def test_very_short_tokens_always_common(self):
        # 1-2 char tokens collide with everything — never rarity-protected.
        assert is_common_token('ab')
        assert is_common_token('x')


class TestRareDirection:
    """Coined brandable names MUST read rare — they keep full scoring weight."""

    def test_coined_names_are_rare(self):
        for w in ('lumenfield', 'finetre', 'cipherhollow', 'qorvex'):
            s = score_token_rarity(w)
            assert s['max'] < MEMBERSHIP_ZIPF, f'{w} zipf={s["max"]}'
            assert not is_common_token(w), f'{w} must read RARE'

    def test_non_alpha_token_needs_frequency_leg(self):
        # Digits/mixed tokens never take the membership leg.
        assert not is_common_token('lumen42field')

    def test_empty_token_is_not_common(self):
        assert not is_common_token('')
        assert not is_common_token(None)


class TestFailOpen:
    """A missing wordfreq must read RARE (prior scoring behavior, never a
    silent dampen of real detections)."""

    def test_wordfreq_failure_reads_rare(self, monkeypatch):
        import lib.token_rarity as tr
        monkeypatch.setattr(tr, '_wordfreq', None)
        monkeypatch.setattr(tr, '_wordfreq_failed', True)
        assert not tr.is_common_token('vital')
        assert tr.score_token_rarity('vital')['max'] == 0.0
        # 1-2 char tokens stay common even fail-open (pure length rule).
        assert tr.is_common_token('ab')


class TestRiskAnchorTokens:
    def test_credential_intent_tokens_present(self):
        for t in ('login', 'verify', 'support', 'account'):
            assert t in RISK_ANCHOR_TOKENS
