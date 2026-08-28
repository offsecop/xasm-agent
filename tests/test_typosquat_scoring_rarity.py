"""Phase 4 (P1-4 #825) — token-rarity dampener locks on the REAL
TyposquatDetectTool._score_result (calib_rarity_* classes).

FICTITIOUS brands only: the COMMON-word brand is 'mode' (mode.test — an
ordinary dictionary word, the zinnia/vertex/vital collision class) and the
RARE control is 'lumenfield' (coined). No client brand strings — the run.ts
hardcode tripwire must never trip here.

The dampener acts on the two brand-token bonuses in `_score_result`:
  - brand-label identity (+12 → +6 for a common brand token),
  - combosquat containment (+20 → +6 for a common brand token WITHOUT a
    risk-keyword second anchor; the anchor restores +20+10).

Lock classes (Layer A pytest — gated via run.ts `layerA_pytest`):
  calib_rarity_common_dampen   PRECISION — a bare common-word collision
                               ("mode-hub.tk", aged/unknown age, no anchors)
                               scores STRICTLY LESS than the identical shape on
                               the RARE brand, and stays below the HIGH band.
  calib_rarity_anchor_recall   RECALL — the SAME common-word brand WITH the
                               second anchor ("mode-login.tk") keeps the full
                               containment weight (hits the 49 structural cap;
                               the HIGH band itself is backend post-enrichment,
                               #1751).
  calib_rarity_rare_unaffected CONTROL — the RARE brand's scores are
                               byte-identical to the pre-dampener weights
                               (rarity dampening must never touch coined
                               brands; fail-open parity).

RED mutations (each lock turns RED on a one-line change):
  calib_rarity_common_dampen   → drop the `brand_is_common` branch (always
                                 +20/+12) ⇒ the collision shape scores equal to
                                 the rare control ⇒ PRECISION RED.
  calib_rarity_anchor_recall   → make the dampener unconditional (ignore the
                                 risk-keyword anchor) ⇒ "mode-login" loses the
                                 attack-shape weight ⇒ RECALL RED.
  calib_rarity_rare_unaffected → invert `is_common_token` ⇒ coined brands get
                                 dampened ⇒ CONTROL RED.
"""

import os
import sys
from datetime import datetime, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from tools.typosquat_detect import TyposquatDetectTool  # noqa: E402

SCORER = TyposquatDetectTool()

_LEVEL_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

AGED = (datetime.now() - timedelta(days=5 * 365)).strftime('%Y-%m-%d')
FRESH = (datetime.now() - timedelta(days=20)).strftime('%Y-%m-%d')


def score(original, candidate, **kw):
    defaults = dict(is_registered=True)
    defaults.update(kw)
    return SCORER._score_result(original, candidate, **defaults)


class TestCalibRarityCommonDampen:
    """calib_rarity_common_dampen PRECISION — bare common-word collisions."""

    def test_common_containment_scores_below_rare_twin(self):
        # Identical shape, only the brand token's rarity differs.
        common_score, _ = score('mode.com', 'mode-hub.tk')
        rare_score, _ = score('lumenfield.com', 'lumenfield-hub.tk')
        assert common_score < rare_score, (
            f'common-word containment ({common_score}) must score below the '
            f'rare twin ({rare_score})'
        )

    def test_common_containment_stays_below_high(self):
        # Aged, structure-only, no anchor: registered+web+ssl + dampened
        # containment + suspicious TLD must not reach the HIGH band.
        s, level = score('mode.com', 'mode-hub.tk')
        assert _LEVEL_RANK[level] < _LEVEL_RANK['HIGH'], f'score={s} level={level}'

    def test_common_tld_swap_identity_dampened(self):
        # Exact common-word name on another TLD (the "zinnia.net is a florist"
        # class) scores below the rare-brand TLD swap.
        common_score, _ = score('mode.com', 'mode.tk')
        rare_score, _ = score('lumenfield.com', 'lumenfield.tk')
        assert common_score < rare_score


class TestCalibRarityAnchorRecall:
    """calib_rarity_anchor_recall RECALL — the second anchor restores weight."""

    def test_common_with_risk_keyword_keeps_full_weight(self):
        # "mode-login.tk": containment +20 + risk-kw +10 + reg + suspicious TLD
        # = 50 raw → the structural ceiling caps it at 49/MEDIUM (#1751 — HIGH
        # is backend post-enrichment). The dictionary word must NOT shield an
        # attack-shaped label: the full containment weight keeps it AT the cap.
        s, level = score('mode.com', 'mode-login.tk')
        assert s == 49 and level == 'MEDIUM', f'score={s} level={level}'

    def test_anchor_beats_bare_collision(self):
        anchored, _ = score('mode.com', 'mode-login.tk')
        bare, _ = score('mode.com', 'mode-hub.tk')
        assert anchored > bare


class TestCalibRarityRareUnaffected:
    """calib_rarity_rare_unaffected CONTROL — coined brands keep full weights."""

    def test_rare_containment_unchanged(self):
        # lumenfield-hub.tk: reg(10)+web(5)+ssl(3)+containment(20)+tld(10)+aged
        # → the containment leg must contribute the FULL +20 (score delta vs
        # the no-containment control is exactly 20).
        with_containment, _ = score('lumenfield.com', 'lumenfield-hub.tk')
        without, _ = score('lumenfield.com', 'orchardgate-hub.tk')
        assert with_containment - without == 20

    def test_rare_tld_swap_keeps_full_identity_bonus(self):
        s_swap, _ = score('lumenfield.com', 'lumenfield.tk')
        s_ctrl, _ = score('lumenfield.com', 'orchardgate.tk')
        # identity(+12) + the lexical-distance difference; assert at least the
        # full +12 present (control shares reg/web/ssl/tld legs).
        assert s_swap - s_ctrl >= 12
