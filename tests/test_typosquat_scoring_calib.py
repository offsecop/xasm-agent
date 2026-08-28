"""
Typosquat STRUCTURAL scorer — structure-only ceiling locks
(FICTITIOUS brands only: lumenfield / .test / .tk — NO client brand strings,
so the run.ts hardcode tripwire can never trip on these).

Binds to: TyposquatDetectTool._score_result()  (agent/tools/typosquat_detect.py)

#1751 — the scorer is STRUCTURE-ONLY by design. The enrichment weights (web/
SSL liveness, brand-in-title, WHOIS freshness, VT/PhishTank/OpenPhish, email
posture) and the Phase-3 HIGH gate moved to the BACKEND post-enrichment
re-score (backend/src/modules/brand-monitors/lookalike/
typosquat-enrichment-score.ts — jest Layer A locks live in
typosquat-enrichment-score.spec.ts). What remains agent-side, and what these
locks pin:

  calib_structure_only_cap   PRECISION — a structure-only resemblance whose
                             additive weights reach the HIGH cut (>=50) is
                             hard-capped at 49 (the MEDIUM ceiling): the agent
                             can NEVER emit HIGH/CRITICAL on shape alone.
  calib_band_ladder          The band ladder below the cap (MEDIUM>=30 /
                             LOW>=15 / INFO<15) is unchanged.

RED mutations (each lock turns RED on a one-line change):
  calib_structure_only_cap  → delete the `score = min(score, 49)` cap ⇒ the
                              50-point structure lands HIGH ⇒ PRECISION RED.
  calib_band_ladder         → move a band cut ⇒ the composition cases below
                              map to the wrong band ⇒ RED.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from tools.typosquat_detect import TyposquatDetectTool

SCORER = TyposquatDetectTool()

_LEVEL_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


class TestCalibStructureOnlyCap:
    """calib_structure_only_cap PRECISION — structure-only never reaches HIGH."""

    def test_combosquat_risk_keyword_capped_to_49(self):
        # lumenfield-login.tk = reg(+10) + combosquat 'lumenfield'(+20) +
        # risk-keyword 'login'(+10) + suspicious .tk(+10) = 50 → capped 49.
        score, level = SCORER._score_result(
            'lumenfield.com', 'lumenfield-login.tk',
            is_registered=True, mx_records=[],
        )
        assert score == 49, (
            f"structure-only 50-point shape scored {score} (level={level}); "
            "the structural ceiling must cap it at 49."
        )
        assert _LEVEL_RANK[level] <= _LEVEL_RANK["MEDIUM"], (
            f"structure-only shape scored {level} — the agent must never emit "
            "HIGH on shape alone (#1751: HIGH is backend post-enrichment)."
        )

    def test_mx_cannot_push_past_the_ceiling(self):
        # The same shape + MX(+8) = 58 raw → still capped 49 / <= MEDIUM.
        score, level = SCORER._score_result(
            'lumenfield.com', 'lumenfield-login.tk',
            is_registered=True, mx_records=['mx1.lumenfield-login.tk'],
        )
        assert score == 49 and _LEVEL_RANK[level] <= _LEVEL_RANK["MEDIUM"], (
            f"MX-capable structure-only shape scored {score}/{level}; "
            "MX is structural and must not breach the 49 ceiling."
        )

    def test_never_high_or_critical(self):
        score, level = SCORER._score_result(
            'lumenfield.com', 'lumenfield.tk',
            is_registered=True, mx_records=['mx1.lumenfield.tk'],
        )
        assert level not in ("HIGH", "CRITICAL"), (
            f"structural scorer returned {level} (score={score}) — "
            "HIGH/CRITICAL are enrichment/AI bands, never structural."
        )


class TestCalibBandLadder:
    """calib_band_ladder — the band cuts below the cap are unchanged."""

    def test_registration_only_is_info(self):
        # reg(+10) + len-diff<=2(+2) = 12 → INFO (<15). No lexical/containment leg.
        score, level = SCORER._score_result(
            'lumenfield.com', 'orchardgate.test', is_registered=True,
        )
        assert score == 12 and level == 'INFO', f"got {score}/{level}"

    def test_tld_swap_lands_medium(self):
        # lumenfield.tk: reg(+10) + identity(+12, coined brand) + dist3(+5)
        # + suspicious .tk(+10) + len-diff<=2(+2) = 39 → MEDIUM.
        score, level = SCORER._score_result(
            'lumenfield.com', 'lumenfield.tk', is_registered=True,
        )
        assert score == 39 and level == 'MEDIUM', f"got {score}/{level}"

    def test_unregistered_near_miss_is_low_band(self):
        # Unregistered transposition: dist1(+15) + len(+2) = 17 → LOW.
        score, level = SCORER._score_result(
            'lumenfield.com', 'lumenifeld.com', is_registered=False,
        )
        assert score == 17 and level == 'LOW', f"got {score}/{level}"
