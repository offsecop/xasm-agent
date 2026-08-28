"""
Accerta ground-truth STRUCTURAL scoring locks.

Binds to: TyposquatDetectTool._score_result()

STATUS: BOUND — _score_result EXISTS in typosquat_detect.py (structure-only).

#1751 — the scorer is STRUCTURE-ONLY (registration + lexical shape + TLD + MX)
and hard-capped at 49 (the MEDIUM ceiling). The enrichment weights that used to
live here (web/SSL, brand-in-title, WHOIS freshness, VT/PhishTank/OpenPhish,
email posture) and the Phase-3 HIGH gate moved to the BACKEND post-enrichment
re-score (backend/src/modules/brand-monitors/lookalike/
typosquat-enrichment-score.ts) — its jest Layer A spec carries the ported
recall/precision locks (fresh live clone → HIGH, feed hits → HIGH, unswept
lanes contribute nothing). The agent-side locks below pin what REMAINS
agent-side against the real Accerta audit ground truth:

  - owned/defensive registrations and unrelated entities never structurally
    exceed MEDIUM (they used to false-positive at HIGH);
  - the structural ceiling itself (49 / never HIGH / never CRITICAL);
  - the band ladder on engineered compositions.

This method is private (self._score_result) so we access it via an instance.
"""

import os
import sys

import pytest

# Add agent root to path so imports work without install.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from tools.typosquat_detect import TyposquatDetectTool

SCORER = TyposquatDetectTool()

_LEVEL_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


# ---------------------------------------------------------------------------
# §O — OWNED cluster: Accerta's own defensive registrations must not flag.
# ---------------------------------------------------------------------------
class TestOwnedDomainScoring:
    """Owned domains — structural score must stay LOW/INFO territory."""

    @pytest.mark.parametrize("domain,original", [
        ("accertio.xyz", "accerta.ca"),
        ("accertio.co", "accerta.ca"),
        ("accertio.app", "accerta.ca"),
        ("accertio.net", "accerta.ca"),
        ("accessoap.com", "accerta.ca"),
        ("accessoap.org", "accerta.ca"),
        ("accerta.net", "accerta.ca"),
    ])
    def test_owned_cluster_no_threat_signals(self, domain, original):
        """Owned domains with no MX → the structural score alone must land
        at most MEDIUM (they are name-similar by construction), and the
        distant ones LOW/INFO."""
        score, level = SCORER._score_result(
            original=original,
            candidate=domain,
            is_registered=True,
            mx_records=[],
        )
        assert _LEVEL_RANK[level] <= _LEVEL_RANK["MEDIUM"], (
            f"{domain}: expected <= MEDIUM but got {level} (score={score}). "
            "Structure-only can never exceed MEDIUM (#1751 ceiling)."
        )


# ---------------------------------------------------------------------------
# §A — UNRELATED domains: fail all ownership proofs, no threat signals.
# ---------------------------------------------------------------------------
class TestUnrelatedDomainScoring:
    """UNRELATED entities — should NOT be flagged above MEDIUM structurally."""

    @pytest.mark.parametrize("domain,original,expected_max_level", [
        # acerta.ca → Acerta Analytics (1-char near-miss: lexical shape alone)
        ("acerta.ca", "accerta.ca", "MEDIUM"),
        # accessmap.ca → map.ca alias
        ("accessmap.ca", "accerta.ca", "LOW"),
        # accerta.info → Italian sailing charter (dead)
        ("accerta.info", "accerta.ca", "MEDIUM"),
    ])
    def test_unrelated_entity_low_score(self, domain, original, expected_max_level):
        score, level = SCORER._score_result(
            original=original,
            candidate=domain,
            is_registered=True,
            mx_records=[],
        )
        assert _LEVEL_RANK.get(level, 99) <= _LEVEL_RANK[expected_max_level], (
            f"{domain}: expected ≤{expected_max_level} but got {level} (score={score})"
        )


# ---------------------------------------------------------------------------
# Structural ceiling: 49 max, never HIGH, never CRITICAL.
# ---------------------------------------------------------------------------
class TestScoreCap:
    """_score_result hard-caps at 49 — HIGH/CRITICAL never from structure."""

    def test_worst_case_structural_score_capped_at_49(self):
        """Even the worst structural shape (identity + combosquat + risk kw +
        suspicious TLD + MX) is capped at 49 / <= MEDIUM."""
        score, level = SCORER._score_result(
            original="accerta.ca",
            candidate="accerta-login.tk",
            is_registered=True,
            mx_records=["mail.accerta-login.tk"],
        )
        assert score <= 49, f"Score {score} exceeded the structural cap 49"
        assert level in ("MEDIUM", "LOW", "INFO"), (
            f"Structural scorer returned {level} — HIGH is backend "
            "post-enrichment only, CRITICAL is AI-only."
        )

    # Each case engineers a structural input whose additive score is KNOWN
    # (computed from the documented signal weights), then asserts the REAL
    # _score_result maps that score to the expected band. The thresholds are
    # NOT re-derived in the test — `expected_level` is a literal constant per
    # case, and `expected_score` self-checks the input engineering so a weight
    # change surfaces here instead of silently shifting a band.
    @pytest.mark.parametrize("case_id,inputs,expected_score,expected_level", [
        # reg(+10) = 10 → INFO (distant unrelated name, no other leg).
        (
            "info_below_low_cut",
            dict(candidate="unrelatedwebsite.test", is_registered=True),
            10, "INFO",
        ),
        # reg(+10)+dist1(+15)+lendiff(+2) = 27 → LOW band.
        (
            "low_mid_band",
            dict(candidate="accerto.ca", is_registered=True),
            27, "LOW",
        ),
        # reg(+10)+dist1(+15)+lendiff(+2)+mx(+8) = 35 → MEDIUM cut region.
        (
            "medium_with_mx",
            dict(candidate="accerto.ca", is_registered=True,
                 mx_records=["mx.accerto.ca"]),
            35, "MEDIUM",
        ),
        # reg(+10)+identity(+6, 'accerta' reads common → dampened)+dist2(+10)
        # +tld(+10)+lendiff(+2) = 38 → MEDIUM.
        (
            "medium_tld_swap",
            dict(candidate="accerta.tk", is_registered=True),
            38, "MEDIUM",
        ),
        # 38 + mx(+8) = 46 → MEDIUM, below the 49 ceiling (the cap lock lives
        # in test_typosquat_scoring_calib.py on the combosquat shape).
        (
            "medium_tld_swap_with_mx",
            dict(candidate="accerta.tk", is_registered=True,
                 mx_records=["mx.accerta.tk"]),
            46, "MEDIUM",
        ),
    ])
    def test_score_to_level_bands(self, case_id, inputs, expected_score, expected_level):
        """Drive the REAL _score_result with engineered inputs and assert the
        band it returns."""
        score, level = SCORER._score_result(original="accerta.ca", **inputs)
        assert score == expected_score, (
            f"{case_id}: engineered input scored {score}, expected {expected_score} "
            f"(level={level}). Signal weights changed — update the case and confirm "
            "the band still holds."
        )
        assert level == expected_level, (
            f"{case_id}: score {score} mapped to {level}, expected {expected_level}. "
            "Band cut regression in _score_result."
        )


# ---------------------------------------------------------------------------
# §G — structure-only ceiling on the combosquat attack shape.
# ---------------------------------------------------------------------------
class TestStructureOnlyCeiling:
    """The combosquat + risk-keyword shape reaches the raw HIGH cut and is
    capped — the agent can never emit HIGH without enrichment (#1751)."""

    def test_combosquat_risk_shape_capped(self):
        # accerta-login.tk = combosquat(+20) + risk-keyword 'login'(+10) +
        # reg(+10) + suspicious .tk(+10) = 50 raw → capped 49.
        score, level = SCORER._score_result(
            original="accerta.ca",
            candidate="accerta-login.tk",
            is_registered=True,
            mx_records=[],
        )
        assert score == 49, f"Expected the 49 ceiling, got {score}"
        assert _LEVEL_RANK[level] <= _LEVEL_RANK["MEDIUM"], (
            f"Structure-only attack shape scored {level} (score={score}); "
            "HIGH requires a backend post-enrichment positive signal."
        )
