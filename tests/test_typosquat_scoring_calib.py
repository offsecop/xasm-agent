"""
Typosquat brand-content / active-threat gate — Phase 3 calibration locks
(FICTITIOUS brands only: lumenfield / .test / .tk — NO client brand strings,
so the run.ts hardcode tripwire can never trip on these).

Binds to: TyposquatDetectTool._score_result()  (agent/tools/typosquat_detect.py)

These DRIVE THE REAL _score_result and assert the band it returns — the band
ladder (HIGH>=50 / MEDIUM>=30 / LOW>=15 / INFO<15) is NEVER re-implemented in the
test. Each case engineers a STRUCTURE-ONLY additive score that reaches the HIGH
cut (>=50) via the documented signal weights (combosquat brand-token +20 +
risk-keyword +10 + reg/web/ssl + suspicious-TLD), so the Phase 3 GATE — not the
ladder — is the thing under test.

The gate (typosquat_detect.py §"Brand-content / active-threat gate for HIGH"):
a structure-only resemblance that reaches >=50 is capped to the MEDIUM ceiling
(49) UNLESS at least one POSITIVE brand-intent / active-threat / hard-intel
signal is present — brand keyword in the live <title>, VirusTotal/PhishTank/
OpenPhish hit, fresh (<=90d) registration, or MX+fresh. Unknown registration age
is FAIL-CLOSED (treated as NOT fresh), composing with the Phase-2 backend
null-age cap.

Lock classes (Layer A pytest — gated via run.ts `layerA_pytest`):
  calib_structure_only_cap   PRECISION — aged / unknown-age structure-only
                             (registered + web + ssl + combosquat + suspicious
                             TLD, NO vt/phishtank/title/mx-fresh) → level <= MEDIUM
                             (the gate caps the >=50 structure to 49).
  calib_brand_content_high   RECALL — the SAME structure + a brand keyword in the
                             page <title> (or a VirusTotal hit) → level HIGH (a
                             positive brand-intent / hard-intel signal qualifies).
  calib_fresh_gate_exempt    RECALL — the SAME structure but FRESH (<=90d) → HIGH
                             (the fresh-registration recency exemption).

RED mutations (each lock turns RED on a one-line change):
  calib_structure_only_cap  → delete the `score = 49` cap line (the gate body) ⇒
                              the 58-point structure stays HIGH ⇒ PRECISION RED.
  calib_brand_content_high  → drop `title_brand_hit` (or `hard_intel`) from the
                              gate's exemption list ⇒ a real brand-in-title clone
                              is wrongly capped to MEDIUM ⇒ RECALL RED.
  calib_fresh_gate_exempt   → drop `not is_fresh_90` from the gate condition ⇒ a
                              fresh weaponizing clone is capped to MEDIUM ⇒ RECALL
                              RED (the fresh-exemption regression).
"""

import os
import sys
from datetime import datetime, timedelta

import pytest

# Add agent root to path so imports work without install.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from tools.typosquat_detect import TyposquatDetectTool

SCORER = TyposquatDetectTool()

_LEVEL_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

# Shared STRUCTURE-ONLY shape on a FICTITIOUS brand. lumenfield-login.tk =
# combosquat brand-token 'lumenfield'(+20) + risk-keyword 'login'(+10) +
# reg(+10)+web(+5)+ssl(+3) + suspicious .tk(+10) = 58 → would be HIGH without
# the gate. No lexical-distance / brand-label-identity / length-diff bonus fires
# (the combosquat suffix makes the full-domain distance large), so the 58 is the
# pure structure-only total the gate exists to cap.
_STRUCT = dict(
    original="lumenfield.com",
    candidate="lumenfield-login.tk",
    is_registered=True,
    has_web=True,
    has_ssl=True,
    brand_keywords=["Lumenfield"],
)


class TestCalibStructureOnlyCap:
    """calib_structure_only_cap PRECISION — structure-only never reaches HIGH."""

    def test_aged_structure_only_capped_to_medium(self):
        """Aged (old WHOIS) structure-only resemblance, no positive signal →
        the gate caps the 58-point structure to the MEDIUM ceiling (49)."""
        score, level = SCORER._score_result(
            page_title="Welcome",          # NO brand keyword in title
            mx_records=[],
            whois_created="2015-01-01",     # old → NOT fresh
            vt_detections=None,
            final_url=None,
            phishtank_match=False,
            openphish_match=False,
            email_security=None,
            **_STRUCT,
        )
        assert score == 49, (
            f"calib_structure_only_cap: aged structure-only scored {score} "
            f"(level={level}); the Phase 3 gate must cap the >=50 structure to 49."
        )
        assert _LEVEL_RANK[level] <= _LEVEL_RANK["MEDIUM"], (
            f"calib_structure_only_cap: aged structure-only scored {level} — "
            "must stay <= MEDIUM (no positive brand-intent/active-threat signal)."
        )

    def test_null_age_structure_only_capped_to_medium(self):
        """Unknown registration age is FAIL-CLOSED (treated as NOT fresh) → the
        same structure is capped to the MEDIUM ceiling (49)."""
        score, level = SCORER._score_result(
            page_title="Welcome",
            mx_records=[],
            whois_created=None,             # unknown age → NOT fresh (fail-closed)
            vt_detections=None,
            final_url=None,
            phishtank_match=False,
            openphish_match=False,
            email_security=None,
            **_STRUCT,
        )
        assert score == 49, (
            f"calib_structure_only_cap: null-age structure-only scored {score}; "
            "unknown age must be treated as NOT fresh and capped to 49."
        )
        assert _LEVEL_RANK[level] <= _LEVEL_RANK["MEDIUM"], (
            f"calib_structure_only_cap: null-age structure-only scored {level} — "
            "unknown age must fail closed to <= MEDIUM."
        )


class TestCalibBrandContentHigh:
    """calib_brand_content_high RECALL — a positive signal qualifies HIGH."""

    @pytest.mark.parametrize("case_id,extra", [
        # Brand keyword present in the live page <title> (brand-intent signal).
        ("title_brand_hit", dict(page_title="Lumenfield Member Login",
                                 whois_created="2015-01-01")),
        # Hard intel: VirusTotal malicious detections.
        ("vt_malicious", dict(vt_detections={"malicious": 3},
                              whois_created="2015-01-01")),
    ])
    def test_positive_signal_qualifies_high(self, case_id, extra):
        """The SAME aged structure-only shape, PLUS one positive signal, must NOT
        be capped — it qualifies HIGH."""
        call = dict(
            page_title=None, mx_records=[], vt_detections=None, final_url=None,
            phishtank_match=False, openphish_match=False, email_security=None,
        )
        call.update(extra)
        score, level = SCORER._score_result(**_STRUCT, **call)
        assert level == "HIGH", (
            f"calib_brand_content_high[{case_id}]: positive signal present but "
            f"scored {level} (score={score}); the gate must NOT cap a resemblance "
            "carrying a real brand-intent / hard-intel signal."
        )
        assert score >= 50, f"{case_id}: score {score} below the HIGH cut (50)."


class TestCalibFreshGateExempt:
    """calib_fresh_gate_exempt RECALL — fresh (<=90d) structure-only stays HIGH."""

    def test_fresh_structure_only_exempt_high(self):
        """A FRESH (<=90d) registration is a positive recency signal — the gate
        EXEMPTS it, so the same structure-only shape reaches HIGH. Date computed
        from wall-clock now (the scorer's freshness math uses datetime.now())."""
        fresh = (datetime.now() - timedelta(days=10)).strftime("%Y-%m-%d")
        score, level = SCORER._score_result(
            page_title="Welcome",          # NO brand keyword in title
            mx_records=[],
            whois_created=fresh,            # <=90d → fresh exemption
            vt_detections=None,
            final_url=None,
            phishtank_match=False,
            openphish_match=False,
            email_security=None,
            **_STRUCT,
        )
        assert level == "HIGH", (
            f"calib_fresh_gate_exempt: fresh (<=90d) structure-only scored {level} "
            f"(score={score}); the fresh-registration exemption must keep it HIGH "
            "(a fresh weaponizing clone must not be capped to MEDIUM)."
        )
        assert score >= 50, f"fresh structure-only score {score} below HIGH cut (50)."
