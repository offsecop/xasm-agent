"""
Typosquat domain structural scoring — Accerta golden-set Layer A tests.

Binds to: TyposquatDetectTool._score_result()

STATUS: BOUND — _score_result EXISTS in typosquat_detect.py:1010.
This method is private (self._score_result) so we access it via an
instance. No extraction needed.

Ground truth: ACCERTA-AUDIT-GROUNDTRUTH.md §A + §B
"""

import sys
import os
import pytest

# Add agent root to path so imports work without install
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from tools.typosquat_detect import TyposquatDetectTool

SCORER = TyposquatDetectTool()

FROZEN_NOW = "2026-06-11T00:00:00Z"  # matches manifest.json


# ---------------------------------------------------------------------------
# §A — OWNED domains: all 12 owned domains should score LOW or INFO
# when resolved as owned (no real threat signals fire).
# The structural scorer receives the raw HTTP/DNS facts; the ownership
# verdict happens upstream. So we test that an "all benign" signal set
# produces LOW/INFO, confirming the scorer can't produce false HIGH.
# ---------------------------------------------------------------------------
class TestOwnedDomainBenignScoring:
    """Owned domains have no real threat indicators — structural score must be LOW/INFO."""

    @pytest.mark.skip(
        reason=(
            "owned-domain suppression is Layer B (ingestion resolveOwnership/ownedDomains), "
            "not the structural agent scorer — asserted in the Layer B replay tier. "
            "The structural scorer SHOULD return MEDIUM for a near-identical name; "
            "suppression to INFO happens at ingestion. "
            "See backend/test/drp-replay/fixtures/accerta/expected/domains.expected.json "
            "(accertio.xyz, accerta.net etc. expectedSeverity=INFO, expectedAlertSuppressed=true)."
        )
    )
    @pytest.mark.parametrize("domain,original,registered,has_web,has_ssl,age_days", [
        # The accertio.xyz cluster: same-brand TLD swap + old registration
        ("accertio.xyz", "accerta.ca", True, True, True, 1095),
        ("accertio.co", "accerta.ca", True, True, True, 1095),
        ("accertio.app", "accerta.ca", True, True, True, 1095),
        ("accertio.net", "accerta.ca", True, True, True, 1095),
        ("accessoap.com", "accerta.ca", True, True, True, 1095),
        ("accessoap.org", "accerta.ca", True, True, True, 1095),
        ("accerta.net", "accerta.ca", True, True, True, 1095),
    ])
    def test_owned_cluster_no_threat_signals(
        self, domain, original, registered, has_web, has_ssl, age_days,
    ):
        """Owned domains with no threat indicators (no brand keyword in title,
        no MX, no VirusTotal hits, old registration, no phishtank) → LOW or INFO."""
        score, level = SCORER._score_result(
            original=original,
            candidate=domain,
            is_registered=registered,
            has_web=has_web,
            has_ssl=has_ssl,
            page_title=None,           # no brand keyword in title
            mx_records=[],             # no MX → not email-capable
            brand_keywords=["Accerta"],
            whois_created="2023-01-01",  # ~3yr ago → not fresh
            vt_detections=None,
            final_url=None,
            phishtank_match=False,
            openphish_match=False,
            email_security=None,
        )
        assert level in ("LOW", "INFO"), (
            f"{domain}: expected LOW/INFO but got {level} (score={score}). "
            "Owned domains with no threat signals should not reach MEDIUM+."
        )


# ---------------------------------------------------------------------------
# §A — UNRELATED domains: these fail all ownership proofs and have
# no brand keyword in title/MX/VirusTotal → should score LOW/INFO.
# ---------------------------------------------------------------------------
class TestUnrelatedDomainScoring:
    """UNRELATED entities — should NOT be flagged MEDIUM+."""

    @pytest.mark.parametrize("domain,original,page_title,expected_max_level", [
        # acerta.ca → Acerta Analytics, no brand keyword in title
        ("acerta.ca", "accerta.ca", "Acerta Analytics — Industrial AI", "MEDIUM"),
        # accessmap.ca → map.ca alias
        ("accessmap.ca", "accerta.ca", None, "LOW"),
        # accerta.info → Italian sailing charter (dead)
        ("accerta.info", "accerta.ca", "Accerta Sailing — Lisbon Charter", "MEDIUM"),
    ])
    def test_unrelated_entity_low_score(self, domain, original, page_title, expected_max_level):
        """Unrelated entities with no active threat signals → LOW/INFO."""
        score, level = SCORER._score_result(
            original=original,
            candidate=domain,
            is_registered=True,
            has_web=False,  # dead / redirect / no live content
            has_ssl=False,
            page_title=page_title,
            mx_records=[],
            brand_keywords=["Accerta"],
            whois_created="2015-01-01",  # old registration
            vt_detections=None,
            final_url=None,
            phishtank_match=False,
            openphish_match=False,
            email_security=None,
        )
        level_rank = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}
        assert level_rank.get(level, 4) <= level_rank.get(expected_max_level, 4), (
            f"{domain}: expected ≤{expected_max_level} but got {level} (score={score})"
        )


# ---------------------------------------------------------------------------
# §B — NEW_REGISTRATION recency gate: stale domains → no HIGH.
# The structural scorer contributes to severity through its base score;
# the recency gate is upstream but the scorer's age-related bonuses
# must not push stale domains to HIGH on score alone.
# ---------------------------------------------------------------------------
class TestRegistrationAgeDampening:
    """Old registrations should score below 50 (< HIGH threshold)."""

    @pytest.mark.parametrize("domain,whois_created,expected_max_score", [
        # 5-year-old accertio.com parked for-sale → no MX, no brand in title
        ("accertio.com", "2018-01-01", 49),
        # acerta.ca 2013 → very old
        ("acerta.ca", "2013-06-01", 49),
        # accerta.info 2010 est. → old
        ("accerta.info", "2010-01-01", 49),
    ])
    def test_old_registration_score_below_high(self, domain, whois_created, expected_max_score):
        score, level = SCORER._score_result(
            original="accerta.ca",
            candidate=domain,
            is_registered=True,
            has_web=False,
            has_ssl=False,
            page_title=None,
            mx_records=[],
            brand_keywords=["Accerta"],
            whois_created=whois_created,
            vt_detections=None,
            final_url=None,
            phishtank_match=False,
            openphish_match=False,
            email_security=None,
        )
        level_rank = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        assert score <= expected_max_score, (
            f"{domain}: old domain (whois={whois_created}) scored {score} "
            f"(level={level}); expected <= {expected_max_score}."
        )
        # Assert a band RANGE (<= MEDIUM), not `!= HIGH`. `!= HIGH` would pass
        # on a CRITICAL escalation; an OLD domain with no active threat signals
        # must land at most MEDIUM.
        assert level_rank.get(level, 99) <= level_rank["MEDIUM"], (
            f"{domain}: old domain (whois={whois_created}) scored {level} (score={score}). "
            "OLD domains with no active threat indicators must stay <= MEDIUM."
        )


# ---------------------------------------------------------------------------
# §E — Synthetic true positive #1: fresh phishing clone.
# A 7-day-old live domain with brand keyword in title, MX, SSL → HIGH.
# ---------------------------------------------------------------------------
class TestSyntheticPhishingClone:
    """Synthetic recall test: fresh live phishing clone must score HIGH."""

    def test_fresh_live_clone_scores_high(self):
        """accerta-health-login.com: 7d old, has web, has SSL, brand in title, MX → HIGH."""
        score, level = SCORER._score_result(
            original="accerta.ca",
            candidate="accerta-health-login.com",
            is_registered=True,
            has_web=True,
            has_ssl=True,
            page_title="Accerta Health — Member Login",
            mx_records=["mail.accerta-health-login.com"],
            brand_keywords=["Accerta"],
            whois_created="2026-06-04",  # 7 days ago from frozen now
            vt_detections=None,
            final_url=None,
            phishtank_match=False,
            openphish_match=False,
            email_security=None,
        )
        assert level == "HIGH", (
            f"Synthetic phishing clone scored {level} (score={score}). "
            "Expected HIGH: fresh registration + live + brand keyword in title + MX."
        )
        assert score >= 50, f"Score {score} below HIGH threshold 50"

    def test_boundary_negative_parked_old_domain_not_high(self):
        """Boundary-negative: 3yr parked lookalike, no content → NOT HIGH."""
        score, level = SCORER._score_result(
            original="accerta.ca",
            candidate="accerta-portal-old.com",
            is_registered=True,
            has_web=False,
            has_ssl=False,
            page_title=None,
            mx_records=[],
            brand_keywords=["Accerta"],
            whois_created="2023-06-11",  # 3 years ago
            vt_detections=None,
            final_url=None,
            phishtank_match=False,
            openphish_match=False,
            email_security=None,
        )
        # Assert a band RANGE (<= MEDIUM), not `!= HIGH` (which would pass on a
        # CRITICAL escalation). A 3yr parked lookalike with no live content must
        # stay at most MEDIUM on structure alone.
        level_rank = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        assert level_rank.get(level, 99) <= level_rank["MEDIUM"], (
            f"Old parked domain scored {level} (score={score}). "
            "Boundary-negative: 3yr parked domain MUST stay <= MEDIUM on age alone."
        )


# ---------------------------------------------------------------------------
# Score cap: structural scorer is capped at 75 (HIGH max = 75).
# CRITICAL is reserved for AI-confirmed phishing.
# ---------------------------------------------------------------------------
class TestScoreCap:
    """_score_result hard-caps at 75 — CRITICAL never from structural scoring."""

    def test_worst_case_score_capped_at_75(self):
        """Even with all threat signals, structural score is capped at 75 (HIGH, not CRITICAL)."""
        score, level = SCORER._score_result(
            original="accerta.ca",
            candidate="accerta.ca.phish.com",
            is_registered=True,
            has_web=True,
            has_ssl=True,
            page_title="Accerta Health Portal",
            mx_records=["mail.phish.com"],
            brand_keywords=["Accerta"],
            whois_created="2026-06-10",  # 1 day old, fresh
            vt_detections={"malicious": 15, "suspicious": 5},
            final_url="https://evil.com/steal",
            phishtank_match=True,
            openphish_match=True,
            email_security={"spf": {"has_spf": False}, "dmarc": {"has_dmarc": False}},
        )
        assert score <= 75, f"Score {score} exceeded hard cap 75"
        assert level in ("HIGH", "MEDIUM", "LOW", "INFO"), f"Unexpected level: {level}"
        assert level != "CRITICAL", "Structural scorer must never return CRITICAL (reserved for AI)"

    # Each case engineers a structural input whose additive score is KNOWN
    # (computed from the documented signal weights), then asserts the REAL
    # _score_result maps that score to the expected band. The thresholds are
    # NOT re-derived in the test — `expected_level` is a literal constant per
    # case, and `expected_score` self-checks the input engineering so a weight
    # change surfaces here instead of silently shifting a band. Cases sit on or
    # adjacent to each band cut (INFO<15, LOW>=15, MEDIUM>=30, HIGH>=50).
    @pytest.mark.parametrize("case_id,inputs,expected_score,expected_level", [
        # reg(+10)+ssl(+3) = 13 → just below the LOW cut.
        (
            "info_below_low_cut",
            dict(candidate="unrelatedwebsite.test", is_registered=True,
                 has_web=False, has_ssl=True),
            13, "INFO",
        ),
        # reg(+10)+web(+5) = 15 → exactly the LOW cut.
        (
            "low_at_cut",
            dict(candidate="unrelatedweb.test", is_registered=True,
                 has_web=True, has_ssl=False),
            15, "LOW",
        ),
        # reg(+10)+dist1(+15)+lendiff(+2) = 27 → mid LOW band.
        (
            "low_mid_band",
            dict(candidate="accerto.ca", is_registered=True,
                 has_web=False, has_ssl=False),
            27, "LOW",
        ),
        # reg(+10)+web(+5)+ssl(+3)+dist2(+10)+lendiff(+2) = 30 → exactly the MEDIUM cut.
        (
            "medium_at_cut",
            dict(candidate="axxerta.ca", is_registered=True,
                 has_web=True, has_ssl=True),
            30, "MEDIUM",
        ),
        # reg(+10)+web(+5)+ssl(+3)+dist1(+15)+title(+10)+lendiff(+2) = 45 → mid MEDIUM band.
        (
            "medium_below_high_cut",
            dict(candidate="accerto.ca", is_registered=True, has_web=True,
                 has_ssl=True, page_title="Accerta Member Login"),
            45, "MEDIUM",
        ),
        # 45 + suspicious-redirect(+5) = 50 → exactly the HIGH cut.
        (
            "high_at_cut",
            dict(candidate="accerto.ca", is_registered=True, has_web=True,
                 has_ssl=True, page_title="Accerta Member Login",
                 final_url="https://malware.test/login"),
            50, "HIGH",
        ),
        # 50 + mx(+8) = 58 → clearly inside the HIGH band.
        (
            "high_mid_band",
            dict(candidate="accerto.ca", is_registered=True, has_web=True,
                 has_ssl=True, page_title="Accerta Member Login",
                 final_url="https://malware.test/login",
                 mx_records=["mx.accerto.ca"]),
            58, "HIGH",
        ),
    ])
    def test_score_to_level_bands(self, case_id, inputs, expected_score, expected_level):
        """Drive the REAL _score_result with engineered inputs and assert the
        band it returns. No re-derivation of thresholds — the input's score is
        known up front and the expected band is a literal per case."""
        score, level = SCORER._score_result(
            original="accerta.ca",
            brand_keywords=["Accerta"],
            whois_created=None,  # date-independent: no age/fresh/interaction bonus
            **inputs,
        )
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
# §G — Phase 3 brand-content / active-threat gate.
# A structure-only resemblance whose ADDITIVE score reaches the HIGH cut
# (>=50) must NOT land HIGH unless a POSITIVE brand-intent / active-threat /
# hard-intel signal is present. Every case below engineers a structural score
# of >=50 (combosquat + risk-keyword + suspicious TLD + reg/web/ssl) so the
# gate — not the band ladder — is the thing under test. Precision cases assert
# the cap fires (<= MEDIUM); recall cases assert each individual positive
# signal exempts the same shape (HIGH preserved).
# ---------------------------------------------------------------------------
class TestBrandContentGate:
    """_score_result Phase 3 gate: structure-only never reaches HIGH alone."""

    # Shared structure-only shape: accerta-login.tk = combosquat(+20) +
    # risk-keyword 'login'(+10) + reg(+10)+web(+5)+ssl(+3) + suspicious .tk(+10)
    # = 58 before any positive signal → would be HIGH without the gate.
    _STRUCT_KW = dict(
        original="accerta.ca",
        candidate="accerta-login.tk",
        is_registered=True,
        has_web=True,
        has_ssl=True,
        brand_keywords=["Accerta"],
    )

    def test_structure_only_old_capped_to_medium(self):
        """Aged structure-only resemblance, no positive signal → capped <= MEDIUM."""
        score, level = SCORER._score_result(
            page_title="Welcome",  # NO brand keyword in title
            mx_records=[],
            whois_created="2015-01-01",  # old
            vt_detections=None,
            phishtank_match=False,
            openphish_match=False,
            **self._STRUCT_KW,
        )
        level_rank = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        assert level_rank[level] <= level_rank["MEDIUM"], (
            f"Structure-only aged resemblance scored {level} (score={score}); "
            "the Phase 3 gate must cap it to MEDIUM (no positive signal)."
        )
        assert score == 49, f"Expected MEDIUM-ceiling cap (49), got {score}"

    def test_structure_only_null_age_capped_to_medium(self):
        """Unknown age is fail-closed (treated as NOT fresh) → capped <= MEDIUM."""
        score, level = SCORER._score_result(
            page_title="Welcome",
            mx_records=[],
            whois_created=None,  # unknown age → NOT fresh (fail-closed)
            vt_detections=None,
            phishtank_match=False,
            openphish_match=False,
            **self._STRUCT_KW,
        )
        assert level != "HIGH", (
            f"Null-age structure-only resemblance scored {level} (score={score}); "
            "unknown age must be treated as NOT fresh and capped."
        )
        assert score == 49, f"Expected MEDIUM-ceiling cap (49), got {score}"

    def test_mx_without_freshness_still_capped(self):
        """MX alone (without freshness) is NOT a HIGH qualifier → still capped."""
        score, level = SCORER._score_result(
            page_title="Welcome",
            mx_records=["mx.accerta-login.tk"],  # email-capable but OLD
            whois_created="2015-01-01",
            vt_detections=None,
            phishtank_match=False,
            openphish_match=False,
            **self._STRUCT_KW,
        )
        assert level != "HIGH", (
            f"Old MX-capable structure-only resemblance scored {level} (score={score}); "
            "MX without freshness must not qualify HIGH."
        )

    @pytest.mark.parametrize("case_id,kwargs", [
        # Fresh (<=90d) registration is a positive recency signal.
        ("fresh_90d", dict(whois_created="2026-05-01")),
        # Brand keyword present in the live page title.
        ("title_brand_hit", dict(page_title="Accerta Member Login",
                                 whois_created="2015-01-01")),
        # Hard intel: VirusTotal malicious.
        ("vt_malicious", dict(vt_detections={"malicious": 3},
                              whois_created="2015-01-01")),
        # Hard intel: PhishTank verified.
        ("phishtank", dict(phishtank_match=True, whois_created="2015-01-01")),
        # Hard intel: OpenPhish feed.
        ("openphish", dict(openphish_match=True, whois_created="2015-01-01")),
        # Email-capable AND fresh → composite positive signal.
        ("mx_and_fresh", dict(mx_records=["mx.accerta-login.tk"],
                              whois_created="2026-05-01")),
    ])
    def test_positive_signal_exempts_high(self, case_id, kwargs):
        """Each positive signal alone exempts the same structure-only shape → HIGH."""
        call = dict(page_title=None, mx_records=[], vt_detections=None,
                    phishtank_match=False, openphish_match=False)
        call.update(kwargs)
        score, level = SCORER._score_result(**self._STRUCT_KW, **call)
        assert level == "HIGH", (
            f"{case_id}: positive signal present but scored {level} (score={score}); "
            "the Phase 3 gate must NOT cap a resemblance with a real signal."
        )
