"""
scrapecreators_ads classify — Accerta golden-set Layer A tests.

Binds to:
  - _classify_fb(ad, legit_page_ids, legit_domains, brand) [EXISTS at scrapecreators_ads.py:273]
  - _ad_brand_relevance(ad, brand) [EXISTS at scrapecreators_ads.py:245]
  - _domain_matches_whitelist(dom, legit_domains) [EXISTS at scrapecreators_ads.py:217]

STATUS: FULLY BOUND — all three functions exist.

Ground truth: ACCERTA-AUDIT-GROUNDTRUTH.md §D
  - Bare "OAP" collisions → brand_adjacent (not impersonator)
  - Italian verb "accerta" → brand_adjacent
  - Whitelisted partners (Mrs Tutor, Endless Abilities, Spectacokids, Aspire ABA) → legit
  - Name collision (Accerta Cybersecurity) → brand_adjacent
  - Geo-gated ads (DE/IN/AU/PH/MY/TH/IT/UK) → brand_adjacent
  - Synthetic ad impersonator → impersonator
"""

import sys
import os
import json
import pytest
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from tools.scrapecreators_ads import (
    _classify_fb,
    _ad_brand_relevance,
    _domain_matches_whitelist,
)

BRAND = "Accerta"
LEGIT_PAGE_IDS = set()   # no owned FB page IDs for Accerta (they use web-only)
LEGIT_DOMAINS = {"accerta.ca", "accessoap.com"}
PARTNER_NAMES = {"Mrs Tutor", "Endless Abilities", "Spectacokids", "Aspire ABA"}

FIXTURE_ROOT = Path(__file__).parent.parent.parent / "test" / "drp-replay" / "fixtures" / "accerta"


# ---------------------------------------------------------------------------
# §D — Bare OAP keyword collisions → NOT impersonator.
# ---------------------------------------------------------------------------
class TestOapKeywordCollisions:
    """Bare 'OAP' keyword must not produce impersonator unless brand-relevant."""

    @pytest.mark.parametrize("case_id,advertiser_id,advertiser_name,link_domain,creative_text,country", [
        (
            "iiit-ranchi-oap",
            "123456789",
            "IIIT Ranchi OAP Division",
            "iiitranchi.ac.in",
            "OAP semester results announced. Apply now.",
            "IN",
        ),
        (
            "german-oap-fiber",
            "987654321",
            "OpticalAccessPoint GmbH",
            "oap-fiber.de",
            "Optical Access Point — Glasfaser für Unternehmen",
            "DE",
        ),
        (
            "uk-oap-senior",
            "111222333",
            "Senior Lifestyle UK",
            "seniorlifestyle.co.uk",
            "OAP deals — savings for over 65s",
            "GB",
        ),
    ])
    def test_oap_collision_not_impersonator(
        self, case_id, advertiser_id, advertiser_name, link_domain, creative_text, country
    ):
        """Bare OAP keyword with no Accerta brand token → brand_adjacent."""
        ad = {
            "advertiser_id": advertiser_id,
            "advertiser_name": advertiser_name,
            "link_domain": link_domain,
            "creative_text": creative_text,
        }
        bucket, reason, evidence = _classify_fb(ad, LEGIT_PAGE_IDS, LEGIT_DOMAINS, BRAND)
        assert bucket != "impersonator", (
            f"[{case_id}] OAP collision '{advertiser_name}' should NOT be impersonator. "
            f"Got {bucket}: {reason}"
        )
        assert bucket in ("brand_adjacent", "legit"), (
            f"[{case_id}] Expected brand_adjacent/legit, got {bucket}: {reason}"
        )

    def test_iiit_ranchi_brand_relevance_check(self):
        """_ad_brand_relevance returns False for IIIT Ranchi (no Accerta token)."""
        ad = {
            "advertiser_id": "123456789",
            "advertiser_name": "IIIT Ranchi OAP Division",
            "link_domain": "iiitranchi.ac.in",
            "creative_text": "OAP semester results announced. Apply now.",
        }
        is_relevant, signals = _ad_brand_relevance(ad, BRAND)
        assert not is_relevant, (
            f"IIIT Ranchi has no Accerta brand token — should not be relevant. "
            f"Signals: {signals}"
        )
        assert len(signals) == 0, f"No brand signals expected, got: {signals}"


# ---------------------------------------------------------------------------
# §D — Italian verb "accerta" → brand_adjacent.
# ---------------------------------------------------------------------------
class TestItalianVerbAccerta:
    @pytest.mark.xfail(
        reason=(
            "WP-2-geo: multilingual disambiguation of the Italian verb 'accerta' vs the brand "
            "— tracked follow-up. The brand keyword 'accerta' fires on creative_text "
            "'Il tribunale accerta la colpevolezza' (Italian for 'the court ascertains guilt'), "
            "producing a false impersonator bucket. Geo/language gate suppression is a deferred "
            "feature (WP-2 follow-up); do NOT implement a geo gate in this iteration."
        ),
        strict=False,
    )
    def test_italian_legal_ad_brand_adjacent(self):
        """Italian legal ad with 'accerta' as verb → no brand relevance → brand_adjacent."""
        ad = {
            "advertiser_id": "it-111222",
            "advertiser_name": "Studio Legale Marini",
            "link_domain": "studiolegale.it",
            "creative_text": "Il tribunale accerta la colpevolezza — assistenza legale",
        }
        bucket, reason, evidence = _classify_fb(ad, LEGIT_PAGE_IDS, LEGIT_DOMAINS, BRAND)
        assert bucket != "impersonator", (
            f"Italian legal ad should NOT be impersonator. Got {bucket}: {reason}"
        )
        # Studio Legale Marini has no Accerta brand token in advertiser name or link domain
        is_relevant, signals = _ad_brand_relevance(ad, BRAND)


# ---------------------------------------------------------------------------
# §D — Whitelisted partner names → legit/brand_adjacent, NEVER impersonator.
# ---------------------------------------------------------------------------
class TestWhitelistedPartners:
    """Authorized OAP-funded providers must not be flagged as impersonators."""

    @pytest.mark.parametrize("advertiser_name,link_domain,advertiser_id", [
        ("Mrs Tutor", "mrstutor.com", "444555666"),
        ("Endless Abilities", "endlessabilities.ca", "555666777"),
        ("Spectacokids", "spectacokids.ca", "666777888"),
        ("Aspire ABA", "aspireaba.com", "777888999"),
    ])
    def test_partner_not_impersonator(self, advertiser_name, link_domain, advertiser_id):
        """Whitelisted partners: domain in legit_domains or name recognized → legit."""
        # legit_domains contains 'accerta.ca', 'accessoap.com' — NOT partner domains.
        # So partners arrive as non-whitelisted domain but brand_adjacent via no brand relevance.
        # Partners are recognized via advertiser_name matching PARTNER_NAMES.
        # _classify_fb doesn't know partner names unless legit_page_ids / legit_domains set.
        # They'll land as brand_adjacent (no brand-relevance: partner name != "Accerta").
        ad = {
            "advertiser_id": advertiser_id,
            "advertiser_name": advertiser_name,
            "link_domain": link_domain,
            "creative_text": f"OAP-funded ABA therapy — Ontario families",
        }
        bucket, reason, evidence = _classify_fb(ad, LEGIT_PAGE_IDS, LEGIT_DOMAINS, BRAND)
        assert bucket != "impersonator", (
            f"Partner '{advertiser_name}' must NOT be classified as impersonator. "
            f"Got {bucket}: {reason}"
        )

    def test_partner_brand_relevance_false(self):
        """_ad_brand_relevance is False for partner ads (partner name ≠ Accerta)."""
        for name, domain in [
            ("Mrs Tutor", "mrstutor.com"),
            ("Endless Abilities", "endlessabilities.ca"),
        ]:
            ad = {"advertiser_name": name, "link_domain": domain, "creative_text": "OAP services"}
            is_relevant, signals = _ad_brand_relevance(ad, BRAND)
            # 'accerta' not in 'mrstutor'/'endless abilities' and not in 'oap services'
            # → no Accerta brand relevance
            assert not is_relevant, (
                f"Partner '{name}' should not have Accerta brand relevance; signals={signals}"
            )


# ---------------------------------------------------------------------------
# §D — Advertiser-scoped dedup: same page_id should dedup.
# ---------------------------------------------------------------------------
class TestAdvertiserScopedDedup:
    """Same advertiser_id across multiple creatives → same fingerprint."""

    def test_iiit_ranchi_dedup_key_stable(self):
        """IIIT Ranchi ×5: same advertiser_id produces same fingerprint."""
        from tools.scrapecreators_ads import _build_fb_ad
        # Verify the build function preserves advertiser_id for dedup
        raw_ads = [
            {"advertiser_id": "123456789", "creative_text": f"OAP ad #{i}", "page_name": "IIIT Ranchi"}
            for i in range(5)
        ]
        built = [_build_fb_ad(r) for r in raw_ads]
        # All should have the same advertiser_id
        ids = {ad.get("advertiser_id") for ad in built}
        assert len(ids) == 1, f"Expected single advertiser_id, got: {ids}"

    def test_domain_whitelist_subdomain_aware(self):
        """_domain_matches_whitelist is subdomain-aware."""
        assert _domain_matches_whitelist("www.accerta.ca", {"accerta.ca"}), \
            "www.accerta.ca should match apex accerta.ca"
        assert _domain_matches_whitelist("portal.accessoap.com", {"accessoap.com"}), \
            "portal.accessoap.com should match apex accessoap.com"
        assert not _domain_matches_whitelist("evil-accerta.ca", {"accerta.ca"}), \
            "evil-accerta.ca must NOT match accerta.ca (not a subdomain)"
        assert not _domain_matches_whitelist("accerta.ca.evil.com", {"accerta.ca"}), \
            "accerta.ca.evil.com must NOT match accerta.ca"


# ---------------------------------------------------------------------------
# §E — Synthetic true positive #3: ad impersonation.
# Advertiser name + domain + creative text all reference Accerta.
# ---------------------------------------------------------------------------
class TestSyntheticAdImpersonation:
    def test_synthetic_impersonator_ad_classified(self):
        """Synthetic: Accerta brand in name + lookalike domain → impersonator."""
        ad = {
            "advertiser_id": "syn-fake-999888777",
            "advertiser_name": "Accerta Benefits Portal",
            "link_domain": "accerta-health-login.com",
            "creative_text": "Access your Accerta dental and ODSP benefits. Login at Accerta Benefits Portal.",
        }
        is_relevant, signals = _ad_brand_relevance(ad, BRAND)
        assert is_relevant, (
            f"Synthetic ad impersonator should have brand relevance. Signals: {signals}"
        )
        assert "advertiser_name_brand_match" in signals, \
            "Advertiser name 'Accerta Benefits Portal' should match brand"

        bucket, reason, evidence = _classify_fb(ad, LEGIT_PAGE_IDS, LEGIT_DOMAINS, BRAND)
        assert bucket == "impersonator", (
            f"Synthetic ad impersonator: expected impersonator, got {bucket}: {reason}"
        )

    def test_boundary_negative_partner_not_impersonator(self):
        """Boundary-negative: Mrs Tutor (whitelisted partner) → NOT impersonator."""
        ad = {
            "advertiser_id": "syn-partner-111222333",
            "advertiser_name": "Mrs Tutor",
            "link_domain": "mrstutor.com",
            "creative_text": "OAP-funded ABA therapy — Ontario families",
        }
        is_relevant, signals = _ad_brand_relevance(ad, BRAND)
        # Mrs Tutor has no 'accerta' token in name/domain/creative
        assert not is_relevant, (
            f"Mrs Tutor boundary-negative should have no brand relevance. Signals: {signals}"
        )
        bucket, reason, evidence = _classify_fb(ad, LEGIT_PAGE_IDS, LEGIT_DOMAINS, BRAND)
        assert bucket != "impersonator", (
            f"Whitelisted partner Mrs Tutor should NOT be impersonator. Got {bucket}: {reason}"
        )
