"""#1464 — parking / for-sale fingerprint primitive locks (Layer A, gated).

The Layer-B replay enters at the IngestionService seam with the agent's
`parkedFingerprint` / `cloakingDetected` fields ALREADY computed, so the
primitives that produce them — `PARKING_TITLE_RE`, `PARKING_HOSTS`,
`_is_parked_capture`, `_detect_cloaking` — never execute in the gate. These
tests drive them DIRECTLY (agent-primitive coverage seam, #267).

Motivating live-data shape: a lookalike rated HIGH off a phishing-kit
fingerprint whose capture title was "<name>.com is for sale | HugeDomains" —
the original PARKING_TITLE_RE only matched the literal "domain ... for sale"
phrasing and HugeDomains/Efty/Trellian were missing from PARKING_HOSTS.

Fictitious brands (`lumenfield`) on `.test` domains only.
"""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from tools.brand_monitor_screenshot import (  # noqa: E402
    PARKING_HOSTS,
    PARKING_TITLE_RE,
    BrandMonitorScreenshotTool,
)


def _tool() -> BrandMonitorScreenshotTool:
    return BrandMonitorScreenshotTool()


# ---------------------------------------------------------------------------
# PARKING_TITLE_RE — precision: marketplace title shapes must fingerprint
# ---------------------------------------------------------------------------

class TestParkingTitlePatterns:
    def test_hugedomains_style_title_is_parked(self):
        # The exact live-FP shape: "<name>.com is for sale | <vendor>".
        assert PARKING_TITLE_RE.search(
            'lumenfeild.com is for sale | HugeDomains'
        )

    def test_generic_is_for_sale_title_is_parked(self):
        assert PARKING_TITLE_RE.search('lumenfield-shop.test is for sale')

    def test_domain_is_available_title_is_parked(self):
        assert PARKING_TITLE_RE.search(
            'The domain is available for purchase'
        )

    def test_make_an_offer_title_is_parked(self):
        assert PARKING_TITLE_RE.search('lumenfeild.test — make an offer')

    def test_legacy_phrasings_still_match(self):
        for title in (
            'This domain may be for sale',
            'Domain for sale',
            'Buy this domain',
            'parked free courtesy of a registrar',
        ):
            assert PARKING_TITLE_RE.search(title), title

    # #1556 — geo-localized landers: aftermarket vendors serve translated
    # for-sale titles (an observed GoDaddy lander read "<name> está à venda").
    def test_localized_for_sale_titles_are_parked(self):
        for title in (
            'lumenfeild.com está à venda',                    # pt (GoDaddy shape)
            'O domínio pode estar à venda',                   # pt "may be for sale"
            'esta a venda — faça uma oferta',                 # pt, accents dropped
            'lumenfeild.com está en venta',                   # es
            'Este dominio puede estar en venta',              # es
            'lumenfeild.com est à vendre',                    # fr
            'Ce domaine peut être à vendre',                  # fr
            'lumenfeild.de steht zum Verkauf',                # de
            'Diese Domain ist zu verkaufen',                  # de
            'lumenfeild.it è in vendita',                     # it
            "Fai un'offerta per questo dominio",              # it
            'lumenfeild.nl is te koop',                       # nl
            'Doe een bod op dit domein',                      # nl
        ):
            assert PARKING_TITLE_RE.search(title), title

    # Recall guard: ordinary brand/business titles must NOT fingerprint parked.
    # (Note: "<x> is/are for sale" titles DO fingerprint by design — on a
    # lookalike-domain capture that phrasing is overwhelmingly a lander.)
    def test_ordinary_titles_are_not_parked(self):
        for title in (
            'Lumenfield — Secure Client Login',
            'Lumenfield Support Portal',
            'Big summer sale — everything must go',  # "sale" without "for sale"
            'Availability calendar — book now',  # "available" without "domain"
            # #1556 — localized precision guards: bare commerce nouns / benign
            # verb uses in other languages must NOT fingerprint parked.
            'Grande venda de verão — Lumenfield',      # pt "sale" noun alone
            'Ofertas y ventas — tienda Lumenfield',    # es commerce noun
            'Vendita online — Lumenfield store',       # it bare "vendita"
            'Koopgids voor sieraden',                  # nl "koop" inside a word
            'Verkaufsberater Portal',                  # de "verkauf" inside a word
        ):
            assert not PARKING_TITLE_RE.search(title), title


# ---------------------------------------------------------------------------
# PARKING_HOSTS — the missing marketplace vendors are now fingerprinted
# ---------------------------------------------------------------------------

class TestParkingHosts:
    def test_new_marketplace_hosts_present(self):
        for host in ('hugedomains.com', 'efty.com', 'trellian.com', 'above.com'):
            assert host in PARKING_HOSTS, host

    def test_original_hosts_retained(self):
        for host in ('forsale.godaddy.com', 'sedoparking.com', 'bodis.com'):
            assert host in PARKING_HOSTS, host


# ---------------------------------------------------------------------------
# _is_parked_capture — capture-level fingerprint (title OR final-url host)
# ---------------------------------------------------------------------------

class TestIsParkedCapture:
    def test_title_fingerprints_parked(self):
        tool = _tool()
        results = [
            {
                'pageTitle': 'lumenfeild.com is for sale | HugeDomains',
                'finalUrl': 'https://lumenfeild.test/',
            }
        ]
        assert tool._is_parked_capture(results) is True

    def test_redirect_to_marketplace_host_fingerprints_parked(self):
        tool = _tool()
        results = [
            {
                'pageTitle': 'Premium domains',
                'finalUrl': 'https://hugedomains.com/domain/lumenfeild',
            }
        ]
        assert tool._is_parked_capture(results) is True

    def test_live_brand_clone_is_not_parked(self):
        tool = _tool()
        results = [
            {
                'pageTitle': 'Lumenfield — Sign in to your account',
                'finalUrl': 'https://lumenfeild.test/login',
            }
        ]
        assert tool._is_parked_capture(results) is False


# ---------------------------------------------------------------------------
# _detect_cloaking — parked capture suppresses divergence; live divergence kept
# ---------------------------------------------------------------------------

def _capture(ua: str, file_hash: str, title: str, final_url: str):
    return {
        'success': True,
        'filePath': f'/tmp/{ua}.png',
        'userAgent': ua,
        'fileHash': file_hash,
        'pageTitle': title,
        'finalUrl': final_url,
    }


class TestDetectCloakingParkingGate:
    def test_parked_lander_divergence_is_suppressed(self):
        # PRECISION — bot vs human hashes fully disjoint (SHA fallback → 1.0
        # divergence) but the capture is a HugeDomains-style lander: cloaking
        # must be suppressed and the parked fingerprint set.
        tool = _tool()
        results = [
            _capture('desktop', 'aaa1', 'lumenfeild.com is for sale | HugeDomains', 'https://lumenfeild.test/'),
            _capture('bot', 'bbb2', 'lumenfeild.com is for sale | HugeDomains', 'https://lumenfeild.test/'),
        ]
        verdict = tool._detect_cloaking(results)
        assert verdict['parked'] is True
        assert verdict['detected'] is False

    def test_live_divergence_still_reports_cloaking(self):
        # RECALL — same disjoint divergence on a NON-parking capture must still
        # report cloaking (no recall loss from the widened patterns).
        tool = _tool()
        results = [
            _capture('desktop', 'aaa1', 'Lumenfield — Sign in', 'https://lumenfeild.test/login'),
            _capture('bot', 'bbb2', 'Lumenfield — Sign in', 'https://lumenfeild.test/login'),
        ]
        verdict = tool._detect_cloaking(results)
        assert verdict['parked'] is False
        assert verdict['detected'] is True
