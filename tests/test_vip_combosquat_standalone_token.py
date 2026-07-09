"""P0-4 — VIP-exposure combosquat: STANDALONE-token, never substring.

`_classify_serp_host` hard-emitted COMBOSQUAT / IMPERSONATION / HIGH /
riskScore 78 on a raw SUBSTRING match of a brand token inside the registrable
label — strictly weaker than the platform's own combosquat rule
(typosquat_detect.py requires the brand as a standalone token of a tokenized
SLD, brand length >= 4). The fix mirrors that semantics: split the label on
non-alphanumeric + camelCase boundaries and require an EXACT token match
against a brand token of length >= 4.

FICTITIOUS brands only (lumenfield / sol + `.test`) per the synthetic-data
principle — the real-world FP shape (a company whose name embeds the brand as
a glued substring, the "<brand>wealth" class) is reproduced synthetically.
"""
from tools.brand_monitor_vip_exposure import (
    _classify_serp_host,
    _label_has_standalone_brand_token,
    _label_tokens,
)

BRAND_TOKENS = ['lumenfield']


def classify(url, brand_tokens=None):
    return _classify_serp_host(
        url,
        owned_domains=['lumenfield.test'],
        typosquat_domains=['lumenf1eld.test'],
        brand_tokens=brand_tokens if brand_tokens is not None else BRAND_TOKENS,
        full_name='Jane Synth',
    )


class TestCombosquatPrecision:
    def test_glued_substring_label_does_not_emit_high(self):
        # The "<brand>wealth" FP class: brand token glued into an unrelated
        # legal-entity name with no token boundary. Must NOT hard-emit
        # IMPERSONATION/HIGH — falls through to the content classifier (None).
        assert classify('https://lumenfieldwealth.test/about') is None

    def test_brand_inside_longer_word_does_not_emit_high(self):
        assert classify('https://alumenfielder.test/') is None

    def test_short_brand_token_never_matches(self):
        # Brand tokens shorter than 4 chars are excluded from the standalone
        # rule (typosquat_detect.py parity) — 'sol' must not flag 'sol-support'.
        assert classify('https://sol-support.test/', brand_tokens=['sol']) is None

    def test_owned_domain_still_suppressed(self):
        got = classify('https://lumenfield.test/team')
        assert got == {'action': 'suppress', 'reason': 'owned'}

    def test_tracked_typosquat_still_suppressed(self):
        got = classify('https://lumenf1eld.test/login')
        assert got == {'action': 'suppress', 'reason': 'known_typosquat'}


class TestCombosquatRecall:
    def test_hyphenated_standalone_token_flags_high(self):
        got = classify('https://lumenfield-login.test/secure')
        assert got is not None and got['action'] == 'flag'
        assert got['category'] == 'COMBOSQUAT'
        assert got['exposureType'] == 'IMPERSONATION'
        # Genuine hits keep the original band untouched.
        assert got['severity'] == 'HIGH'
        assert got['riskScore'] == 78
        assert got['confidence'] == 0.7

    def test_exact_brand_label_on_other_tld_still_flags(self):
        # Single-token label that IS the brand (TLD swap, not owned/tracked)
        # remains a standalone-token match — recall preserved.
        got = classify('https://lumenfield.example/')
        assert got is not None and got['action'] == 'flag'
        assert got['category'] == 'COMBOSQUAT'


class TestTokenizerHelpers:
    def test_label_tokens_non_alnum_boundaries(self):
        assert _label_tokens('lumenfield-secure_login') == [
            'lumenfield', 'secure', 'login',
        ]

    def test_label_tokens_camelcase_boundary(self):
        assert _label_tokens('lumenfieldSecure') == ['lumenfield', 'Secure']

    def test_standalone_requires_exact_token(self):
        assert _label_has_standalone_brand_token('lumenfield-login', BRAND_TOKENS)
        assert not _label_has_standalone_brand_token('lumenfieldwealth', BRAND_TOKENS)

    def test_standalone_requires_min_length_4(self):
        assert not _label_has_standalone_brand_token('sol-support', ['sol'])
        assert _label_has_standalone_brand_token('sole-support', ['sole'])
