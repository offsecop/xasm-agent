"""A3 — origin-ASN annotation of resolved IPv4s (Team Cymru IP→ASN over DNS).

`_asn_lookup` resolves the domain's A records via the shared async resolver,
then maps each IPv4 (capped at 8) to its hosting network through the keyless
Team Cymru TXT service: ``d.c.b.a.origin.asn.cymru.com`` (ASN | prefix |
country | registry | allocated) and ``AS<n>.asn.cymru.com`` (… | AS name).
Two lookalikes parked in the same ASN is a same-operator correlation signal.

No network calls: `resolve_records` is monkeypatched at the helpers-module
seam. Fictitious brands / `.test` domains only.
"""

import asyncio

import lib.typosquat_enrich_helpers as helpers
from lib.typosquat_enrich_helpers import TyposquatEnrichmentMixin


class _Enricher(TyposquatEnrichmentMixin):
    """Bare mixin host — the mixin owns all state its methods need."""


# Fictitious mapping data (TEST-NET-1/2 addresses, documentation ASNs).
ORIGIN_TXT_A = '"64496 | 192.0.2.0/24 | US | arin | 2026-01-01"'
ORIGIN_TXT_B = '"64511 | 198.51.100.0/24 | NL | ripencc | 2026-02-01"'
ASNAME_TXT_A = '"64496 | US | arin | 2026-01-01 | LUMENHOST-EXAMPLE, US"'
ASNAME_TXT_B = '"64511 | NL | ripencc | 2026-02-01 | SOLPARK-EXAMPLE, NL"'


def _fake_resolver(answers):
    """Build a resolve_records double + call log. `answers` maps
    (name, rrtype) → (records, status); unknown names get NXDOMAIN."""
    calls = []

    async def fake(name, rrtype):
        calls.append((name, rrtype.upper()))
        return answers.get((name, rrtype.upper()), ([], 'NXDOMAIN'))

    return fake, calls


class TestParseCymruOrigin:
    def test_parses_all_fields(self):
        parsed = TyposquatEnrichmentMixin._parse_cymru_origin(ORIGIN_TXT_A)
        assert parsed == {
            'asn': 64496,
            'bgp_prefix': '192.0.2.0/24',
            'country': 'US',
            'registry': 'arin',
        }

    def test_multi_origin_asn_field_takes_first(self):
        parsed = TyposquatEnrichmentMixin._parse_cymru_origin(
            '"64496 64511 | 192.0.2.0/24 | US | arin | 2026-01-01"',
        )
        assert parsed['asn'] == 64496

    def test_missing_tail_fields_degrade_to_none(self):
        parsed = TyposquatEnrichmentMixin._parse_cymru_origin('"64496 | 192.0.2.0/24"')
        assert parsed['asn'] == 64496
        assert parsed['bgp_prefix'] == '192.0.2.0/24'
        assert parsed['country'] is None
        assert parsed['registry'] is None

    def test_garbage_returns_none_never_raises(self):
        for garbage in ('', '" "', '"NA | x"', '"not-a-number | p | c | r | d"', None):
            assert TyposquatEnrichmentMixin._parse_cymru_origin(garbage) is None


class TestParseCymruAsname:
    def test_parses_last_field_as_name(self):
        assert (
            TyposquatEnrichmentMixin._parse_cymru_asname(ASNAME_TXT_A)
            == 'LUMENHOST-EXAMPLE, US'
        )

    def test_short_or_garbage_returns_none(self):
        for garbage in ('', '"64496 | US"', None):
            assert TyposquatEnrichmentMixin._parse_cymru_asname(garbage) is None


class TestAsnLookup:
    def setup_method(self):
        self.tool = _Enricher()

    def test_happy_path_two_ips_two_asns(self, monkeypatch):
        fake, calls = _fake_resolver({
            ('lumenfield-login.test', 'A'): (['192.0.2.10', '198.51.100.20'], 'NOERROR'),
            ('10.2.0.192.origin.asn.cymru.com', 'TXT'): ([ORIGIN_TXT_A], 'NOERROR'),
            ('20.100.51.198.origin.asn.cymru.com', 'TXT'): ([ORIGIN_TXT_B], 'NOERROR'),
            ('AS64496.asn.cymru.com', 'TXT'): ([ASNAME_TXT_A], 'NOERROR'),
            ('AS64511.asn.cymru.com', 'TXT'): ([ASNAME_TXT_B], 'NOERROR'),
        })
        monkeypatch.setattr(helpers, 'resolve_records', fake)
        result = asyncio.run(self.tool._asn_lookup('lumenfield-login.test'))
        assert result == [
            {
                'asn': 64496,
                'name': 'LUMENHOST-EXAMPLE, US',
                'bgp_prefix': '192.0.2.0/24',
                'country': 'US',
                'registry': 'arin',
            },
            {
                'asn': 64511,
                'name': 'SOLPARK-EXAMPLE, NL',
                'bgp_prefix': '198.51.100.0/24',
                'country': 'NL',
                'registry': 'ripencc',
            },
        ]

    def test_dedups_by_asn_across_ips(self, monkeypatch):
        # Two IPs in the same netblock → one deduped entry.
        fake, _calls = _fake_resolver({
            ('lumenfield-login.test', 'A'): (['192.0.2.10', '192.0.2.11'], 'NOERROR'),
            ('10.2.0.192.origin.asn.cymru.com', 'TXT'): ([ORIGIN_TXT_A], 'NOERROR'),
            ('11.2.0.192.origin.asn.cymru.com', 'TXT'): ([ORIGIN_TXT_A], 'NOERROR'),
            ('AS64496.asn.cymru.com', 'TXT'): ([ASNAME_TXT_A], 'NOERROR'),
        })
        monkeypatch.setattr(helpers, 'resolve_records', fake)
        result = asyncio.run(self.tool._asn_lookup('lumenfield-login.test'))
        assert len(result) == 1
        assert result[0]['asn'] == 64496

    def test_no_a_records_returns_empty(self, monkeypatch):
        fake, calls = _fake_resolver({
            ('sol-pay.test', 'A'): ([], 'NXDOMAIN'),
        })
        monkeypatch.setattr(helpers, 'resolve_records', fake)
        assert asyncio.run(self.tool._asn_lookup('sol-pay.test')) == []
        # No Cymru fan-out when nothing resolved.
        assert calls == [('sol-pay.test', 'A')]

    def test_origin_failure_skips_that_ip_only(self, monkeypatch):
        # First IP's origin lookup times out; second succeeds.
        fake, _calls = _fake_resolver({
            ('lumenfield-login.test', 'A'): (['192.0.2.10', '198.51.100.20'], 'NOERROR'),
            ('10.2.0.192.origin.asn.cymru.com', 'TXT'): ([], 'TIMEOUT'),
            ('20.100.51.198.origin.asn.cymru.com', 'TXT'): ([ORIGIN_TXT_B], 'NOERROR'),
            ('AS64511.asn.cymru.com', 'TXT'): ([ASNAME_TXT_B], 'NOERROR'),
        })
        monkeypatch.setattr(helpers, 'resolve_records', fake)
        result = asyncio.run(self.tool._asn_lookup('lumenfield-login.test'))
        assert [r['asn'] for r in result] == [64511]

    def test_asname_failure_keeps_entry_with_none_name(self, monkeypatch):
        fake, _calls = _fake_resolver({
            ('lumenfield-login.test', 'A'): (['192.0.2.10'], 'NOERROR'),
            ('10.2.0.192.origin.asn.cymru.com', 'TXT'): ([ORIGIN_TXT_A], 'NOERROR'),
            # AS64496.asn.cymru.com absent → NXDOMAIN → name None.
        })
        monkeypatch.setattr(helpers, 'resolve_records', fake)
        result = asyncio.run(self.tool._asn_lookup('lumenfield-login.test'))
        assert result == [{
            'asn': 64496,
            'name': None,
            'bgp_prefix': '192.0.2.0/24',
            'country': 'US',
            'registry': 'arin',
        }]

    def test_caps_at_first_eight_ips(self, monkeypatch):
        ips = [f'192.0.2.{i}' for i in range(1, 13)]  # 12 resolved addresses
        answers = {('lumenfield-login.test', 'A'): (ips, 'NOERROR')}
        for i in range(1, 13):
            answers[(f'{i}.2.0.192.origin.asn.cymru.com', 'TXT')] = (
                [ORIGIN_TXT_A], 'NOERROR',
            )
        answers[('AS64496.asn.cymru.com', 'TXT')] = ([ASNAME_TXT_A], 'NOERROR')
        fake, calls = _fake_resolver(answers)
        monkeypatch.setattr(helpers, 'resolve_records', fake)
        asyncio.run(self.tool._asn_lookup('lumenfield-login.test'))
        origin_calls = [c for c in calls if c[0].endswith('.origin.asn.cymru.com')]
        assert len(origin_calls) == 8

    def test_non_ipv4_records_are_ignored(self, monkeypatch):
        fake, calls = _fake_resolver({
            ('lumenfield-login.test', 'A'): (['2001:db8::1', 'garbage', '999.1.1.1'], 'NOERROR'),
        })
        monkeypatch.setattr(helpers, 'resolve_records', fake)
        assert asyncio.run(self.tool._asn_lookup('lumenfield-login.test')) == []
        assert calls == [('lumenfield-login.test', 'A')]

    def test_resolver_exception_fails_soft_to_empty(self, monkeypatch):
        async def boom(name, rrtype):
            raise RuntimeError('resolver blew up')

        monkeypatch.setattr(helpers, 'resolve_records', boom)
        assert asyncio.run(self.tool._asn_lookup('lumenfield-login.test')) == []
