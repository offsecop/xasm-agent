"""Agent-side Layer-A locks for the registration honesty tri-state (#269).

REG-1/REG-3: `_dns_probe` must distinguish three states so the backend never
flips a previously-registered lookalike to clean on a transient resolver
failure:
  - records present                       → is_registered=True,  unknown=False
  - NXDOMAIN / NOERROR(NODATA)            → is_registered=False, unknown=False
  - SERVFAIL / REFUSED / TIMEOUT only     → is_registered=False, unknown=True

WHOIS-2: `_rdap_created` returns (iso, age_throttled); age_throttled is True
ONLY when a tenant rate-limit (QuotaExceededError) SKIPPED the lookup — so the
backend can HOLD a null-age row for re-sweep rather than fail-closing it to
'stale'. A successful lookup (date or no date) returns age_throttled=False.

Fictitious brand only (sol.test) — the hardcode tripwire stays green.
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import tools.typosquat_detect as td
from tools.typosquat_detect import TyposquatDetectTool

# RDAP/WHOIS enrichment (incl. `_rdap_created` and its `asyncwhois` /
# `checkout_provider` / `QuotaExceededError` symbols) was extracted verbatim into
# the shared enrichment mixin (#1049 T2). Patch there — `_rdap_created` resolves
# those names from the helpers module namespace, not from tools.typosquat_detect.
import lib.typosquat_enrich_helpers as enrich


def _probe(tool, statuses, mx=None):
    """Drive _dns_probe with stubbed A/AAAA/NS rcodes + MX list."""
    a_st, aaaa_st, ns_st = statuses

    async def fake_dig(domain, rrtype):
        st = {'A': a_st, 'AAAA': aaaa_st, 'NS': ns_st}[rrtype]
        recs = [f'rec-{rrtype}'] if st == 'RECORDS' else []
        return recs, ('NOERROR' if st == 'RECORDS' else st)

    async def fake_mx(domain):
        return mx or []

    tool._dig_records = fake_dig
    tool._mx_lookup = fake_mx
    return asyncio.run(tool._dns_probe('sol-login.test'))


class TestDnsProbeTriState:
    def setup_method(self):
        self.tool = TyposquatDetectTool()

    def test_records_present_is_registered(self):
        r = _probe(self.tool, ('RECORDS', 'NONE', 'NONE'))
        assert r['is_registered'] is True
        assert r['registration_unknown'] is False

    def test_nxdomain_definitively_unregistered(self):
        r = _probe(self.tool, ('NXDOMAIN', 'NXDOMAIN', 'NXDOMAIN'))
        assert r['is_registered'] is False
        assert r['registration_unknown'] is False

    def test_noerror_nodata_definitively_unregistered(self):
        r = _probe(self.tool, ('NOERROR', 'NOERROR', 'NOERROR'))
        assert r['is_registered'] is False
        assert r['registration_unknown'] is False

    def test_servfail_only_is_unknown(self):
        r = _probe(self.tool, ('SERVFAIL', 'SERVFAIL', 'SERVFAIL'))
        assert r['is_registered'] is False
        assert r['registration_unknown'] is True

    def test_timeout_only_is_unknown(self):
        r = _probe(self.tool, ('TIMEOUT', 'REFUSED', 'TIMEOUT'))
        assert r['is_registered'] is False
        assert r['registration_unknown'] is True

    def test_mx_present_registers_even_on_servfail_rcodes(self):
        # An MX record proves existence regardless of A/AAAA/NS rcodes.
        r = _probe(self.tool, ('SERVFAIL', 'SERVFAIL', 'SERVFAIL'), mx=['mail.sol.test'])
        assert r['is_registered'] is True
        assert r['registration_unknown'] is False


class TestRdapAgeThrottle:
    def setup_method(self):
        self.tool = TyposquatDetectTool()
        self._orig_aw = enrich.asyncwhois
        self._orig_checkout = enrich.checkout_provider

    def teardown_method(self):
        enrich.asyncwhois = self._orig_aw
        enrich.checkout_provider = self._orig_checkout

    def test_quota_exceeded_returns_age_throttled(self):
        # asyncwhois must look available so we reach the checkout (rate-limit) path.
        enrich.asyncwhois = object()

        async def fake_checkout(provider, requested_units=1):
            raise enrich.QuotaExceededError('RDAP', 60)

        enrich.checkout_provider = fake_checkout
        created, throttled = asyncio.run(self.tool._rdap_created('sol-login.test'))
        assert created is None
        assert throttled is True

    def test_successful_lookup_not_throttled(self):
        class _AW:
            @staticmethod
            async def aio_rdap(domain):
                return ('q', {'created': '2020-01-01T00:00:00Z'})

        enrich.asyncwhois = _AW()

        async def fake_checkout(provider, requested_units=1):
            return {'leaseToken': None}  # no lease → no reconcile

        enrich.checkout_provider = fake_checkout
        created, throttled = asyncio.run(self.tool._rdap_created('sol-login.test'))
        assert created is not None
        assert throttled is False

    def test_asyncwhois_unavailable_is_a_gap_not_a_throttle(self):
        enrich.asyncwhois = None
        created, throttled = asyncio.run(self.tool._rdap_created('sol-login.test'))
        assert created is None
        assert throttled is False  # capability gap, not a rate-limit → backend caps
