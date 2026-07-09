"""Agent-side Layer-A locks for the threat-intel feed-leg honesty (#270).

FEED-2/HONESTY-1/PASTEBIN-1: a non-200 from URLhaus / ThreatFox / Pastebin must
NOT read as 'clean'. The legs send the mandatory abuse.ch `Auth-Key` header and
record a per-source sweep status (swept / unswept_needkey / error_*) so an empty
result list from a 401/429/5xx is distinguishable from a genuine no-listing.

Drives the REAL _query_urlhaus / _query_threatfox / _query_pastebin against a
mocked aiohttp session. Fictitious brand only (sol.test).
"""

import asyncio
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import tools.darkweb_monitor as td
from tools.darkweb_monitor import DarkWebMonitorTool

DOMAIN = 'sol.test'


class _FakeResp:
    def __init__(self, status, payload=None):
        self.status = status
        self._payload = payload if payload is not None else {}

    async def json(self):
        return self._payload

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


class _FakeSession:
    """Records post/get calls so the Auth-Key header can be asserted."""

    def __init__(self, resp):
        self._resp = resp
        self.calls = []

    def post(self, url, **kwargs):
        self.calls.append(('post', url, kwargs))
        return self._resp

    def get(self, url, **kwargs):
        self.calls.append(('get', url, kwargs))
        return self._resp


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture
def tool():
    t = DarkWebMonitorTool()
    t._source_status = {}
    return t


@pytest.fixture(autouse=True)
def _clear_key(monkeypatch):
    monkeypatch.delenv('ABUSECH_KEY', raising=False)


# --- URLhaus -----------------------------------------------------------------

class TestUrlhaus:
    def test_missing_key_is_unswept_not_clean(self, tool):
        sess = _FakeSession(_FakeResp(200, {'urls': []}))
        out = _run(tool._query_urlhaus(sess, DOMAIN))
        assert out == []
        assert tool._source_status['urlhaus'] == 'unswept_needkey'
        assert sess.calls == []  # no key → no pointless 401 call

    def test_auth_key_header_sent_when_key_set(self, tool, monkeypatch):
        monkeypatch.setenv('ABUSECH_KEY', 'test-key-123')
        sess = _FakeSession(_FakeResp(200, {'urls': []}))
        _run(tool._query_urlhaus(sess, DOMAIN))
        assert sess.calls[0][2]['headers']['Auth-Key'] == 'test-key-123'
        assert tool._source_status['urlhaus'] == 'swept'

    def test_401_is_needkey_not_clean(self, tool, monkeypatch):
        monkeypatch.setenv('ABUSECH_KEY', 'k')
        out = _run(tool._query_urlhaus(_FakeSession(_FakeResp(401)), DOMAIN))
        assert out == []
        assert tool._source_status['urlhaus'] == 'unswept_needkey'

    def test_5xx_is_error_not_clean(self, tool, monkeypatch):
        monkeypatch.setenv('ABUSECH_KEY', 'k')
        out = _run(tool._query_urlhaus(_FakeSession(_FakeResp(503)), DOMAIN))
        assert out == []
        assert tool._source_status['urlhaus'] == 'error_http_503'


# --- ThreatFox ---------------------------------------------------------------

class TestThreatFox:
    def test_missing_key_is_unswept(self, tool):
        out = _run(tool._query_threatfox(_FakeSession(_FakeResp(200, {})), DOMAIN))
        assert out == []
        assert tool._source_status['threatfox'] == 'unswept_needkey'

    def test_auth_key_sent_and_swept(self, tool, monkeypatch):
        monkeypatch.setenv('ABUSECH_KEY', 'tf-key')
        sess = _FakeSession(_FakeResp(200, {'query_status': 'ok', 'data': []}))
        _run(tool._query_threatfox(sess, DOMAIN))
        assert sess.calls[0][2]['headers']['Auth-Key'] == 'tf-key'
        assert tool._source_status['threatfox'] == 'swept'

    def test_429_is_error_not_clean(self, tool, monkeypatch):
        monkeypatch.setenv('ABUSECH_KEY', 'k')
        out = _run(tool._query_threatfox(_FakeSession(_FakeResp(429)), DOMAIN))
        assert out == []
        assert tool._source_status['threatfox'] == 'error_http_429'


# --- Pastebin ----------------------------------------------------------------

class TestPastebin:
    def test_200_is_swept(self, tool):
        out = _run(tool._query_pastebin(_FakeSession(_FakeResp(200, [])), DOMAIN, []))
        assert out == []
        assert tool._source_status['pastebin'] == 'swept'

    def test_403_is_unswept_needkey(self, tool):
        out = _run(tool._query_pastebin(_FakeSession(_FakeResp(403)), DOMAIN, []))
        assert out == []
        assert tool._source_status['pastebin'] == 'unswept_needkey'

    def test_5xx_is_error_not_clean(self, tool):
        out = _run(tool._query_pastebin(_FakeSession(_FakeResp(503)), DOMAIN, []))
        assert out == []
        assert tool._source_status['pastebin'] == 'error_http_503'


# --- HIBP domain scoping (HIBP-1) --------------------------------------------

class TestHibpScoping:
    # The free /breaches catalog: an UNRELATED breach whose name merely contains
    # the brand label, and a GENUINE breach for the monitored apex.
    CATALOG = [
        {'Name': 'SolarWinds', 'Domain': 'solarwinds.com', 'Title': 'SolarWinds',
         'DataClasses': ['Passwords'], 'PwnCount': 1000, 'BreachDate': '2020-12-01'},
        {'Name': 'SolTest', 'Domain': 'sol.test', 'Title': 'Sol Test',
         'DataClasses': ['Passwords'], 'PwnCount': 5000, 'BreachDate': '2024-01-01'},
    ]

    def test_substring_breach_name_does_not_fire_cross_brand(self, tool):
        out = _run(tool._query_hibp_breaches(_FakeSession(_FakeResp(200, self.CATALOG)), DOMAIN))
        domains = {r['metadata']['breachName'] for r in out}
        # 'sol' must NOT match 'SolarWinds' (cross-brand substring FP).
        assert 'SolarWinds' not in domains
        # The exact apex match DOES fire (recall).
        assert 'SolTest' in domains
        assert len(out) == 1


# --- LeakCheck 429 honesty (LEAKCHECK-1) -------------------------------------

class TestLeakCheckRateLimit:
    def test_429_records_unqueried_prefixes_as_unswept(self, tool):
        out = _run(tool._query_leakcheck(_FakeSession(_FakeResp(429)), DOMAIN))
        assert out == []
        status = tool._source_status['leakcheck']
        assert status.startswith('unswept_ratelimited:')
        # The un-queried prefix tail is recorded (not silently dropped).
        assert 'info' in status  # first prefix; rate-limited before it returned data


# --- #889: owned-domain credential/breach sweep ------------------------------

class _RouteBySubstringSession:
    """Returns a per-call response chosen by matching a substring in the URL.

    Lets the LeakCheck multi-domain sweep return a 429 only for a specific
    owned domain while every other probe returns a clean 200.
    """

    def __init__(self, default_resp, routes=None):
        self._default = default_resp
        self._routes = routes or []  # list[(substr, _FakeResp)]
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append(('get', url, kwargs))
        for sub, resp in self._routes:
            if sub in url:
                return resp
        return self._default


@pytest.fixture
def _no_sleep(monkeypatch):
    async def _noop(*a, **k):
        return None

    monkeypatch.setattr(td.asyncio, 'sleep', _noop)


class TestHibpOwnedDomains889:
    CATALOG = [
        {'Name': 'ApexBreach', 'Domain': 'sol.test', 'Title': 'Apex',
         'DataClasses': ['Passwords'], 'PwnCount': 100, 'BreachDate': '2024-01-01'},
        {'Name': 'OwnedBreach', 'Domain': 'owned-a.test', 'Title': 'Owned',
         'DataClasses': ['Email addresses'], 'PwnCount': 200, 'BreachDate': '2024-02-01'},
        {'Name': 'Unrelated', 'Domain': 'someoneelse.test', 'Title': 'Nope',
         'DataClasses': ['Passwords'], 'PwnCount': 300, 'BreachDate': '2024-03-01'},
    ]

    def test_owned_domain_breach_matched_via_extra_domains(self, tool):
        out = _run(tool._query_hibp_breaches(
            _FakeSession(_FakeResp(200, self.CATALOG)), DOMAIN,
            None, ['www.owned-a.test'],  # www-prefixed → apex-normalised
        ))
        by_domain = {r['metadata']['matchedDomain']: r for r in out}
        # Both the apex and the owned domain fire; the unrelated one never does.
        assert set(by_domain) == {'sol.test', 'owned-a.test'}
        assert by_domain['owned-a.test']['matchedKeywords'] == ['owned-a.test']

    def test_apex_only_when_no_extra_domains(self, tool):
        out = _run(tool._query_hibp_breaches(
            _FakeSession(_FakeResp(200, self.CATALOG)), DOMAIN,
        ))
        assert {r['metadata']['matchedDomain'] for r in out} == {'sol.test'}


class TestLeakCheckOwnedDomains889:
    def test_sweeps_apex_plus_owned_cohort_and_records_swept_list(self, tool, _no_sleep):
        # Every probe returns a clean 200 (no hits): assert the swept cohort is
        # recorded honestly and that owned-domain emails were actually probed.
        sess = _RouteBySubstringSession(_FakeResp(200, {'success': True, 'found': 0}))
        out = _run(tool._query_leakcheck(sess, DOMAIN, None, ['owned-a.test', 'WWW.owned-b.test']))
        assert out == []
        assert tool._source_status['leakcheck'] == 'swept:sol.test,owned-a.test,owned-b.test'
        # 3 domains × 10 prefixes = 30 probes; owned domains really were queried.
        probed = ' '.join(c[1] for c in sess.calls)
        assert 'admin@owned-a.test' in probed
        assert 'admin@owned-b.test' in probed
        assert len(sess.calls) == 30

    def test_dedupes_apex_and_www_twin(self, tool, _no_sleep):
        sess = _RouteBySubstringSession(_FakeResp(200, {'success': True, 'found': 0}))
        _run(tool._query_leakcheck(sess, DOMAIN, None, ['www.sol.test', 'sol.test']))
        # apex + its www twin + a plain dup collapse to a single domain sweep.
        assert tool._source_status['leakcheck'] == 'swept:sol.test'
        assert len(sess.calls) == 10

    def test_per_prefix_error_is_not_clobbered_by_terminal_swept(self, tool, _no_sleep):
        # A transient error on ONE prefix of a non-last domain must NOT read as a
        # clean 'swept' after later domains sweep fine (COV-6/LEAKCHECK-1 honesty).
        class _RaiseOnce:
            def __init__(self):
                self.raised = False

            def get(self, url, **kwargs):
                if 'admin@owned-a.test' in url and not self.raised:
                    self.raised = True
                    raise RuntimeError('boom')
                return _FakeResp(200, {'success': True, 'found': 0})

        out = _run(tool._query_leakcheck(_RaiseOnce(), DOMAIN, None, ['owned-a.test', 'owned-b.test']))
        assert out == []
        status = tool._source_status['leakcheck']
        # Terminal status reflects the partial error, not a bare swept.
        assert status.startswith('partial_error:')
        assert 'errors=owned-a.test:admin' in status
        # The errored domain is kept OUT of the swept list; clean domains are in.
        assert 'swept=sol.test,owned-b.test' in status

    def test_429_mid_cohort_records_swept_and_pending(self, tool, _no_sleep):
        # apex sweeps clean; the FIRST probe on owned-b returns 429.
        sess = _RouteBySubstringSession(
            _FakeResp(200, {'success': True, 'found': 0}),
            routes=[('@owned-b.test', _FakeResp(429))],
        )
        out = _run(tool._query_leakcheck(sess, DOMAIN, None, ['owned-a.test', 'owned-b.test']))
        assert out == []
        status = tool._source_status['leakcheck']
        # sol.test + owned-a.test were fully swept; owned-b.test was cut off.
        assert status.startswith('unswept_ratelimited:')
        assert 'swept=sol.test,owned-a.test' in status
        assert 'pending=owned-b.test:' in status


# --- GitHub EXPOSED_SECRET entropy gate (GHSECRET-1) -------------------------

class _RouterSession:
    """Returns a different response per URL substring (repo vs code search)."""

    def __init__(self, routes):
        self.routes = routes  # list[(substr, _FakeResp)]

    def get(self, url, **kwargs):
        for sub, resp in self.routes:
            if sub in url:
                return resp
        return _FakeResp(200, {'items': []})


def _code_resp(fragment):
    return _FakeResp(200, {'items': [{
        'sha': 'abc123def4567890',
        'html_url': 'https://github.com/acme/repo/blob/main/x.py',
        'path': 'x.py',
        'repository': {'full_name': 'acme/repo', 'id': 1},
        'text_matches': [{'fragment': fragment}],
    }]})


class TestGithubSecretGate:
    def test_fragment_has_secret_pure(self, tool):
        assert tool._fragment_has_secret('def reset_password(user): pass') is False
        assert tool._fragment_has_secret('the user password reset flow') is False
        assert tool._fragment_has_secret('AWS_SECRET=wJalrXUtnFEMIK7MDENGbPxRfiCYz') is True
        assert tool._fragment_has_secret('ghp_' + 'a' * 36) is True

    def test_long_identifier_is_not_a_secret(self, tool):
        # FP guard: long snake_case/camelCase identifiers reach ~3.9 entropy but
        # use few distinct chars — must NOT trip the entropy gate.
        assert tool._fragment_has_secret('value = get_password_from_environment()') is False
        assert tool._fragment_has_secret('DEFAULT_REFRESH_TOKEN_EXPIRY_SECONDS = 3600') is False
        assert tool._fragment_has_secret('const resetPasswordTokenHandler = require("x")') is False

    def test_function_call_assignment_is_not_a_secret(self, tool):
        # FP guard: the generic key=value pattern requires a QUOTED literal, so a
        # function-call / env-var value does not fire.
        assert tool._fragment_has_secret('password = get_password_from_env()') is False
        assert tool._fragment_has_secret("token = request.headers.get('Authorization')") is False
        # A genuine quoted hardcoded credential DOES fire.
        assert tool._fragment_has_secret('api_key = "A1b2C3d4E5f6G7h8"') is True

    def _run_github(self, tool, monkeypatch, fragment):
        monkeypatch.setenv('GITHUB_TOKEN', 'tok')

        async def no_sleep(*a, **k):
            return None

        async def no_lease(*a, **k):
            raise td.IntegrationCredentialsError('no integration')

        monkeypatch.setattr(td.asyncio, 'sleep', no_sleep)
        monkeypatch.setattr(td, 'checkout_provider', no_lease)
        sess = _RouterSession([
            ('search/repositories', _FakeResp(200, {'items': []})),
            ('search/code', _code_resp(fragment)),
        ])
        # #879 — EMPTY patterns is the PRODUCTION dispatch shape; the gate
        # falls back to the domain-derived terms, so brand-in-content hits are kept.
        return _run(tool._query_github(sess, DOMAIN, []))

    def test_keyword_without_secret_is_not_high_exposed_secret(self, tool, monkeypatch):
        out = self._run_github(
            tool, monkeypatch,
            'def reset_password(user): # password reset flow for sol.test',
        )
        # No HIGH EXPOSED_SECRET for a bare keyword co-occurrence.
        assert not any(r['matchType'] == 'EXPOSED_SECRET' and r['severity'] == 'HIGH' for r in out)
        # Demoted to a LOW brand-mention instead.
        assert any(r['matchType'] == 'BRAND_MENTION' and r['severity'] == 'LOW' for r in out)

    def test_real_secret_emits_high(self, tool, monkeypatch):
        out = self._run_github(
            tool, monkeypatch,
            # brand token present (a real brand code-search hit) + a real secret.
            'sol.test config: AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY',
        )
        assert any(r['matchType'] == 'EXPOSED_SECRET' and r['severity'] == 'HIGH' for r in out)

    def test_absent_text_matches_demotes_and_flags_unavailable(self, tool, monkeypatch):
        monkeypatch.setenv('GITHUB_TOKEN', 'tok')

        async def no_sleep(*a, **k):
            return None

        async def no_lease(*a, **k):
            raise td.IntegrationCredentialsError('no integration')

        monkeypatch.setattr(td.asyncio, 'sleep', no_sleep)
        monkeypatch.setattr(td, 'checkout_provider', no_lease)
        # Code item with NO text_matches (API didn't surface a fragment). The
        # FULL domain lives in the repo name (a real brand code-search hit — for
        # the short brand `sol`, the 3-char label is dropped by the #348
        # specificity guard, so only the full `sol.test` is a valid gate term), so
        # the #879 keep/drop gate passes and the absent-fragment demote is under test.
        code = _FakeResp(200, {'items': [{
            'sha': 'deadbeefcafe0001', 'html_url': 'https://github.com/acme/sol.test-config/blob/main/y',
            'path': 'y', 'repository': {'full_name': 'acme/sol.test-config', 'id': 2},
        }]})
        sess = _RouterSession([
            ('search/repositories', _FakeResp(200, {'items': []})),
            ('search/code', code),
        ])
        out = _run(tool._query_github(sess, DOMAIN, []))  # #879 production empty-patterns path
        secret_hits = [r for r in out if r['source'] == 'CODE_REPOSITORY' and r['metadata'].get('path') == 'y']
        assert secret_hits, 'expected the code hit to be emitted'
        for r in secret_hits:
            assert r['matchType'] == 'BRAND_MENTION'  # demoted (no fragment to verify)
            assert r['metadata']['fragmentAvailable'] is False
