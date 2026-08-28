"""Agent-side Layer-A locks for the #1487 no-clone public-code coverage widen:

  * the serper `site:`-dork secret-hunting leg (`_query_serper_dorks`), and
  * the GitLab metadata→blob (code-content) upgrade (`_query_gitlab`).

Both reuse the SHARED secret gate (`_apply_secret_gate` → `_match_secret` →
`_build_exposed_secret_evidence`); these locks assert the load-bearing
INVARIANTS: dork construction (correct `site:` pinning, `filetype:` dorks on our
paid tier, budget bound), BODY-gating (a secret in the fetched page body is
flagged; the SAME high-entropy string present ONLY in the SERP snippet / a URL
fragment is NOT — the proven 5/5-snippet-FP guard), the raw-secret-never-stored
invariant, and GitLab's honest degrade with no token.

EVERY credential literal here is FABRICATED and authenticates to nothing — these
are detection fixtures, not secrets. Only the fictitious brand `lumenfield` /
`lumenfield.test` appears (synthetic-data principle: no real client brand string
in agent tests).
"""

import asyncio
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import tools.darkweb_monitor as td
from tools.darkweb_monitor import DarkWebMonitorTool

DOMAIN = 'lumenfield.test'
PATTERNS = [{'pattern': 'lumenfield', 'name': 'Lumenfield', 'isRegex': False}]

# A fabricated AWS-style access key id (regex family aws-access-key-id: AKIA +
# 16 upper/digit chars). Inert — detection fixture only.
FAKE_SECRET = 'AKIAEXAMPLE0000FAKEK'
# A high-entropy opaque token used ONLY in a SERP snippet / URL fragment to prove
# the snippet is never gated (the FP guard).
SNIPPET_ENTROPY_FRAGMENT = 'aB3xY9zQ7wE2rT5uI8oP1kLmNvCxZ0jH4'


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture
def tool():
    t = DarkWebMonitorTool()
    t._source_status = {}
    t._dork_coverage = []
    return t


def _patterns(tool):
    return tool._normalize_patterns([], PATTERNS)


# ── _FakeResp / _FakeSession (mirror test_darkweb_feed_legs) ──────────────────
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


class _CaptureSession:
    """Records every get() so query params / headers can be asserted."""

    def __init__(self, resp):
        self._resp = resp
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append(('get', url, kwargs))
        return self._resp


# =============================================================================
# B. serper `site:`-dork leg — construction
# =============================================================================
class TestSerperDorkConstruction:
    def test_queries_pin_site_and_quote_brand(self, tool):
        qs = tool._build_serper_dork_queries(['lumenfield'])
        assert qs, 'expected dork queries for a specific brand'
        for host, query in qs:
            assert query.startswith(f'site:{host} '), f'query not site-pinned: {query}'
            assert '"lumenfield"' in query, f'brand not exact-quoted: {query}'

    def test_filetype_dorks_are_constructed(self, tool):
        # Paid tier — `filetype:` IS supported and is high-signal; the leg MUST
        # build filetype dorks (this replaces the old "no filetype:" guard).
        joined = ' '.join(q for (_h, q) in tool._build_serper_dork_queries(['lumenfield']))
        assert 'filetype:' in joined, 'no filetype: dork constructed'
        # at least one of the secret-bearing file types is targeted
        assert any(f'filetype:{ft}' in joined for ft in tool._SERPER_DORK_FILETYPES)

    def test_keyword_dorks_are_constructed(self, tool):
        joined = ' '.join(q for (_h, q) in tool._build_serper_dork_queries(['lumenfield']))
        assert any(kw in joined for kw in tool._SERPER_DORK_KEYWORDS), \
            'no credential keyword dork constructed'

    def test_dark_hosts_are_covered(self, tool):
        hosts = {h for (h, _q) in tool._build_serper_dork_queries(['lumenfield'])}
        # the leg exists to reach hosts our native legs miss
        for expect in ('bitbucket.org', 'sourceforge.net', 'gitlab.com',
                       'codeberg.org', 'pastebin.com'):
            assert expect in hosts, f'dark host not dorked: {expect}'

    def test_empty_terms_yields_no_queries(self, tool):
        assert tool._build_serper_dork_queries([]) == []


# =============================================================================
# B. serper leg — BUDGET bound (paid tier: every query costs)
# =============================================================================
class TestSerperDorkBudget:
    def test_query_count_capped(self, tool, monkeypatch):
        calls = {'n': 0}

        async def _fake_dispatch(query, page, session):
            calls['n'] += 1
            return {'hits': [], 'unswept': False}

        monkeypatch.setattr(td, 'dispatch_serper', _fake_dispatch)
        _run(tool._query_serper_dorks(_CaptureSession(None), DOMAIN, _patterns(tool)))
        assert calls['n'] <= tool._SERPER_DORK_MAX_QUERIES, \
            f'issued {calls["n"]} queries; budget is {tool._SERPER_DORK_MAX_QUERIES}'
        assert calls['n'] >= 1, 'leg issued no queries at all'


# =============================================================================
# B. serper leg — BODY-gating (the core FP fix)
# =============================================================================
class TestSerperBodyGating:
    def _wire(self, tool, monkeypatch, hits, bodies):
        """dispatch_serper → the given hits (once, then empty); _fetch_dork_body
        → the canned `bodies` map keyed by url."""
        state = {'served': False}

        async def _fake_dispatch(query, page, session):
            if state['served']:
                return {'hits': [], 'unswept': False}
            state['served'] = True
            return {'hits': hits, 'unswept': False}

        async def _fake_body(session, url):
            return bodies.get(url, '')

        monkeypatch.setattr(td, 'dispatch_serper', _fake_dispatch)
        monkeypatch.setattr(tool, '_fetch_dork_body', _fake_body)

    def test_secret_in_body_is_flagged_exposed_secret(self, tool, monkeypatch):
        url = 'https://pastebin.com/raw/ABC123'
        hits = [{'url': url, 'title': 'lumenfield config', 'snippet': 'nothing here'}]
        bodies = {url: f'lumenfield prod config\nAWS_ACCESS_KEY_ID={FAKE_SECRET}\n'}
        self._wire(tool, monkeypatch, hits, bodies)

        out = _run(tool._query_serper_dorks(_CaptureSession(None), DOMAIN, _patterns(tool)))
        assert len(out) == 1, 'body-secret hit not emitted'
        row = out[0]
        assert row['matchType'] == 'EXPOSED_SECRET'
        assert row['severity'] == 'HIGH'
        ev = row['metadata']['exposedSecret']
        assert ev['detectorName'] == 'aws-access-key-id'
        # redacted preview present, masked, and NOT the raw value
        assert '•' in ev['maskedPreview']
        assert ev['maskedPreview'] != FAKE_SECRET

    def test_raw_secret_never_stored(self, tool, monkeypatch):
        url = 'https://bitbucket.org/acme/x/raw/env'
        hits = [{'url': url, 'title': 'lumenfield', 'snippet': 's'}]
        bodies = {url: f'lumenfield\nAWS_ACCESS_KEY_ID={FAKE_SECRET}'}
        self._wire(tool, monkeypatch, hits, bodies)
        out = _run(tool._query_serper_dorks(_CaptureSession(None), DOMAIN, _patterns(tool)))
        assert out, 'expected a hit'
        # The raw secret must appear in NONE of the emitted row (snippet/title/meta).
        assert FAKE_SECRET not in json.dumps(out[0]), 'raw secret leaked into emitted row'

    def test_snippet_only_high_entropy_is_not_flagged(self, tool, monkeypatch):
        # FP GUARD: the high-entropy token is present ONLY in the SERP snippet and
        # the result URL fragment — the fetched BODY has no secret. Because the leg
        # gates the BODY (never the snippet), NOTHING is flagged.
        url = f'https://sourceforge.net/p/x/#{SNIPPET_ENTROPY_FRAGMENT}'
        hits = [{
            'url': url,
            'title': 'lumenfield mirror',
            'snippet': f'download token {SNIPPET_ENTROPY_FRAGMENT} lumenfield',
        }]
        # Body is a benign brand page — no credential-shaped/high-entropy token.
        bodies = {url: '<html>lumenfield open-source mirror. see the readme.</html>'}
        fetched: dict = {'urls': []}

        async def _fake_dispatch(query, page, session):
            # serve once
            if fetched.get('served'):
                return {'hits': [], 'unswept': False}
            fetched['served'] = True
            return {'hits': hits, 'unswept': False}

        async def _fake_body(session, u):
            fetched['urls'].append(u)
            return bodies.get(u, '')

        monkeypatch.setattr(td, 'dispatch_serper', _fake_dispatch)
        monkeypatch.setattr(tool, '_fetch_dork_body', _fake_body)

        out = _run(tool._query_serper_dorks(_CaptureSession(None), DOMAIN, _patterns(tool)))
        assert out == [], 'snippet-only high-entropy fragment must NOT be flagged'
        # prove the leg actually fetched the body (did not gate the snippet)
        assert url in fetched['urls'], 'body was never fetched — snippet-gating regression'


# =============================================================================
# B. serper leg — honest status
# =============================================================================
class TestSerperStatus:
    def test_no_provider_is_unswept_not_clean(self, tool, monkeypatch):
        async def _fake_dispatch(query, page, session):
            raise td.SerpNotConfigured('no integration')

        monkeypatch.setattr(td, 'dispatch_serper', _fake_dispatch)
        out = _run(tool._query_serper_dorks(_CaptureSession(None), DOMAIN, _patterns(tool)))
        assert out == []
        assert tool._source_status['serper_dorks'] == 'unswept_no_provider'

    def test_broken_provider_is_error_not_clean(self, tool, monkeypatch):
        async def _fake_dispatch(query, page, session):
            raise td.SerpSweepFailed('serp_http_429')

        monkeypatch.setattr(td, 'dispatch_serper', _fake_dispatch)
        out = _run(tool._query_serper_dorks(_CaptureSession(None), DOMAIN, _patterns(tool)))
        assert out == []
        assert tool._source_status['serper_dorks'].startswith('error')

    def test_swept_when_queries_run(self, tool, monkeypatch):
        async def _fake_dispatch(query, page, session):
            return {'hits': [], 'unswept': False}

        monkeypatch.setattr(td, 'dispatch_serper', _fake_dispatch)
        _run(tool._query_serper_dorks(_CaptureSession(None), DOMAIN, _patterns(tool)))
        assert tool._source_status['serper_dorks'] == 'swept'


# =============================================================================
# A. GitLab metadata → blob (code-content) upgrade
# =============================================================================
class TestGitLabBlobs:
    def test_no_token_degrades_honestly(self, tool, monkeypatch):
        monkeypatch.delenv('GITLAB_TOKEN', raising=False)
        out = _run(tool._query_gitlab(_CaptureSession(None), DOMAIN, _patterns(tool)))
        assert out == [], 'no-token GitLab must return empty'
        # honest degrade — never a silent clean
        assert tool._source_status['gitlab'] == 'unswept_needkey'

    def test_blobs_query_shape_and_token_header(self, tool, monkeypatch):
        monkeypatch.setenv('GITLAB_TOKEN', 'glpat-FAKEtoken0000000000')
        sess = _CaptureSession(_FakeResp(200, []))
        _run(tool._query_gitlab(sess, DOMAIN, _patterns(tool)))
        assert sess.calls, 'no GitLab request issued'
        _method, url, kwargs = sess.calls[0]
        assert url == 'https://gitlab.com/api/v4/search'
        params = kwargs.get('params') or {}
        assert params.get('scope') == 'blobs', 'GitLab search must use scope=blobs (code content)'
        assert params.get('search'), 'no search term sent'
        headers = kwargs.get('headers') or {}
        assert headers.get('PRIVATE-TOKEN') == 'glpat-FAKEtoken0000000000'

    def test_secret_in_blob_content_is_flagged(self, tool, monkeypatch):
        monkeypatch.setenv('GITLAB_TOKEN', 'glpat-FAKEtoken0000000000')
        blob = {
            'path': 'config/prod.py',
            'filename': 'prod.py',
            'project_id': 42,
            'ref': 'main',
            'startline': 3,
            'data': f'lumenfield settings\nAWS_ACCESS_KEY_ID={FAKE_SECRET}\n',
        }
        sess = _CaptureSession(_FakeResp(200, [blob]))
        out = _run(tool._query_gitlab(sess, DOMAIN, _patterns(tool)))
        assert out, 'GitLab blob secret not surfaced'
        row = out[0]
        assert row['matchType'] == 'EXPOSED_SECRET'
        assert row['severity'] == 'HIGH'
        assert row['metadata']['exposedSecret']['detectorName'] == 'aws-access-key-id'
        # raw-secret invariant across the whole emitted row
        assert FAKE_SECRET not in json.dumps(row), 'raw secret leaked into GitLab row'

    def test_401_is_needkey_not_clean(self, tool, monkeypatch):
        monkeypatch.setenv('GITLAB_TOKEN', 'glpat-FAKEtoken0000000000')
        out = _run(tool._query_gitlab(_CaptureSession(_FakeResp(401)), DOMAIN, _patterns(tool)))
        assert out == []
        assert tool._source_status['gitlab'] == 'unswept_needkey'

    def test_scope_unsupported_object_body_is_degraded(self, tool, monkeypatch):
        monkeypatch.setenv('GITLAB_TOKEN', 'glpat-FAKEtoken0000000000')
        # instance without Advanced Search → 200 with a non-list error object
        sess = _CaptureSession(_FakeResp(200, {'message': 'scope not supported'}))
        out = _run(tool._query_gitlab(sess, DOMAIN, _patterns(tool)))
        assert out == []
        assert tool._source_status['gitlab'] == 'degraded'

    def test_benign_blob_without_secret_is_not_high(self, tool, monkeypatch):
        monkeypatch.setenv('GITLAB_TOKEN', 'glpat-FAKEtoken0000000000')
        blob = {
            'path': 'README.md', 'filename': 'README.md', 'project_id': 7,
            'ref': 'main', 'data': 'lumenfield helper library for oauth flows',
        }
        out = _run(tool._query_gitlab(_CaptureSession(_FakeResp(200, [blob])), DOMAIN, _patterns(tool)))
        assert out, 'a brand-matched blob should still surface as a mention'
        assert out[0]['matchType'] == 'BRAND_MENTION'
        assert out[0]['severity'] == 'LOW'
