"""Agent-side Layer-A lock for the cross-provider EXPOSED_SECRET gate.

The `_fragment_has_secret` credential/entropy gate historically ran ONLY in the
GitHub path — GitLab / npm / Stack Overflow / Pastebin / Gist content shipped as
a plain LOW `BRAND_MENTION`, so a REAL leaked secret on any non-GitHub provider
was silently downgraded. `_apply_secret_gate` now runs the SAME gate across those
providers and elevates a hit to the GitHub path's exact `EXPOSED_SECRET` / HIGH
shape, while leaving a benign brand mention byte-untouched.

PRECISION: a benign brand mention (no credential-shaped / high-entropy token)
           stays `BRAND_MENTION` / LOW — must NOT become `EXPOSED_SECRET`.
RECALL:    a real high-entropy / credential-shaped secret in the provider's
           content elevates to `EXPOSED_SECRET` / HIGH.

Drives the REAL `_query_gitlab` / `_query_npm` against a mocked aiohttp session.
Fictitious brand only (lumenfield.test); the secret is a synthetic, non-live
AWS-shaped key literal.
"""

import asyncio
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from tools.darkweb_monitor import DarkWebMonitorTool

DOMAIN = 'lumenfield.test'
# Synthetic AWS-access-key-shaped literal (AKIA + 16 uppercase) — matches the
# _SECRET_PATTERNS regex. NOT a real key.
SYNTHETIC_SECRET = 'AKIAABCDEFGHIJKLMNOP'


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
    def __init__(self, resp):
        self._resp = resp

    def get(self, url, **kwargs):
        return self._resp


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture
def tool():
    t = DarkWebMonitorTool()
    t._source_status = {}
    return t


# ── unit: the gate itself ─────────────────────────────────────────────────────

def test_gate_elevates_on_secret(tool):
    row = {'matchType': 'BRAND_MENTION', 'severity': 'LOW',
           'relevanceScore': 60, 'riskScore': 38, 'sourceName': 'npm'}
    out = tool._apply_secret_gate(dict(row), f"config token = {SYNTHETIC_SECRET}")
    assert out['matchType'] == 'EXPOSED_SECRET'
    assert out['severity'] == 'HIGH'
    assert out['relevanceScore'] >= 75
    assert out['riskScore'] >= 70
    assert out['metadata']['secretDetected'] is True


def test_gate_leaves_benign_untouched(tool):
    row = {'matchType': 'BRAND_MENTION', 'severity': 'LOW',
           'relevanceScore': 60, 'riskScore': 38, 'sourceName': 'npm'}
    out = tool._apply_secret_gate(dict(row), 'a helper library for lumenfield oauth flows')
    assert out['matchType'] == 'BRAND_MENTION'
    assert out['severity'] == 'LOW'


def test_gate_never_demotes_higher_base_score(tool):
    # Pastebin's base (76/55) must not be demoted to the GitHub floor (75/70 pair)
    row = {'matchType': 'BRAND_MENTION', 'severity': 'MEDIUM',
           'relevanceScore': 76, 'riskScore': 55, 'sourceName': 'Pastebin'}
    out = tool._apply_secret_gate(dict(row), SYNTHETIC_SECRET)
    assert out['relevanceScore'] == 76  # max(76, 75)
    assert out['riskScore'] == 70       # max(55, 70)


# ── GitLab leg ────────────────────────────────────────────────────────────────

def _gitlab_projects(description):
    return [{
        'id': 42,
        'path_with_namespace': 'lumenfield/config',
        'name': 'config',
        'description': description,
        'web_url': 'https://gitlab.com/lumenfield/config',
        'visibility': 'public',
        'namespace': {'full_path': 'lumenfield'},
        'last_activity_at': '2026-06-10T00:00:00Z',
    }]


def test_gitlab_secret_elevates_to_exposed_secret(tool):
    desc = f"lumenfield prod config: aws_secret = {SYNTHETIC_SECRET}"
    sess = _FakeSession(_FakeResp(200, _gitlab_projects(desc)))
    out = _run(tool._query_gitlab(sess, DOMAIN, []))
    assert out, 'expected the brand-matching project to be kept'
    assert all(r['matchType'] == 'EXPOSED_SECRET' for r in out)
    assert all(r['severity'] == 'HIGH' for r in out)


def test_gitlab_benign_stays_brand_mention(tool):
    sess = _FakeSession(_FakeResp(200, _gitlab_projects('lumenfield helper SDK for oauth')))
    out = _run(tool._query_gitlab(sess, DOMAIN, []))
    assert out
    assert all(r['matchType'] == 'BRAND_MENTION' for r in out)
    assert all(r['severity'] == 'LOW' for r in out)


# ── npm leg ───────────────────────────────────────────────────────────────────

def _npm_objects(description):
    return {'objects': [{
        'package': {
            'name': 'lumenfield-sdk',
            'description': description,
            'version': '1.0.0',
            'links': {'npm': 'https://npmjs.com/package/lumenfield-sdk'},
            'date': '2026-06-10T00:00:00Z',
        }
    }]}


def test_npm_secret_elevates_to_exposed_secret(tool):
    desc = f"lumenfield client — do not commit: api_key = {SYNTHETIC_SECRET}"
    sess = _FakeSession(_FakeResp(200, _npm_objects(desc)))
    out = _run(tool._query_npm(sess, DOMAIN, []))
    assert out
    assert all(r['matchType'] == 'EXPOSED_SECRET' for r in out)
    assert all(r['severity'] == 'HIGH' for r in out)


def test_npm_benign_stays_brand_mention(tool):
    sess = _FakeSession(_FakeResp(200, _npm_objects('official lumenfield javascript client')))
    out = _run(tool._query_npm(sess, DOMAIN, []))
    assert out
    assert all(r['matchType'] == 'BRAND_MENTION' for r in out)
