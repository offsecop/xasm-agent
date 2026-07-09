"""Agent-side Layer-A lock for #882 — Stack Overflow is surface-web PUBLIC CODE,
NOT threat-actor targeting.

`_query_stackoverflow` used to stamp every Q&A hit `matchType='TARGETING_DISCUSSION'`
unconditionally, so a public code discussion presented with threat-actor-targeting
semantics (and, downstream, under "dark web"). The leg now defaults to
`BRAND_MENTION` and only escalates to `TARGETING_DISCUSSION` when a REAL threat tag
(`apt` / `targeted`) is present — mirroring the OTX gate in the same file.

Drives the REAL _query_stackoverflow against a mocked aiohttp session. Fictitious
brand only (lumenfield.test).
"""

import asyncio
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from tools.darkweb_monitor import DarkWebMonitorTool

DOMAIN = 'lumenfield.test'


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
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append(('get', url, kwargs))
        return self._resp


def _run(coro):
    return asyncio.run(coro)


def _items(tags):
    # a single Q&A whose title carries the brand token so the #879 code gate keeps it
    return {
        'items': [
            {
                'title': 'lumenfield SDK oauth token refresh error',
                'tags': tags,
                'link': 'https://stackoverflow.com/q/1',
                'question_id': 1,
                'score': 3,
                'is_answered': True,
            }
        ]
    }


@pytest.fixture
def tool():
    t = DarkWebMonitorTool()
    t._source_status = {}
    return t


def test_no_threat_tag_is_brand_mention(tool):
    # technology tags only → surface-web mention, NOT targeting
    sess = _FakeSession(_FakeResp(200, _items(['python', 'oauth', 'sdk'])))
    out = _run(tool._query_stackoverflow(sess, DOMAIN, []))
    assert out, 'expected the brand-matching Q&A to be kept by the code gate'
    assert all(r['matchType'] == 'BRAND_MENTION' for r in out)
    assert all(r['source'] == 'CODE_REPOSITORY' for r in out)


def test_real_threat_tag_escalates_to_targeting(tool):
    # an actual threat tag → TARGETING_DISCUSSION (mirrors the OTX apt/targeted gate)
    sess = _FakeSession(_FakeResp(200, _items(['apt', 'python'])))
    out = _run(tool._query_stackoverflow(sess, DOMAIN, []))
    assert out
    assert all(r['matchType'] == 'TARGETING_DISCUSSION' for r in out)


def test_threat_tag_is_case_insensitive(tool):
    sess = _FakeSession(_FakeResp(200, _items(['Targeted'])))
    out = _run(tool._query_stackoverflow(sess, DOMAIN, []))
    assert out
    assert all(r['matchType'] == 'TARGETING_DISCUSSION' for r in out)
