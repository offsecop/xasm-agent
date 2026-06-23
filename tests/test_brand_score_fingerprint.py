"""DRP score-fan-out flood control — brand:score_against_fingerprint tool tests.

Pre-fix, the only READY fingerprint was a poisoned legacy v1 with ALL signal
columns NULL (it predates ingestion's `|| []` coercion). `fingerprint.get(
'dominantColors', [])` returns None for those rows — the `.get(key, [])`
default is bypassed by an explicit null — so `_color_frequency_vector(None)`
raised TypeError AFTER a chromium session had already been burned
(6,744 lifetime NoneType failures).

Covers:
  - _as_list / _as_dict null-coercion helpers
  - _color_frequency_vector hardened against None / malformed entries
  - _parse_color_hex non-string tolerance
  - _fingerprint_has_usable_signals (incl. nested fingerprintVector fallback)
  - execute(): the pre-chromium "no usable signals" structured fail —
    asserted to return BEFORE any playwright import/launch
"""

import asyncio

import pytest

from tools.brand_score_fingerprint import (
    BrandScoreFingerprintTool,
    _as_dict,
    _as_list,
    _collect_reference_image_hashes,
    _color_frequency_vector,
    _fingerprint_has_usable_signals,
    _parse_color_hex,
)


# The exact poisoned legacy shape served to every score job (F1).
def poisoned_fingerprint():
    return {
        'dominantColors': None,
        'logoHashes': None,
        'fontFamilies': None,
        'layoutPatterns': None,
        'textPatterns': None,
        'faviconHash': None,
        'fingerprintVector': None,
        'referenceImageHashes': None,
    }


class TestNullCoercionHelpers:
    def test_as_list(self):
        assert _as_list(None) == []
        assert _as_list('not-a-list') == []
        assert _as_list({'a': 1}) == []
        assert _as_list([1, 2]) == [1, 2]

    def test_as_dict(self):
        assert _as_dict(None) == {}
        assert _as_dict([1]) == {}
        assert _as_dict('x') == {}
        assert _as_dict({'a': 1}) == {'a': 1}

    def test_color_frequency_vector_none_no_longer_raises(self):
        # The original crash site: _color_frequency_vector(None) at the old
        # brand_score_fingerprint.py:288.
        assert _color_frequency_vector(None) == {}

    def test_color_frequency_vector_malformed_entries(self):
        colors = [
            {'hex': '#102a43', 'frequency': 0.4},
            {'frequency': 0.2},          # missing hex — dropped
            'not-a-dict',                # malformed — dropped
            None,                        # null entry — dropped
            {'hex': '#ffffff'},          # missing frequency — defaults 0
        ]
        assert _color_frequency_vector(colors) == {'#102a43': 0.4, '#ffffff': 0}

    def test_parse_color_hex_non_string(self):
        assert _parse_color_hex(None) is None
        assert _parse_color_hex(123) is None
        assert _parse_color_hex('rgb(16, 42, 67)') == '#102a43'

    def test_collect_reference_image_hashes_null_everywhere(self):
        assert _collect_reference_image_hashes(poisoned_fingerprint()) == []

    def test_collect_reference_image_hashes_nested_fallback(self):
        fp = {
            'referenceImageHashes': None,
            'fingerprintVector': {
                'referenceImageHashes': [
                    {'hash': 'aaaa', 'source': 'manual_screenshot'},
                    {'source': 'broken-no-hash'},
                ],
            },
        }
        assert _collect_reference_image_hashes(fp) == [
            {'hash': 'aaaa', 'source': 'manual_screenshot'},
        ]


class TestUsableSignalsGuard:
    def test_poisoned_fingerprint_has_no_signals(self):
        assert _fingerprint_has_usable_signals(poisoned_fingerprint()) is False

    def test_empty_collections_have_no_signals(self):
        fp = {
            'dominantColors': [],
            'logoHashes': [],
            'fontFamilies': [],
            'layoutPatterns': {},
            'textPatterns': [],
            'faviconHash': None,
            'fingerprintVector': {'referenceAssets': [], 'referenceImageHashes': []},
        }
        assert _fingerprint_has_usable_signals(fp) is False

    @pytest.mark.parametrize('signal', [
        {'dominantColors': [{'hex': '#102a43', 'frequency': 0.4}]},
        {'logoHashes': [{'hash': 'abcd1234'}]},
        {'fontFamilies': ['Inter']},
        {'textPatterns': ['Sign in']},
        {'layoutPatterns': {'hasHeader': True}},
        {'faviconHash': 'ffff0000'},
        {'fingerprintVector': {'referenceImageHashes': [{'hash': 'aaaa'}]}},
    ])
    def test_any_single_signal_is_usable(self, signal):
        fp = poisoned_fingerprint()
        fp.update(signal)
        assert _fingerprint_has_usable_signals(fp) is True

    def test_non_dict_fingerprint_has_no_signals(self):
        assert _fingerprint_has_usable_signals(None) is False
        assert _fingerprint_has_usable_signals('garbage') is False


class TestExecutePreChromiumGuard:
    def _run(self, params):
        tool = BrandScoreFingerprintTool()
        return asyncio.run(tool.execute(params))

    def test_poisoned_fingerprint_structured_fail_before_browser(self, monkeypatch):
        # Poison the playwright import path: if execute() reaches the browser
        # phase the test fails loudly. The guard must return FIRST.
        import sys
        monkeypatch.setitem(sys.modules, 'playwright', None)
        monkeypatch.setitem(sys.modules, 'playwright.async_api', None)

        result = self._run({
            'targetUrl': 'http://examp1e.com',
            'brandMonitorId': 'mon-1',
            'typosquatDomainId': 'tdom-1',
            'fingerprint': poisoned_fingerprint(),
        })
        assert result['success'] is False
        assert 'no usable signals' in result['error']
        assert result['output']['skipReason'] == 'empty_fingerprint'
        assert result['output']['compositeScore'] == 0
        assert result['output']['typosquatDomainId'] == 'tdom-1'

    def test_missing_target_url_still_structured_fail(self):
        result = self._run({'fingerprint': {'fontFamilies': ['Inter']}})
        assert result['success'] is False
        assert 'targetUrl' in result['error']

    def test_missing_fingerprint_still_structured_fail(self):
        result = self._run({'targetUrl': 'http://examp1e.com'})
        assert result['success'] is False
        assert 'fingerprint' in result['error']

    def test_string_null_fingerprint_json(self):
        # Fingerprint arriving as a JSON string with null fields must also
        # hit the guard, not the browser.
        result = self._run({
            'targetUrl': 'http://examp1e.com',
            'fingerprint': '{"dominantColors": null, "logoHashes": null}',
        })
        assert result['success'] is False
        assert result['output'].get('skipReason') == 'empty_fingerprint'
