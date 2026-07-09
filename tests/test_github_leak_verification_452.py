"""G4a (#452) — GitHub leak live-verification + commit-history scan.

The clone+TruffleHog verifier is INJECTED so these run without the binary or any
network/clone. FICTITIOUS repos only.
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from tools.darkweb_monitor import DarkWebMonitorTool

TOOL = DarkWebMonitorTool()


def _secret_result(repo='acme/leak', severity='HIGH', risk=70):
    return {
        'matchType': 'EXPOSED_SECRET',
        'severity': severity,
        'riskScore': risk,
        'metadata': {'repository': repo, 'secretDetected': True},
    }


def _verify(results, verdict):
    return asyncio.run(TOOL._apply_secret_verification(results, verifier=lambda url: verdict))


class TestVerificationVerdicts:
    def test_unverified_placeholder_is_not_high(self):
        # A fake-but-valid-shape AWS key TruffleHog cannot verify → demoted out of
        # the HIGH-floored EXPOSED_SECRET matchType to a LOW brand mention.
        r = _verify([_secret_result()], {'verdict': 'unverified', 'detail': 'placeholder'})
        assert r[0]['severity'] == 'LOW'
        assert r[0]['matchType'] == 'BRAND_MENTION'
        assert r[0]['metadata']['verificationVerdict'] == 'unverified'
        assert r[0]['metadata']['unverifiedSecretCandidate'] is True

    def test_verified_live_key_is_high(self):
        r = _verify([_secret_result(severity='MEDIUM')], {'verdict': 'verified', 'detail': '1'})
        assert r[0]['severity'] == 'HIGH'
        assert r[0]['metadata']['verificationVerdict'] == 'verified'

    def test_secret_only_in_history_is_detected(self):
        r = _verify([_secret_result(severity='MEDIUM')], {'verdict': 'verified', 'historyOnly': True})
        assert r[0]['severity'] == 'HIGH'
        assert r[0]['metadata']['secretInHistoryOnly'] is True

    def test_oversized_repo_is_honest_skip_not_crash(self):
        r = _verify([_secret_result()], {'verdict': 'skipped_oversized', 'detail': '900MB'})
        assert r[0]['severity'] == 'HIGH'  # severity unchanged (couldn't verify)
        assert r[0]['metadata']['verificationVerdict'] == 'skipped_oversized'

    def test_verifier_unavailable_keeps_severity_with_marker(self):
        # No trufflehog binary → recall-preserving: keep severity, mark honestly.
        r = _verify([_secret_result()], {'verdict': 'unavailable', 'detail': 'no bin'})
        assert r[0]['severity'] == 'HIGH'
        assert r[0]['metadata']['verificationVerdict'] == 'unavailable'

    def test_non_secret_results_untouched(self):
        r = _verify([{'matchType': 'BRAND_MENTION', 'severity': 'LOW'}], {'verdict': 'verified'})
        assert r[0]['severity'] == 'LOW'
        assert 'verificationVerdict' not in (r[0].get('metadata') or {})

    def test_budget_caps_verifications(self):
        many = [_secret_result(repo=f'acme/r{i}') for i in range(TOOL._GH_VERIFY_MAX_PER_SCAN + 3)]
        calls = []

        def counting(url):
            calls.append(url)
            return {'verdict': 'verified'}

        asyncio.run(TOOL._apply_secret_verification(many, verifier=counting))
        assert len(calls) == TOOL._GH_VERIFY_MAX_PER_SCAN  # bounded


class TestCloneUrlDerivation:
    def test_derives_https_clone_url(self):
        assert TOOL._derive_clone_url({'metadata': {'repository': 'acme/leak'}}) == 'https://github.com/acme/leak.git'

    def test_missing_repo_returns_empty(self):
        assert TOOL._derive_clone_url({'metadata': {}}) == ''
        assert TOOL._derive_clone_url({'metadata': {'repository': 'norepo'}}) == ''


class TestRealVerifierGuards:
    def test_real_verdict_is_unavailable_without_binary(self):
        # In CI/local without trufflehog installed, the real path degrades cleanly.
        v = TOOL._trufflehog_verdict('https://github.com/acme/leak.git')
        assert v['verdict'] in ('unavailable', 'unknown')
