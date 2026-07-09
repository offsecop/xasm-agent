"""Agent-side Layer-A locks for #436 — rotated GitHub dork cohorts.

Pure, offline (no network, no GitHub PAT). Locks the cohort taxonomy, the
rotation cursor, the per-cohort quota budget, and the GHSECRET-1 secret gate on
the new commit/issue legs. FICTITIOUS brands only (lumenfield / sol on .test).
"""

import os
import sys

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
AGENT_DIR = os.path.dirname(THIS_DIR)
for d in (AGENT_DIR, os.path.join(AGENT_DIR, 'tools')):
    if d not in sys.path:
        sys.path.insert(0, d)

from unittest.mock import patch  # noqa: E402
from tools.darkweb_monitor import DarkWebMonitorTool  # noqa: E402

DOMAIN = 'lumenfield.test'
PATTERNS = [{'pattern': 'lumenfield', 'name': 'Lumenfield', 'isRegex': False}]
# A high-entropy opaque token (len>=20, >=18 distinct, entropy>=4.2) → real secret.
REAL_TOKEN = 'aB3xY9zQ7wE2rT5uI8oP1kLmNvCxZ0jH4'
# Low-entropy SCREAMING_SNAKE identifier — the classic placeholder FP.
PLACEHOLDER = 'DEFAULT_REFRESH_TOKEN_EXPIRY_SECONDS = 3600'


def _terms(tool):
    return tool._extract_search_terms(DOMAIN, tool._normalize_patterns([], PATTERNS))


class TestRotationCursor:
    def test_explicit_cohort_is_modulo_num_cohorts(self):
        tool = DarkWebMonitorTool()
        n = tool._GH_NUM_COHORTS
        for i in range(0, n * 3):
            assert tool._resolve_dork_cohort(i, DOMAIN) == i % n

    def test_negative_or_none_is_safe(self):
        tool = DarkWebMonitorTool()
        # negative cursor never escapes [0, NUM)
        assert 0 <= tool._resolve_dork_cohort(-5, DOMAIN) < tool._GH_NUM_COHORTS

    def test_absent_cursor_fallback_is_deterministic_and_covers_all(self):
        tool = DarkWebMonitorTool()
        n = tool._GH_NUM_COHORTS
        seen = set()
        # Walk 6 consecutive 4h buckets at a fixed domain — the wall-clock+hash
        # fallback must be stable per bucket AND cover every cohort.
        for bucket in range(n):
            t = (bucket * 14400) + 10
            with patch('tools.darkweb_monitor.time.time', return_value=t):
                a = tool._resolve_dork_cohort(None, DOMAIN)
                b = tool._resolve_dork_cohort(None, DOMAIN)
            assert a == b, 'fallback not stable within a bucket'
            seen.add(a)
        assert seen == set(range(n)), f'fallback did not cover all cohorts: {seen}'


class TestCohortTaxonomy:
    def test_legacy_cohort0_has_no_email_and_keeps_all_qualifiers(self):
        tool = DarkWebMonitorTool()
        triples = tool._build_cohort_queries(_terms(tool), DOMAIN, 0)
        queries = [q for (_t, _e, q, _p) in triples]
        joined = ' '.join(queries)
        # legacy qualifiers + keywords all present
        for q in ('filename:.env', 'extension:yml', 'extension:yaml', 'path:config',
                  'password OR secret', 'leak OR credential'):
            assert q in joined, f'legacy dork missing from cohort 0: {q}'
        # cohort 0 is budget-locked: NO email dork
        assert not any('"@' in q for q in queries), 'cohort 0 must not carry the email dork'
        assert all(e == 'code' for (_t, e, _q, _p) in triples)

    def test_email_dork_present_on_every_nonzero_cohort(self):
        tool = DarkWebMonitorTool()
        for c in range(1, tool._GH_NUM_COHORTS):
            triples = tool._build_cohort_queries(_terms(tool), DOMAIN, c)
            assert any(q == f'"@{DOMAIN}"' for (_t, _e, q, _p) in triples), \
                f'cohort {c} missing the always-on email dork'

    def test_commit_cohort_routes_to_commits_endpoint_with_org_scope(self):
        tool = DarkWebMonitorTool()
        triples = tool._build_cohort_queries(_terms(tool), DOMAIN, tool._GH_COHORT_COMMITS)
        endpoints = {e for (_t, e, _q, _p) in triples}
        assert 'commits' in endpoints
        assert any('org:lumenfield' in q for (_t, _e, q, _p) in triples), 'no org-scoped commit sweep'

    def test_issue_cohort_routes_to_issues_endpoint_and_pages(self):
        tool = DarkWebMonitorTool()
        triples = tool._build_cohort_queries(_terms(tool), DOMAIN, tool._GH_COHORT_ISSUES)
        assert any(e == 'issues' for (_t, e, _q, _p) in triples)
        assert any(p == 2 for (_t, _e, _q, p) in triples), 'no deep-paging (page 2) leg'

    def test_credential_name_cohort_includes_api_host_dork(self):
        tool = DarkWebMonitorTool()
        triples = tool._build_cohort_queries(_terms(tool), DOMAIN, 3)
        joined = ' '.join(q for (_t, _e, q, _p) in triples)
        for name in ('consumer_key', 'refresh_token', 'client_secret', f'api.{DOMAIN}'):
            assert name in joined, f'credential dork missing: {name}'


class TestBudget:
    def test_every_cohort_fits_the_lease(self):
        tool = DarkWebMonitorTool()
        terms = _terms(tool)
        for c in range(tool._GH_NUM_COHORTS):
            triples = tool._build_cohort_queries(terms, DOMAIN, c)
            assert len(triples) <= tool._GH_MAX_COHORT_CODE_UNITS, \
                f'cohort {c} exceeds the {tool._GH_MAX_COHORT_CODE_UNITS}-unit code budget'
            # repo-search (<=4 terms) + cohort must stay within the 28-unit lease.
            assert len(terms[:4]) + len(triples) <= 28, f'cohort {c} breaches the 28-unit lease'


class TestSecretGate:
    def _emit(self, tool, fragment, leg='code'):
        # #879 — the repo name carries the brand token (as a real brand
        # code-search hit does), so the keep/drop gate passes and these tests
        # exercise the SECRET gate, not the brand-match gate.
        return tool._emit_github_match(
            source_name='GitHub - lumenfield/app',
            html_url='https://github.com/lumenfield/app', source_id='id',
            repo_full_name='lumenfield/app', fragment=fragment, search_term=DOMAIN,
            domain=DOMAIN, patterns=tool._normalize_patterns([], PATTERNS), leg=leg,
        )

    def test_high_entropy_token_is_exposed_secret(self):
        tool = DarkWebMonitorTool()
        r = self._emit(tool, f'const k = "{REAL_TOKEN}"')
        assert r['matchType'] == 'EXPOSED_SECRET' and r['severity'] == 'HIGH'
        assert r['metadata']['secretDetected'] is True

    def test_placeholder_is_brand_mention_not_high(self):
        tool = DarkWebMonitorTool()
        r = self._emit(tool, PLACEHOLDER)
        assert r['matchType'] == 'BRAND_MENTION' and r['severity'] == 'LOW'
        assert r['metadata']['secretDetected'] is False

    def test_absent_fragment_never_mints_high(self):
        tool = DarkWebMonitorTool()
        r = self._emit(tool, '', leg='commit')
        assert r['severity'] == 'LOW'
        assert r['metadata']['fragmentAvailable'] is False
        assert r['metadata']['secretDetected'] is False

    def test_metadata_stamps_owned_domain_for_relevance_gate(self):
        tool = DarkWebMonitorTool()
        r = self._emit(tool, PLACEHOLDER)
        assert r['metadata']['domain'] == DOMAIN


class TestEmitDispatch:
    def test_issue_repo_derived_from_html_url_not_api_url(self):
        tool = DarkWebMonitorTool()
        item = {
            'html_url': 'https://github.com/acme/widgets/issues/7',
            'repository_url': 'https://api.github.com/repos/acme/widgets',
            'title': 'lumenfield mention', 'body': 'see lumenfield.test', 'id': 7,
        }
        r = tool._emit_from_github_item(item, 'issues', DOMAIN, DOMAIN,
                                        tool._normalize_patterns([], PATTERNS))
        assert r['metadata']['repository'] == 'acme/widgets'
        assert 'api.github.com' not in (r['metadata']['repository'] or '')
