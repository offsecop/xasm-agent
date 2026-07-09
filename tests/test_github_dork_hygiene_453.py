"""G4b (#453) — GitHub dork hygiene: watermark + SHA/fingerprint dedup +
1,000-result-cap slicing.

FICTITIOUS brand (lumenfield) only.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from tools.darkweb_monitor import DarkWebMonitorTool

TOOL = DarkWebMonitorTool()
LAST_RUN = '2026-06-01T00:00:00Z'


class TestWatermark:
    def test_date_qualifier_per_endpoint(self):
        assert TOOL._github_date_qualifier('repositories', LAST_RUN) == 'pushed:>2026-06-01'
        assert TOOL._github_date_qualifier('commits', LAST_RUN) == 'committer-date:>2026-06-01'
        assert TOOL._github_date_qualifier('issues', LAST_RUN) == 'updated:>2026-06-01'
        # code search has NO date qualifier (GitHub limitation) -> empty
        assert TOOL._github_date_qualifier('code', LAST_RUN) == ''

    def test_absent_last_run_is_noop(self):
        assert TOOL._github_date_qualifier('repositories', None) == ''
        assert TOOL._apply_watermark('foo in:name', 'repositories', None) == 'foo in:name'

    def test_apply_watermark_appends(self):
        assert TOOL._apply_watermark('foo in:name', 'repositories', LAST_RUN) == 'foo in:name pushed:>2026-06-01'

    def test_cohort_queries_carry_watermark(self):
        # Commits cohort (4) -> committer-date:> on the commit dorks; the always-on
        # '@domain' email leg is a CODE query and stays un-watermarked.
        triples = TOOL._build_cohort_queries(['lumenfield'], 'lumenfield.test', 4, LAST_RUN)
        commit_qs = [q for (_t, ep, q, _p) in triples if ep == 'commits']
        assert commit_qs and all('committer-date:>2026-06-01' in q for q in commit_qs)
        # Issues cohort (5) -> updated:>.
        triples5 = TOOL._build_cohort_queries(['lumenfield'], 'lumenfield.test', 5, LAST_RUN)
        issue_qs = [q for (_t, ep, q, _p) in triples5 if ep == 'issues']
        assert issue_qs and all('updated:>2026-06-01' in q for q in issue_qs)
        # Absent last-run -> no date qualifier anywhere (legacy behaviour).
        plain = TOOL._build_cohort_queries(['lumenfield'], 'lumenfield.test', 4, None)
        assert not any('committer-date' in q or 'updated:>' in q or 'pushed:>' in q
                       for (_t, _e, q, _p) in plain)


class TestDedup:
    def test_fingerprint_stable_for_same_leak(self):
        a = {'metadata': {'sha': 'abc123', 'secretDetected': True}, 'contentSnippet': 'AKIA...'}
        b = {'metadata': {'sha': 'abc123', 'secretDetected': True}, 'contentSnippet': 'AKIA...'}
        assert TOOL._github_result_fingerprint(a) == TOOL._github_result_fingerprint(b)

    def test_fingerprint_differs_by_sha(self):
        a = {'metadata': {'sha': 'abc123'}, 'sourceUrl': 'x'}
        b = {'metadata': {'sha': 'def456'}, 'sourceUrl': 'x'}
        assert TOOL._github_result_fingerprint(a) != TOOL._github_result_fingerprint(b)

    def test_dedup_emits_once(self):
        # Simulate the within-scan dedup the _query_github loop applies.
        seen = set()
        items = [
            {'metadata': {'sha': 'abc123', 'secretDetected': True}, 'contentSnippet': 's'},
            {'metadata': {'sha': 'abc123', 'secretDetected': True}, 'contentSnippet': 's'},  # dup
            {'metadata': {'sha': 'zzz999'}, 'sourceUrl': 'u'},
        ]
        emitted = []
        for r in items:
            fp = TOOL._github_result_fingerprint(r)
            if fp in seen:
                continue
            seen.add(fp)
            emitted.append(r)
        assert len(emitted) == 2  # the duplicate SHA+secret is collapsed


class TestThousandCapSlicing:
    def test_under_cap_returns_query_unchanged(self):
        assert TOOL._slice_broad_query('"x"', 'code', 900) == ['"x"']

    def test_code_query_sliced_by_extension(self):
        slices = TOOL._slice_broad_query('"x"', 'code', 50000)
        assert len(slices) > 1
        assert all(s.startswith('"x" extension:') for s in slices)
        assert len(slices) <= TOOL._GH_MAX_SLICES

    def test_commit_query_sliced_by_date_window(self):
        slices = TOOL._slice_broad_query('"x"', 'commits', 50000)
        assert len(slices) > 1
        assert all('committer-date:' in s for s in slices)

    def test_issue_query_sliced_by_date_window(self):
        slices = TOOL._slice_broad_query('"x"', 'issues', 50000)
        assert all('created:' in s for s in slices)
