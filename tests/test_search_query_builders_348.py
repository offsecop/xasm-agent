"""Agent-side Layer-A locks for the #348 search-query-builder optimizations.

Pure-string, NO live vendor calls (network is never touched — the GitHub test
drives `_query_github` through a fully mocked aiohttp session and only inspects
the query STRINGS that would be sent). Three builders are locked:

  1. darkweb_monitor._query_github   — emits the new filename:/extension:/path:
     qualifier queries AND keeps the legacy keyword queries.
  2. darkweb_monitor._extract_search_terms — drops ultra-short/loose dotless
     labels and no longer backfills a non-matching RAW term (qt-bonds/questlit
     precision shape) on the repo path.
  3. hiker_brand._gen_brand_permutations — widened homoglyph + transposition /
     omission / doubling / vowel-swap set, deduped, order-preserving, capped.
  4. brand_monitor_vip_exposure._exec_dork_templates — operator-rich exec dorks.

FICTITIOUS brands only (lumenfield / sol / modeapparel / mode) on .test so the
backend hardcode tripwire can never trip (this file lives under agent/tests/,
which is exempt anyway, but we keep the discipline).
"""

import asyncio
import os
import sys
from unittest.mock import AsyncMock, MagicMock, patch

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
AGENT_DIR = os.path.dirname(THIS_DIR)
for d in (AGENT_DIR, os.path.join(AGENT_DIR, 'tools')):
    if d not in sys.path:
        sys.path.insert(0, d)

from tools.darkweb_monitor import DarkWebMonitorTool  # noqa: E402
from tools.hiker_brand import (  # noqa: E402
    _gen_brand_permutations,
    _MAX_BRAND_PERMUTATIONS,
)
from tools.brand_monitor_vip_exposure import _exec_dork_templates  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers — a fully mocked aiohttp session that records every requested URL and
# returns empty 200 JSON, so `_query_github` runs end-to-end with NO network.
# ---------------------------------------------------------------------------
def _ctx_manager(resp):
    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=resp)
    cm.__aexit__ = AsyncMock(return_value=None)
    return cm


def _empty_200():
    resp = MagicMock()
    resp.status = 200
    resp.json = AsyncMock(return_value={'items': []})
    resp.text = AsyncMock(return_value='')
    return resp


def _run_query_github(domain, patterns, github_token='ghs_faketoken_for_test_0123456789',
                      dork_cohort=0):
    """Drive _query_github with a token present (so the code-search leg runs) and
    capture every URL the session.get was asked to fetch. #436 — `dork_cohort`
    defaults to 0 (the legacy cohort) so the #348 qualifier/keyword locks below
    stay deterministic; pass another index to exercise a rotated cohort."""
    tool = DarkWebMonitorTool()
    requested_urls = []

    session = MagicMock()

    def _get(url, **kwargs):
        requested_urls.append(url)
        return _ctx_manager(_empty_200())

    session.get = MagicMock(side_effect=_get)

    # Patch the credential lease so it returns our token and never hits network.
    with patch('tools.darkweb_monitor.checkout_provider', new=AsyncMock(
        return_value={'apiKey': github_token, 'leaseToken': 'lease-test'},
    )), patch('tools.darkweb_monitor.reconcile_call', new=AsyncMock(return_value=None)), \
            patch('tools.darkweb_monitor.asyncio.sleep', new=AsyncMock(return_value=None)):
        asyncio.run(tool._query_github(session, domain, patterns, None, dork_cohort))

    return requested_urls


# ---------------------------------------------------------------------------
# 1. GitHub qualifier queries
# ---------------------------------------------------------------------------
class TestGithubQualifierQueries:
    def test_emits_filename_extension_path_qualifiers(self):
        # A specific brand pattern + a brand domain.
        patterns = [{'pattern': 'lumenfield', 'name': 'Lumenfield', 'isRegex': False}]
        urls = _run_query_github('lumenfield.test', patterns)
        joined = ' '.join(urls)

        # The new high-value qualifiers must appear in the code-search queries.
        assert 'filename:.env' in joined, 'missing filename:.env qualifier query'
        assert 'extension:yml' in joined, 'missing extension:yml qualifier query'
        assert 'extension:yaml' in joined, 'missing extension:yaml qualifier query'
        assert 'path:config' in joined, 'missing path:config qualifier query'

    def test_qualifiers_scope_a_quoted_brand_term(self):
        patterns = [{'pattern': 'lumenfield', 'name': 'Lumenfield', 'isRegex': False}]
        urls = _run_query_github('lumenfield.test', patterns)
        # The full-domain term is always specific → carried as a quoted code query.
        # Confirm at least one qualifier query is scoped to a quoted term (not bare).
        code_urls = [u for u in urls if '/search/code' in u]
        assert code_urls, 'no code-search queries were issued'
        qualifier_code = [u for u in code_urls if 'filename%3A.env' in u or 'filename:.env' in u]
        assert qualifier_code, 'filename qualifier not present on the code-search leg'
        # Quoted term present on the qualifier query (URL-encoded %22 or raw ").
        assert any(('%22' in u) or ('"' in u) for u in qualifier_code)

    def test_legacy_keyword_queries_preserved(self):
        patterns = [{'pattern': 'lumenfield', 'name': 'Lumenfield', 'isRegex': False}]
        urls = _run_query_github('lumenfield.test', patterns)
        joined = ' '.join(urls)
        # Legacy keyword queries must still be present (recall not regressed).
        assert 'password' in joined and 'api_key' in joined
        assert 'leak' in joined and 'credential' in joined


# ---------------------------------------------------------------------------
# 2. _extract_search_terms — specificity guard + no raw-term backfill
# ---------------------------------------------------------------------------
class TestExtractSearchTerms:
    def test_drops_ultra_short_dotless_label(self):
        tool = DarkWebMonitorTool()
        # `qt` is a 2-char dotless label — the loose-token FP source. Dropped.
        patterns = [{'pattern': 'qt', 'name': 'qt', 'isRegex': False}]
        terms = tool._extract_search_terms('qt.test', patterns)
        # The short loose label must NOT be emitted as a free term...
        assert 'qt' not in [t.lower() for t in terms]
        # ...but the full domain (specific, has a dot) is kept.
        assert 'qt.test' in [t.lower() for t in terms]

    def test_keeps_specific_long_label_and_domain(self):
        tool = DarkWebMonitorTool()
        patterns = [{'pattern': 'lumenfield', 'name': 'Lumenfield', 'isRegex': False}]
        terms = tool._extract_search_terms('lumenfield.test', patterns)
        lowered = [t.lower() for t in terms]
        assert 'lumenfield' in lowered
        assert 'lumenfield.test' in lowered

    def test_short_label_brand_still_searchable_by_domain(self):
        """A 3-char synthetic brand (`sol`) — the loose label is dropped, but the
        full domain still anchors the search so the brand is not lost."""
        tool = DarkWebMonitorTool()
        terms = tool._extract_search_terms('sol.test', [])
        lowered = [t.lower() for t in terms]
        assert 'sol' not in lowered  # 3-char dotless label dropped
        assert 'sol.test' in lowered  # domain kept

    def test_repo_path_drops_nonmatching_row(self):
        """#879 — a repo result with NO token-boundary brand match is now DROPPED
        entirely (a real keep/drop gate). #348 only fixed the LABEL (fell back to
        the domain instead of the raw term); #879 removes the retention fallback
        so a non-matching vendor row is not emitted at all.

        We drive _query_github with a repo result whose name/description carry NO
        token-boundary brand reference and confirm it produces no result row."""
        tool = DarkWebMonitorTool()
        patterns = [{'pattern': 'lumenfield', 'name': 'Lumenfield', 'isRegex': False}]

        # A repo whose content is an unrelated 'lumenfield-bonds' glued prefix —
        # the loose-token FP shape. `_text_matches_search_terms` returns [] for it
        # (no standalone brand token), so the backfill path is exercised.
        repo_item = {
            'id': 99,
            'full_name': 'acme/lumenfieldbonds-portfolio',
            'description': 'an unrelated bonds portfolio app',
            'html_url': 'https://github.test/acme/lumenfieldbonds-portfolio',
            'updated_at': '2026-06-10T00:00:00Z',
        }
        repo_resp = MagicMock()
        repo_resp.status = 200
        repo_resp.json = AsyncMock(return_value={'items': [repo_item]})
        repo_resp.text = AsyncMock(return_value='')

        session = MagicMock()

        def _get(url, **kwargs):
            # Only the repo-search leg returns the item; code search returns empty.
            if '/search/repositories' in url:
                return _ctx_manager(repo_resp)
            return _ctx_manager(_empty_200())

        session.get = MagicMock(side_effect=_get)

        with patch('tools.darkweb_monitor.checkout_provider', new=AsyncMock(
            return_value={'apiKey': 'ghs_faketoken', 'leaseToken': 'lease-test'},
        )), patch('tools.darkweb_monitor.reconcile_call', new=AsyncMock(return_value=None)), \
                patch('tools.darkweb_monitor.asyncio.sleep', new=AsyncMock(return_value=None)):
            results = asyncio.run(tool._query_github(session, 'lumenfield.test', patterns))

        # #879 — the unrelated repo (glued 'lumenfieldbonds' prefix, no standalone
        # brand token) must be DROPPED, not kept with a domain-backfill keyword.
        repo_results = [r for r in results
                        if 'bonds-portfolio' in (r.get('sourceUrl') or '')]
        assert not repo_results, (
            f'a repo with no token-boundary brand match must be DROPPED (#879), '
            f'not kept: {repo_results}'
        )


# ---------------------------------------------------------------------------
# 2b. #879 — code-platform legs are a REAL keep/drop gate. A vendor row with no
#     token-boundary match is DROPPED (no `or [domain]` phantom retention); a
#     multi-word term requires the FULL phrase.
# ---------------------------------------------------------------------------
class TestCodePlatformKeepDropGate:
    def _run_npm(self, patterns, objects):
        tool = DarkWebMonitorTool()
        resp = MagicMock()
        resp.status = 200
        resp.json = AsyncMock(return_value={'objects': objects})
        session = MagicMock()
        session.get = MagicMock(side_effect=lambda url, **kwargs: _ctx_manager(resp))
        with patch('tools.darkweb_monitor.asyncio.sleep', new=AsyncMock(return_value=None)):
            return asyncio.run(tool._query_npm(session, 'lumenfield.test', patterns))

    def test_npm_precision_multiword_partial_match_dropped(self):
        """A multi-word term 'lumenfield army' whose npm hit matches ONLY 'army'
        (package 'minion-army') has no full-phrase token-boundary match → 0 rows."""
        patterns = [{'pattern': 'lumenfield army', 'name': 'Lumenfield Army', 'isRegex': False}]
        objects = [{'package': {
            'name': 'minion-army',
            'description': 'a minion army builder game',
            'links': {'npm': 'https://npm.test/minion-army'},
        }}]
        results = self._run_npm(patterns, objects)
        assert results == [], (
            f'partial (army-only) match of a multi-word term must be DROPPED: {results}'
        )

    def test_npm_recall_full_phrase_kept(self):
        """The same term where the package description carries the LITERAL phrase
        'lumenfield army' matches on token boundaries → kept, keyworded correctly."""
        patterns = [{'pattern': 'lumenfield army', 'name': 'Lumenfield Army', 'isRegex': False}]
        objects = [{'package': {
            'name': 'lf-tools',
            'description': 'utilities for the lumenfield army platform',
            'links': {'npm': 'https://npm.test/lf-tools'},
        }}]
        results = self._run_npm(patterns, objects)
        assert len(results) >= 1, f'full-phrase match must be KEPT: {results}'
        kws = [str(k).lower() for k in results[0].get('matchedKeywords', [])]
        assert 'lumenfield army' in kws, f'expected the phrase in matchedKeywords: {kws}'
        # never the domain-backfill phantom.
        assert 'lumenfield.test' not in kws, f'domain phantom leaked (#879): {kws}'


# ---------------------------------------------------------------------------
# 3. _gen_brand_permutations — widened set + cap
# ---------------------------------------------------------------------------
class TestGenBrandPermutations:
    def test_homoglyph_variants_for_modeapparel(self):
        perms = _gen_brand_permutations('Mode Apparel', 'modeapparel')
        # Widened homoglyph substitutions (single-char, first occurrence).
        assert 'm0deapparel' in perms       # o->0
        assert 'mod3apparel' in perms       # e->3
        assert 'mode4pparel' in perms       # a->4
        assert 'rnodeapparel' in perms      # m->rn (multi-char homoglyph)

    def test_structural_typo_classes_for_short_brand(self):
        # `mode` is short enough that transposition / omission / doubling fit
        # under the cap (vowel-swap is asserted on the even shorter `sol` below).
        perms = _gen_brand_permutations('Mode', 'mode')
        assert 'omde' in perms              # transposition (m<->o)
        assert 'ode' in perms               # single-omission (drop 'm')
        assert 'mmode' in perms             # doubling (double 'm')
        assert 'mod3' in perms              # e->3 homoglyph

    def test_transposition_doubling_and_vowel_swap_for_sol(self):
        # `sol` (3 chars) — the whole structural set fits, so vowel-swap survives.
        perms = _gen_brand_permutations('Sol', 'sol')
        assert 's0l' in perms               # o->0
        assert '5ol' in perms               # s->5
        assert 'osl' in perms or 'slo' in perms  # transposition
        assert 'ssol' in perms or 'sool' in perms  # doubling
        # vowel-swap of the 'o' (o->a/e/i/u)
        assert any(p in perms for p in ('sal', 'sel', 'sil', 'sul'))

    def test_dedup_order_preserving_and_real_handle_first(self):
        perms = _gen_brand_permutations('Lumenfield', 'lumenfield')
        # Real handle is the first entry.
        assert perms[0] == 'lumenfield'
        # No duplicates.
        assert len(perms) == len(set(perms))

    def test_bounded_at_cap(self):
        perms = _gen_brand_permutations('Lumenfield', 'lumenfield')
        assert len(perms) <= _MAX_BRAND_PERMUTATIONS
        assert _MAX_BRAND_PERMUTATIONS <= 24  # documented sane bound

    def test_empty_handle_returns_empty(self):
        assert _gen_brand_permutations('', '') == []


# ---------------------------------------------------------------------------
# 4. _exec_dork_templates — operator-rich exec dorks
# ---------------------------------------------------------------------------
class TestExecDorkTemplates:
    def test_emits_operator_rich_queries(self):
        dorks = _exec_dork_templates('Jane Synth', 'Lumenfield', 'lumenfield.test')
        joined = ' | '.join(dorks)

        assert 'site:linkedin.com "Jane Synth"' in dorks
        assert any('site:pastebin.com "Jane Synth"' == d for d in dorks)
        assert 'filetype:pdf "Lumenfield" confidential' in dorks
        # Contact-PII dork scoped to the owned mailbox domain.
        assert '"Jane Synth" ("@lumenfield.test" OR "phone")' in dorks
        # Breach/dox scoping present.
        assert any('breach' in d and 'dox' in d for d in dorks)
        # Sanity: every template is a non-empty string and the name is quoted.
        assert all(d.strip() for d in dorks)
        assert '"Jane Synth"' in joined

    def test_contact_dork_without_domain_uses_generic_contact_operators(self):
        dorks = _exec_dork_templates('Jane Synth', 'Lumenfield')
        assert '"Jane Synth" ("email" OR "phone")' in dorks

    def test_dedup_and_empty_name_guard(self):
        assert _exec_dork_templates('') == []
        dorks = _exec_dork_templates('Jane Synth', '', '')
        assert len(dorks) == len(set(dorks))
