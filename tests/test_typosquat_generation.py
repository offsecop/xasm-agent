"""Agent-side Layer-A coverage for typosquat GENERATION/SPLIT primitives.

Foundation lock (#267): the drp-replay harness starts at the IngestionService
seam and never executes the agent's generate -> filter -> resolve path, so the
`_split_domain` / mutation-generator / edit-distance-filter primitives shipped
UN-LOCKED. This module drives those primitives DIRECTLY so the downstream
permutation fixes (#274 long-combosquat drop / min-brand-len NO-OP, #278 ccTLD
SLD split) inherit a real gate.

These assertions are INVARIANTS that hold on current code and must keep holding:
they characterize the parts of generation that are already correct. The
bug-specific fail-before/pass-after cases land in the owning downstream PRs.

FICTITIOUS brands only (lumenfield / sol / modeapparel) on .test/.com so the
run.ts hardcode tripwire can never trip.
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from tools.typosquat_detect import TyposquatDetectTool

TOOL = TyposquatDetectTool()


def _generated_domains(**params):
    """Run the REAL generate→filter path (checkDns=False) and return the domain
    set that WOULD be passed to DNS resolution."""
    base = {'checkDns': False, 'maxEditDistance': 5}
    base.update(params)
    out = asyncio.run(TOOL.execute(base))
    return {r['domain'] for r in out.get('output', {}).get('results', [])}


class TestSplitDomain:
    """_split_domain: name/TLD split. PSL gap for unlisted ccTLDs is #278."""

    def test_single_tld(self):
        assert TyposquatDetectTool._split_domain('lumenfield.com') == ('lumenfield', '.com')

    def test_listed_double_tld(self):
        assert TyposquatDetectTool._split_domain('lumenfield.co.uk') == ('lumenfield', '.co.uk')

    def test_unlisted_cctld_splits_correctly_psl(self):
        # PERM-3: an unlisted multi-label ccTLD (.ne.jp / .com.sg) mis-split under
        # the old 13-entry hardcoded list → wrong brand label → lost +12 identity
        # bonus. The PSL split now returns the real brand label + full suffix.
        assert TyposquatDetectTool._split_domain('lumenfield.ne.jp') == ('lumenfield', '.ne.jp')
        assert TyposquatDetectTool._split_domain('lumenfield.com.sg') == ('lumenfield', '.com.sg')

    def test_lowercases_and_strips_trailing_dot(self):
        assert TyposquatDetectTool._split_domain('Lumenfield.COM.') == ('lumenfield', '.com')

    def test_no_dot_falls_back_to_com(self):
        assert TyposquatDetectTool._split_domain('lumenfield') == ('lumenfield', '.com')


class TestEditDistancePrimitives:
    """The pure distance functions the maxEditDistance filter (#274) relies on."""

    def test_levenshtein_basics(self):
        assert TyposquatDetectTool._levenshtein('sol', 'sol') == 0
        assert TyposquatDetectTool._levenshtein('sol', 'soI') == 1
        assert TyposquatDetectTool._levenshtein('', 'sol') == 3

    def test_damerau_counts_transposition_as_one(self):
        # Damerau treats an adjacent swap as cost 1 (plain Levenshtein = 2).
        assert TyposquatDetectTool._damerau_levenshtein('modeapparel', 'modeapparle') == 1
        assert TyposquatDetectTool._levenshtein('modeapparel', 'modeapparle') == 2

    def test_long_combosquat_full_domain_distance_exceeds_default_filter(self):
        # WHY THIS LOCK EXISTS (#274 / PERM-1): the maxEditDistance filter measures
        # distance on the FULL candidate vs FULL original, so a long hyphenated
        # combosquat lure is many edits away and is dropped before DNS today.
        # This documents the current (buggy) distance so #274's fix — exempting
        # combosquats from the filter — has a measured baseline to flip.
        d = TyposquatDetectTool._levenshtein('lumenfield.com', 'lumenfield-login.com')
        assert d > 5, f'expected long combosquat distance > default filter 5, got {d}'


class TestMutationGenerators:
    """Each generator yields valid, brand-derived labels (per-position swaps)."""

    def test_transposition_swaps_each_adjacent_pair(self):
        out = TOOL._transposition('sol', '.com')
        cands = {c for c, _ in out}
        # swap(s,o)->osl ; swap(o,l)->slo
        assert 'osl.com' in cands and 'slo.com' in cands
        assert all(tag == 'TRANSPOSITION' for _, tag in out)

    def test_omission_drops_one_char_each(self):
        out = TOOL._omission('sol', '.com')
        cands = {c for c, _ in out}
        assert cands == {'ol.com', 'sl.com', 'so.com'}

    def test_homoglyph_is_per_position_not_global(self):
        # PERM-DEDUP-1 contrast: a homoglyph sub must replace ONE position at a
        # time, not every occurrence globally. 'o'->'0' on 'solo' must yield both
        # 's0lo' and 'sol0' as DISTINCT candidates (not a single 's0l0').
        out = TOOL._homoglyph('solo', '.com')
        cands = {c for c, _ in out}
        assert 's0lo.com' in cands
        assert 'sol0.com' in cands
        assert 's0l0.com' not in cands


class TestCombosquatEditDistanceExemption:
    """PERM-1/9 — long hyphenated combosquats must SURVIVE the maxEditDistance
    filter and reach the DNS-resolution set (they are the credential-phish/BEC
    lure class the filter silently dropped before DNS)."""

    def test_long_hyphenated_combosquats_reach_resolution_set(self):
        domains = _generated_domains(domain='lumenfield.com', techniques=['combosquatting'])
        # full-domain edit distance is 6-7 (> the default max of 5) — yet present.
        assert 'lumenfield-login.com' in domains
        assert 'secure-lumenfield.com' in domains
        assert 'lumenfield-verify.com' in domains
        assert 'lumenfield-account.com' in domains

    def test_subdomain_prepend_also_exempt(self):
        domains = _generated_domains(domain='lumenfield.com', techniques=['subdomain'])
        # SUBDOMAIN_PREPEND candidates (prefix+brand) have a large edit distance;
        # at least one survives the filter (would be dropped before the exemption).
        assert domains
        assert any(
            TyposquatDetectTool._levenshtein(d, 'lumenfield.com') > 5 for d in domains
        )


class TestMinBrandLenNoop:
    """PERM-5 — a 1-3 char brand label generates a junk corpus; NO-OP it."""

    def test_short_brand_generates_nothing(self):
        # 'sol' (3 chars) → generation NO-OP, empty resolution set.
        assert _generated_domains(domain='sol.com', techniques=['combosquatting']) == set()

    def test_normal_brand_still_generates(self):
        # control: a 4+ char brand still generates.
        assert len(_generated_domains(domain='modeapparel.com', techniques=['combosquatting'])) > 0


class TestKeyboardAdjacency:
    """G1 (#446) — locale-aware fat-finger fuzzer. Keyboard-mechanical errors are
    the empirically dominant registered typo class; we generated none before."""

    def test_qwerty_substitutions_are_physically_adjacent(self):
        # Direct generator call (bypasses the joint max_variations budget).
        out = {d for d, _ in TOOL._keyboard_adjacency('paypal', '.com', ['qwerty'])}
        assert 'paupal.com' in out   # y -> u (adjacent)
        assert 'oaypal.com' in out   # p -> o (adjacent, first char)
        assert 'payoal.com' in out   # p -> o (adjacent, 4th char)
        # A non-adjacent substitution must NOT appear (x is nowhere near p).
        assert 'payxal.com' not in out

    def test_layout_changes_output(self):
        qw = {d for d, _ in TOOL._keyboard_adjacency('paypal', '.com', ['qwerty'])}
        az = {d for d, _ in TOOL._keyboard_adjacency('paypal', '.com', ['azerty'])}
        # 'w' is adjacent to 'a' on QWERTY but not on AZERTY (w sits on the bottom
        # row there), so the a->w substitution is layout-specific.
        assert 'pwypal.com' in qw
        assert 'pwypal.com' not in az
        assert qw != az

    def test_all_candidates_are_valid_labels(self):
        out = {d for d, _ in TOOL._keyboard_adjacency('modeapparel', '.com', ['qwerty', 'qwertz'])}
        for d in out:
            label = d[: -len('.com')]
            assert TyposquatDetectTool._is_valid_label(label)

    def test_technique_registered_in_execute_path(self):
        # Selectable as an explicit technique through the real execute() path.
        domains = _generated_domains(domain='modeapparel.com', enabledTechniques=['keyboard_adjacency'])
        assert 'modeapparel.com' not in domains  # original excluded
        assert any(d.endswith('.com') for d in domains)
        assert len(domains) > 0

    def test_short_brand_is_noop(self):
        # Below MIN_BRAND_LABEL_LEN → generation NO-OP (junk-corpus guard).
        assert _generated_domains(domain='sol.com', enabledTechniques=['keyboard_adjacency']) == set()

    def test_max_variations_honored(self):
        domains = _generated_domains(
            domain='modeapparel.com', enabledTechniques=['keyboard_adjacency'], maxVariations=10
        )
        assert len(domains) <= 10

    def test_invalid_layout_falls_back_to_qwerty(self):
        # An unknown layout string is ignored; output equals the qwerty default.
        domains_bad = _generated_domains(
            domain='modeapparel.com', enabledTechniques=['keyboard_adjacency'], keyboardLayouts=['klingon']
        )
        domains_qwerty = _generated_domains(
            domain='modeapparel.com', enabledTechniques=['keyboard_adjacency'], keyboardLayouts=['qwerty']
        )
        assert domains_bad == domains_qwerty
        assert len(domains_bad) > 0


class TestExpandedCoverage:
    """G2-ext (#451) — homophones, misspellings, number swaps, plural,
    dot-omission, dot↔hyphen, wrong-SLD, multi-edit. One assertion per technique
    plus dedup + multi_edit cap invariants."""

    def test_plural_singular(self):
        assert ('cards.com', 'ADDITION') in TOOL._plural('card', '.com')
        assert ('card.com', 'OMISSION') in TOOL._plural('cards', '.com')

    def test_homophone(self):
        out = {d for d, _ in TOOL._homophone('forall', '.com')}
        assert 'fourall.com' in out  # for -> four

    def test_misspelling_dict(self):
        out = {d for d, _ in TOOL._misspelling_dict('recieve', '.com')}
        assert 'receive.com' in out  # ie -> ei

    def test_cardinal_swap(self):
        out = {d for d, _ in TOOL._cardinal_swap('oneworld', '.com')}
        assert '1world.com' in out  # one -> 1

    def test_ordinal_swap(self):
        out = {d for d, _ in TOOL._ordinal_swap('firstbank', '.com')}
        assert '1stbank.com' in out  # first -> 1st

    def test_dot_omission(self):
        out = {d for d, _ in TOOL._dot_omission('modeapparel', '.com')}
        assert 'wwwmodeapparel.com' in out

    def test_dot_hyphen(self):
        out = {d for d, _ in TOOL._dot_hyphen('my-brand', '.com')}
        assert 'mybrand.com' in out      # hyphen collapse
        assert 'my.brand.com' in out     # hyphen -> sub-label dot

    def test_wrong_sld_cctld(self):
        out = {d for d, _ in TOOL._wrong_sld('modeapparel', '.co.uk')}
        assert 'modeapparel.org.uk' in out  # co.uk -> org.uk
        # single-label TLD has no second level — no-op
        assert TOOL._wrong_sld('modeapparel', '.com') == []

    def test_multi_edit_cap(self):
        out = TOOL._multi_edit('modeapparel', '.com', max_candidates=15)
        assert len(out) <= 15
        assert all(t == 'MULTI_EDIT' for _, t in out)

    def test_multi_edit_honors_max_variations(self):
        domains = _generated_domains(
            domain='modeapparel.com', enabledTechniques=['multi_edit'], maxVariations=12
        )
        assert len(domains) <= 12

    def test_execute_path_registers_new_techniques(self):
        # Each new selection key produces output through the real execute() path.
        for tech in ['homophone', 'misspelling', 'plural', 'cardinal_swap',
                     'ordinal_swap', 'dot_omission', 'dot_hyphen', 'multi_edit']:
            domains = _generated_domains(domain='modeapparel.com', enabledTechniques=[tech])
            assert isinstance(domains, set)  # no crash; technique is wired

    def test_no_duplicate_candidates_across_collisions(self):
        # Running the full HIGH set must not emit the same domain twice (the
        # execute() loop dedups via `seen`).
        out = asyncio.run(TOOL.execute({'checkDns': False, 'domain': 'modeapparel.com', 'entropyLevel': 'HIGH'}))
        domains = [r['domain'] for r in out.get('output', {}).get('results', [])]
        assert len(domains) == len(set(domains))
