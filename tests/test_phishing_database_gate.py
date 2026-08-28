"""Agent-side Layer-A locks for the Phishing.Database FP gate (#1617).

WHY THIS FILE EXISTS — the gate shipped in #1611 had NO reachable coverage.
The FP control is Python (`_match_phishing_domains`); the only lock was a
backend replay cassette injected DOWNSTREAM of it, so the cassette could not
execute this code and passed with the gate deleted. Every assertion below is
mutation-checked: it FAILS if the boundary/TLD/scope rules are reverted.

The two rules under test, both measured against the live 391,616-row feed:

  1. TLD EXCLUSION. Splitting the whole domain on `[.-]` made every phishing
     domain on a same-named public suffix a hit: `link` 6,667 matches (6,338
     TLD-only), `site` 4,928 (4,081), `shop` 3,313 (3,077), `cloud` 1,534
     (1,174). None brand-related.
  2. BOUNDARY ANCHORING. A term must EQUAL a whole segment, never appear as a
     substring: raw substring `trade` = 316 hits vs 6 boundary-gated.

Fictitious brands and `.test`/public-suffix domains only.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from tools.darkweb_monitor import (  # noqa: E402
    PHISHING_DB_MAX_EMISSIONS,
    _match_phishing_domains,
)


def _matched(domains, terms):
    return [d for d, _ in _match_phishing_domains(domains, set(terms))]


# --- Rule 1: the public suffix is NOT matchable -------------------------------


def test_tld_is_never_matched():
    """A term equal to the TLD must not match. Reverting the `labels[:-1]`
    slice makes every one of these a hit — this is the 6,338-row `link` bug."""
    feed = [
        'paypal-secure.link',
        'account-verify.shop',
        'login-portal.site',
        'my-bank.cloud',
        'signin.online',
    ]
    for term in ('link', 'shop', 'site', 'cloud', 'online'):
        assert _matched(feed, [term]) == [], (
            f'term {term!r} matched via the public suffix'
        )


def test_registrable_label_still_matches_on_those_tlds():
    """The TLD exclusion must not blind us to a real impersonation that
    happens to sit on one of those TLDs — otherwise fix #1 becomes a recall
    hole. `lumenfield` is a genuine segment of the registrable name here."""
    feed = ['lumenfield-verify.link', 'secure-lumenfield.shop']
    assert _matched(feed, ['lumenfield']) == [
        'lumenfield-verify.link',
        'secure-lumenfield.shop',
    ]


def test_subdomain_labels_are_matchable():
    """Impersonation via a subdomain label is real and must still fire."""
    feed = ['lumenfield.attacker-cdn.test']
    assert _matched(feed, ['lumenfield']) == feed


# --- Rule 2: whole-segment equality, never substring --------------------------


def test_glued_infix_is_not_a_match():
    """Substring containment must not match. Reverting to `t in pd` fires."""
    feed = [
        'lumenfieldsupply-verify.test',   # glued suffix
        'mylumenfield.test',              # glued prefix
        'xlumenfieldx.test',              # glued both sides
    ]
    assert _matched(feed, ['lumenfield']) == []


def test_hyphen_and_dot_are_both_segment_boundaries():
    feed = ['lumenfield-login.test', 'login.lumenfield.test']
    assert sorted(_matched(feed, ['lumenfield'])) == sorted(feed)


def test_common_word_term_does_not_match_unrelated_infixes():
    """The `trade` 316-vs-6 case: a common-word label must only hit whole
    segments, not every domain that happens to contain the letters."""
    feed = [
        'contrader-verify.test',      # substring only
        'brokentradesman.test',       # substring only
        'trade-login.test',           # whole segment -> real hit
    ]
    assert _matched(feed, ['trade']) == ['trade-login.test']


# --- Determinism / shape ------------------------------------------------------


def test_results_are_sorted_and_carry_the_matched_term():
    feed = ['zeta-lumenfield.test', 'alpha-lumenfield.test']
    pairs = _match_phishing_domains(feed, {'lumenfield'})
    assert [d for d, _ in pairs] == ['alpha-lumenfield.test', 'zeta-lumenfield.test']
    assert {t for _, t in pairs} == {'lumenfield'}


def test_bare_token_without_public_suffix_is_skipped():
    """A feed line with no dot is not a resolvable domain; matching it would
    let a stray token mint an alert."""
    assert _matched(['lumenfield', ''], ['lumenfield']) == []


def test_cap_is_a_bound_not_a_filter():
    """The cap must not be load-bearing for FP control — the gate rejects
    non-matches regardless of how many rows arrive."""
    noise = [f'unrelated-{i}.test' for i in range(500)]
    assert _matched(noise, ['lumenfield']) == []
    real = [f'lumenfield-{i:03d}.test' for i in range(PHISHING_DB_MAX_EMISSIONS + 10)]
    # The gate itself returns ALL matches; truncation is the caller's bound,
    # and the caller reports it (swept_truncated) rather than dropping silently.
    assert len(_matched(real, ['lumenfield'])) == PHISHING_DB_MAX_EMISSIONS + 10
