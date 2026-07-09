"""Tests for the UTS #39 confusables skeleton normalizer (agent/lib/confusables.py).

Ref: docs/drp-dorks-permutations-gap-analysis.md (G2). Shared dependency for the
certstream matcher (#448 G3a) and social display-name detection (#455 G6).
"""
import codecs

from lib import confusables
from lib.confusables import (
    is_confusable_with,
    is_mixed_script,
    is_whole_script_confusable,
    scripts_in,
    skeleton,
)


def test_version_pinned_and_offline():
    # Snapshot loads from the vendored file with no network and the version is pinned.
    assert confusables.CONFUSABLES_VERSION == confusables.EXPECTED_CONFUSABLES_VERSION


def test_cyrillic_homoglyph_paypal():
    # All-Cyrillic-but-l rendering of "paypal": р а у р а + Latin l.
    cyr = "раураl"  # раураl
    assert skeleton("paypal") == skeleton(cyr)
    assert is_confusable_with("paypal", cyr)


def test_greek_lookalikes_map_to_latin_prototype():
    # Greek omicron/alpha/rho/nu each collapse to their Latin prototype.
    assert skeleton("ο") == "o"  # ο
    assert skeleton("α") == "a"  # α
    assert skeleton("ρ") == "p"  # ρ
    assert skeleton("ν") == "v"  # ν


def test_armenian_and_cherokee_single_char_lookalikes():
    # Cherokee Ꭰ (U+13A0) is a known Latin 'D' confusable (previously missed).
    assert is_confusable_with("Ꭰ", "D")  # Ꭰ
    # Armenian օ (U+0585) confuses with Latin 'o'.
    assert is_confusable_with("օ", "o")


def test_fullwidth_block_normalizes():
    # Fullwidth Latin small a (U+FF41) maps to ASCII a (math/fullwidth evasion).
    assert skeleton("ａpple") == skeleton("apple")


def test_multichar_confusable_rn_to_m():
    # confusables.txt carries the prototype mapping m -> r n, so the multi-char
    # homoglyph "rn" is confusable with "m" under standard UTS #39 skeleton.
    # (Documented chosen behaviour: skeleton folds 'm' to 'rn', not the reverse.)
    assert skeleton("m") == "rn"
    assert skeleton("rn") == "rn"
    assert is_confusable_with("rn", "m")
    assert is_confusable_with("modern", "rnodern")


def test_punycode_decoded_whole_script_homograph():
    # The classic IDN homograph: xn--80ak6aa92e decodes to all-Cyrillic "аррӏе".
    decoded = codecs.decode("80ak6aa92e".encode("ascii"), "punycode")
    assert decoded == "аррӏе"
    # It is a single (Cyrillic) script — NOT mixed-script, so the mixed-script
    # heuristic alone would miss it; whole-script detection catches it. Its
    # skeleton is "appie" (palochka U+04CF maps to i), demonstrating the decode +
    # skeleton mechanics the certstream matcher (#448) relies on.
    assert scripts_in(decoded) == {"CYRILLIC"}
    assert skeleton(decoded) == "appie"
    assert is_whole_script_confusable(decoded, "appie")


def test_whole_script_confusable_all_cyrillic():
    # An all-Cyrillic rendering of "papa" (р а р а) is whole-script confusable.
    cyr = "рара"  # рара
    assert scripts_in(cyr) == {"CYRILLIC"}
    assert is_whole_script_confusable(cyr, "papa")
    # A plain Latin string is the same script as its target -> not whole-script.
    assert not is_whole_script_confusable("papa", "papa")


def test_mixed_script_detection():
    # One Cyrillic 'а' inside an otherwise-Latin string flags mixed-script.
    assert is_mixed_script("paypаl")  # paypаl
    # Pure ASCII is single-script.
    assert not is_mixed_script("paypal")
    # Digits / hyphens / dots are script-neutral and never trigger it.
    assert not is_mixed_script("pay-pal-2026.com")


def test_skeleton_empty_and_idempotent():
    assert skeleton("") == ""
    once = skeleton("paypal")
    assert skeleton(once) == once
