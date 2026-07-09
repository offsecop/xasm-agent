"""Correctness lock for the #576 length pre-filter.

The generation path rejects a candidate before running the O(L²) Damerau matrix
when its minimum length gap to any original domain already exceeds
maxEditDistance. This is only valid because damerau(a,b) >= |len(a)-len(b)|, so
such a candidate could never satisfy `min_dist <= maxEditDistance`. These tests
pin that the optimized filter produces the EXACT same surviving set as the
unfiltered Damerau path, and that every length-skipped candidate really is
un-keepable.
"""
import itertools
import string

from tools.typosquat_detect import TyposquatDetectTool


DL = TyposquatDetectTool._damerau_levenshtein


def _pure_damerau_filter(domain_list, candidates, max_edit_distance):
    """The pre-#576 behaviour: keep iff min Damerau distance <= threshold."""
    keep = []
    for var in candidates:
        if min(DL(d, var) for d in domain_list) <= max_edit_distance:
            keep.append(var)
    return keep


def _length_prefiltered(domain_list, candidates, max_edit_distance):
    """The #576 behaviour: length pre-check, then Damerau only when it could pass."""
    keep = []
    skipped_by_length = []
    for var in candidates:
        if min(abs(len(d) - len(var)) for d in domain_list) > max_edit_distance:
            skipped_by_length.append(var)
            continue
        if min(DL(d, var) for d in domain_list) <= max_edit_distance:
            keep.append(var)
    return keep, skipped_by_length


def _corpus():
    """A deterministic, varied candidate corpus (lengths from 2 to ~20)."""
    domain_list = ['lumenfield', 'sol', 'modeapparel']
    alphabet = string.ascii_lowercase[:8] + '-0'
    cands = set()
    # short + long strings, plus near-misses of the originals
    for length in range(2, 21):
        cands.add((alphabet * 3)[:length])
    for d in domain_list:
        cands.add(d)
        cands.add(d + 'x')
        cands.add(d[:-1])
        cands.add('x' + d)
        cands.add(d.replace(d[0], d[1], 1) if len(d) > 1 else d)
    for a, b in itertools.product('abc', repeat=2):
        cands.add(a + 'lumen' + b)
    return domain_list, sorted(cands)


def test_length_prefilter_output_identical_across_thresholds():
    domain_list, candidates = _corpus()
    for max_edit_distance in range(0, 8):
        expected = _pure_damerau_filter(domain_list, candidates, max_edit_distance)
        got, skipped = _length_prefiltered(domain_list, candidates, max_edit_distance)
        assert got == expected, f"mismatch at maxEditDistance={max_edit_distance}"
        # Every length-skipped candidate would truly have been rejected by Damerau.
        for var in skipped:
            assert min(DL(d, var) for d in domain_list) > max_edit_distance


def test_length_lower_bounds_damerau():
    """The property the pre-filter relies on: damerau(a,b) >= |len(a)-len(b)|."""
    _, candidates = _corpus()
    for a, b in itertools.product(candidates[:25], repeat=2):
        assert DL(a, b) >= abs(len(a) - len(b))
