"""#1200 — per-monitor custom TLDs for the TLD-swap technique.

Locks the MERGE semantics of `_tld_swap`: `custom_tlds` (the backend's
entropyConfig.customTlds, forwarded on the typosquat:detect job payload)
EXTENDS the built-in ALTERNATIVE_TLDS list — de-duplicated and dot-normalized
— it never REPLACES it. The pre-#1200 implementation silently swapped the
whole list out, which would have shrunk coverage for any monitor that added a
single ccTLD.

Fictitious brand only (lumenfield.test).
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from tools.typosquat_detect import ALTERNATIVE_TLDS, TyposquatDetectTool


class TestTldSwapCustomTldMerge:
    def setup_method(self):
        self.tool = TyposquatDetectTool()

    def _domains(self, custom_tlds=None):
        return {d for d, _ in self.tool._tld_swap('lumenfield', '.test', custom_tlds)}

    def test_default_list_used_without_custom_tlds(self):
        domains = self._domains()
        assert domains == {'lumenfield' + tld for tld in ALTERNATIVE_TLDS}

    def test_custom_tlds_extend_builtins(self):
        domains = self._domains(['.ca', '.co.uk'])
        # Custom entries present…
        assert 'lumenfield.ca' in domains
        assert 'lumenfield.co.uk' in domains
        # …and every built-in still generated (merge, NOT replace).
        for tld in ALTERNATIVE_TLDS:
            assert 'lumenfield' + tld in domains

    def test_custom_tlds_are_dot_normalized_and_lowercased(self):
        domains = self._domains(['ca', ' .CO.UK '])
        assert 'lumenfield.ca' in domains
        assert 'lumenfield.co.uk' in domains

    def test_no_duplicates_when_custom_overlaps_builtin(self):
        results = self.tool._tld_swap('lumenfield', '.test', ['.net', 'net', '.ca'])
        domains = [d for d, _ in results]
        assert len(domains) == len(set(domains))
        assert len(domains) == len(ALTERNATIVE_TLDS) + 1  # only .ca is new

    def test_original_tld_excluded_even_when_custom(self):
        # The monitor's own TLD never appears as a "swap" — including when the
        # operator redundantly lists it as a custom entry.
        domains = self._domains(['.test'])
        assert 'lumenfield.test' not in domains

    def test_non_string_entries_ignored(self):
        domains = self._domains([None, 42, '.ca', ''])
        assert 'lumenfield.ca' in domains
        assert len(domains) == len(ALTERNATIVE_TLDS) + 1
