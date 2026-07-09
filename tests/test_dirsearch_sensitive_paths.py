import os
import unittest

from tools import _dirsearch_base as base


class DirsearchSensitivePathsTests(unittest.TestCase):
    """#318: .git/ and .env must be in the dirsearch:* default discovery list."""

    def _entries(self):
        with open(base.SENSITIVE_PATHS_WORDLIST, "r", encoding="utf-8") as handle:
            return [line.strip() for line in handle if line.strip() and not line.startswith("#")]

    def test_baked_wordlist_exists_and_covers_git_and_env(self):
        self.assertTrue(os.path.exists(base.SENSITIVE_PATHS_WORDLIST))
        entries = self._entries()
        for required in (".env", ".env.local", ".git/HEAD", ".git/config"):
            self.assertIn(required, entries)

    def test_discover_extra_wordlists_includes_sensitive_paths_by_default(self):
        extras = base.discover_extra_wordlists({})
        self.assertTrue(any(p.endswith("sensitive-paths.txt") for p in extras))

    def test_sensitive_paths_can_be_disabled(self):
        extras = base.discover_extra_wordlists({"includeSensitivePaths": False})
        self.assertFalse(any(p.endswith("sensitive-paths.txt") for p in extras))

    def test_combined_wordlist_merges_sensitive_paths_with_base(self):
        # Simulate a base wordlist; the resolver must fold .env/.git into it.
        base_path = "/tmp/_xasm_test_base_wordlist.txt"
        with open(base_path, "w", encoding="utf-8") as handle:
            handle.write("admin\nlogin\nrobots.txt\n")
        try:
            effective, info = base.resolve_dirsearch_wordlist(
                default_wordlist=base_path, parameters={}, tool_label="test"
            )
            self.assertTrue(effective and os.path.exists(effective))
            with open(effective, "r", encoding="utf-8") as handle:
                merged = {line.strip() for line in handle}
            self.assertIn(".env", merged)
            self.assertIn(".git/HEAD", merged)
            self.assertIn("admin", merged)  # base preserved
        finally:
            os.remove(base_path)


if __name__ == "__main__":
    unittest.main()
