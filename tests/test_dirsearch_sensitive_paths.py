import os
import tempfile
import unittest
from unittest.mock import patch

from tools import _dirsearch_base as base


class DirsearchSensitivePathsTests(unittest.TestCase):
    """#318: .git/ and .env must be in the dirsearch:* default discovery list."""

    def _entries(self):
        with open(base.SENSITIVE_PATHS_WORDLIST, "r", encoding="utf-8") as handle:
            return [line.strip() for line in handle if line.strip() and not line.startswith("#")]

    def _route_entries(self):
        with open(base.SENSITIVE_ROUTES_WORDLIST, "r", encoding="utf-8") as handle:
            return [line.strip() for line in handle if line.strip() and not line.startswith("#")]

    def test_baked_wordlist_exists_and_covers_git_and_env(self):
        self.assertTrue(os.path.exists(base.SENSITIVE_PATHS_WORDLIST))
        entries = self._entries()
        for required in (".env", ".env.local", ".git/HEAD", ".git/config"):
            self.assertIn(required, entries)

    def test_discover_extra_wordlists_includes_sensitive_paths_by_default(self):
        extras = base.discover_extra_wordlists({})
        self.assertTrue(any(p.endswith("sensitive-paths.txt") for p in extras))
        self.assertTrue(any(p.endswith("sensitive-routes.txt") for p in extras))

    def test_sensitive_paths_can_be_disabled(self):
        extras = base.discover_extra_wordlists({"includeSensitivePaths": False})
        self.assertFalse(any(p.endswith("sensitive-paths.txt") for p in extras))

    def test_sensitive_routes_are_bounded_and_generic(self):
        entries = self._route_entries()
        self.assertLessEqual(len(entries), 64)
        for required in (
            "debug/users",
            "internal/config",
            "diagnostics/status",
            "admin/settings",
        ):
            self.assertIn(required, entries)

    def test_sensitive_routes_can_be_disabled(self):
        extras = base.discover_extra_wordlists({"includeSensitiveRoutes": False})
        self.assertFalse(any(p.endswith("sensitive-routes.txt") for p in extras))

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

    def test_quick_resolver_uses_official_list_when_container_has_no_common_copy(self):
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as handle:
            handle.write("admin\nlogin\nusers\n")
            downloaded = handle.name
        try:
            with patch.object(base, "_first_common_wordlist", return_value=None), patch.object(
                base, "ensure_dicc_wordlist", return_value=downloaded
            ) as ensure:
                effective, info = base.resolve_dirsearch_wordlist(
                    parameters={},
                    tool_label="test",
                    prefer_common_wordlist=True,
                )

            ensure.assert_called_once_with("test")
            self.assertEqual(info["base_wordlist"], downloaded)
            with open(effective, "r", encoding="utf-8") as handle:
                merged = {line.strip() for line in handle}
            self.assertIn("users", merged)
            self.assertIn(".git/HEAD", merged)
            self.assertIn("debug/users", merged)
        finally:
            os.remove(downloaded)


if __name__ == "__main__":
    unittest.main()
