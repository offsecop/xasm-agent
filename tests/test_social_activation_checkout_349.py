"""#349 cost-safety regression guard.

The four newly-activated ScrapeCreators keyword-discovery tools plus the
twitterapi pattern-scan tool are PAID per-tenant external-vendor calls. Per the
CLAUDE.md provider-quota contract, every such call MUST checkout a lease before
the call and reconcile after, so the per-tenant daily/monthly cap + circuit
breaker apply. This test pins that invariant at the SOURCE level: each tool file
must contain BOTH `checkout_provider(` and `reconcile_call(`, so a future edit
cannot silently drop the cap (which would risk a provider ban at scale).

Source-grep (not import) on purpose: it is fast, has no aiohttp/network
dependency, and fails loudly the moment the lease/reconcile seam is removed —
exactly the regression we are guarding.
"""
import os

AGENT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TOOLS_DIR = os.path.join(AGENT_DIR, "tools")

# The activation #349 paid-vendor tools (4 ScrapeCreators search tools + the
# twitterapi pattern-scan tool the brand-level X sweep fans out over).
COST_GUARDED_TOOLS = [
    "scrapecreators_tiktok_search.py",
    "scrapecreators_threads_search.py",
    "scrapecreators_youtube_search.py",
    "scrapecreators_reddit_search.py",
    "twitterapi_pattern.py",
]


def _read(tool_file: str) -> str:
    path = os.path.join(TOOLS_DIR, tool_file)
    assert os.path.exists(path), f"expected tool file missing: {path}"
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


import pytest

# #1143 — the four SC keyword-search tools now route EVERY vendor call through
# the shared bounded-pagination loop in lib/sc_paginated_search.py, which owns
# the checkout→call→reconcile seam (one lease per page). A tool satisfies the
# cost guard either directly (twitterapi_pattern.py) or via that shared seam.
SHARED_QUOTA_SEAM = "paginated_sc_search("
SHARED_QUOTA_LIB = os.path.join(AGENT_DIR, "lib", "sc_paginated_search.py")


def _uses_quota_seam(src: str, marker: str) -> bool:
    return marker in src or SHARED_QUOTA_SEAM in src


@pytest.mark.parametrize("tool_file", COST_GUARDED_TOOLS)
def test_tool_checks_out_provider_lease(tool_file: str):
    src = _read(tool_file)
    assert _uses_quota_seam(src, "checkout_provider("), (
        f"{tool_file} must call checkout_provider() (directly or via the shared "
        f"paginated_sc_search seam) before any paid vendor call "
        f"(#349 per-tenant cap regression guard)."
    )


@pytest.mark.parametrize("tool_file", COST_GUARDED_TOOLS)
def test_tool_reconciles_call(tool_file: str):
    src = _read(tool_file)
    assert _uses_quota_seam(src, "reconcile_call("), (
        f"{tool_file} must call reconcile_call() (directly or via the shared "
        f"paginated_sc_search seam) after the vendor call so the per-tenant "
        f"quota ledger stays accurate (#349 cost-safety regression guard)."
    )


def test_shared_pagination_lib_owns_both_seams():
    """The shared loop itself must checkout AND reconcile — otherwise the
    per-tool delegation above would be vacuous."""
    assert os.path.exists(SHARED_QUOTA_LIB), SHARED_QUOTA_LIB
    with open(SHARED_QUOTA_LIB, "r", encoding="utf-8") as fh:
        lib_src = fh.read()
    assert "checkout_provider(" in lib_src
    assert "reconcile_call(" in lib_src
