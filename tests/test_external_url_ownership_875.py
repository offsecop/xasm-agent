"""
#875 — social-path ownership evidence: carry HikerAPI `external_url` through
`build_account`, and bucket an account whose profile website resolves to one of
the monitor's `ownedDomains` as LEGIT (own/affiliate) so the agent-side verdict
agrees with the backend's `profile_links_owned_domain` INFO override.

Binds to:
  - build_account()      — agent/lib/wrapper_helpers.py
  - classify_account()   — agent/lib/wrapper_helpers.py (owned_domains kwarg)
  - registrable_domain() — agent/lib/wrapper_helpers.py

Synthetic-data principle: fictitious brand `lumenfield` and `.test` domains only.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from lib.wrapper_helpers import (  # noqa: E402
    build_account,
    classify_account,
    registrable_domain,
    B_LEGIT,
    B_IMPERSONATOR,
)

BRAND = "lumenfield"
BRAND_HANDLE = "lumenfield"
OWNED = ["lumenfield.test", "https://www.lumenfield.test"]


# --- build_account round-trips external_url -------------------------------

def test_build_account_preserves_external_url():
    acct = build_account(
        {"user": {"username": "lumen.official", "external_url": "https://www.lumenfield.test/store"}}
    )
    assert acct["external_url"] == "https://www.lumenfield.test/store"


def test_build_account_external_url_website_fallback():
    # HikerAPI lite shape sometimes ships `website` instead of `external_url`.
    acct = build_account({"username": "lumen", "website": "https://lumenfield.test"})
    assert acct["external_url"] == "https://lumenfield.test"


def test_build_account_external_url_absent_safe():
    # Vendor omits the field entirely → '' (never None / KeyError).
    acct = build_account({"user": {"username": "lumen"}})
    assert acct["external_url"] == ""
    # Also absent-safe on a non-dict raw.
    assert build_account("nope") == {}  # type: ignore[arg-type]


# --- registrable_domain matches backend `registrableDomain` (tldts) --------

def test_registrable_domain_strips_scheme_path_and_www():
    assert registrable_domain("https://www.lumenfield.test/store") == "lumenfield.test"
    assert registrable_domain("lumenfield-support.test") == "lumenfield-support.test"
    assert registrable_domain("ftp://a.b.example.com:8080/p?q=1") == "example.com"


def test_registrable_domain_rejects_bare_label_and_empty():
    assert registrable_domain("localhost") == ""
    assert registrable_domain("") == ""
    assert registrable_domain(None) == ""


# --- classify_account owned-domain gate -----------------------------------

def test_precision_owned_domain_is_legit():
    """external_url in ownedDomains → LEGIT (own/affiliate)."""
    acct = build_account(
        {"user": {"username": "lumen.storefront", "external_url": "https://www.lumenfield.test/store"}}
    )
    bucket, reason, _ = classify_account(
        acct, BRAND, BRAND_HANDLE, is_brand=True, owned_domains=OWNED
    )
    assert bucket == B_LEGIT
    assert "owned domain" in reason


def test_recall_non_owned_lookalike_still_fires():
    """A near-miss whose external_url is NOT owned must still be an impersonator."""
    acct = build_account(
        {"user": {"username": "lumenfield-support", "external_url": "https://lumenfield-support.test"}}
    )
    bucket, _, _ = classify_account(
        acct, BRAND, BRAND_HANDLE, is_brand=True, owned_domains=OWNED
    )
    assert bucket == B_IMPERSONATOR


def test_no_owned_domains_is_noop():
    """Absent ownedDomains → unchanged (pre-#875) verdict."""
    acct = build_account(
        {"user": {"username": "lumen.storefront", "external_url": "https://www.lumenfield.test/store"}}
    )
    with_owned, _, _ = classify_account(
        acct, BRAND, BRAND_HANDLE, is_brand=True, owned_domains=OWNED
    )
    without_owned, _, _ = classify_account(
        acct, BRAND, BRAND_HANDLE, is_brand=True, owned_domains=None
    )
    assert with_owned == B_LEGIT
    assert without_owned != B_LEGIT  # ownership signal was the only thing making it legit


def test_owned_gate_ignores_account_without_external_url():
    """An account with no external_url is untouched by the ownership gate."""
    acct = build_account({"user": {"username": "lumenfield.fan"}})
    bucket, _, _ = classify_account(
        acct, BRAND, BRAND_HANDLE, is_brand=True, owned_domains=OWNED
    )
    assert bucket != B_LEGIT
