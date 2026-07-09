"""#559 — tool-taxonomy canonical-vocabulary + generated-artifact locks.

Two layers:
  1. Unit tests for the derivation/validation logic in tools/_taxonomy.py.
  2. Locks on the committed artifact
     (backend/prisma/seeds/tool-taxonomy.generated.json) — every entry canonical,
     multi-purpose entries enumerate >=2 modes, the flagship Nessus example carries
     its infra + web (WAS) modes.

Runs on the HOST (matches the other pytest agent tests; no plugin deps needed):
    python3 -m pytest agent/tests/test_tool_taxonomy.py
The complementary "every live plugin's source metadata validates" gate is the
generator itself (agent/scripts/generate_tool_taxonomy.py exits non-zero on any
validation error, and --check guarantees the artifact is fresh vs the plugins).
"""
import json
import os
import sys

import pytest

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
AGENT_DIR = os.path.dirname(THIS_DIR)
REPO_ROOT = os.path.dirname(AGENT_DIR)
sys.path.insert(0, os.path.join(AGENT_DIR, "tools"))

import _taxonomy  # noqa: E402

GENERATED_JSON = os.path.join(
    REPO_ROOT, "backend", "prisma", "seeds", "tool-taxonomy.generated.json"
)
SUPPLEMENT_JSON = os.path.join(AGENT_DIR, "tools", "_taxonomy_platform_supplement.json")

KNOWN_MULTI = {
    "scrapecreators:reddit_search",
    "scrapecreators:threads_search",
    "scrapecreators:tiktok_search",
    "scrapecreators:youtube_search",
    "api:access_control_probe",
    "nessus:launch_scan",
}


# --------------------------------------------------------------------------- #
# Layer 1 — derivation / validation logic
# --------------------------------------------------------------------------- #
def test_derive_qualifier_only_domain_falls_back_to_web():
    merged = _taxonomy.derive_canonical("sca:retirejs_scan", {"category": "sca-web", "phase": 3, "domain": ["sca"]})
    assert merged["taxonomy_domain"] == ["web"]
    assert merged["lifecycle_phase"] == "scan"


def test_derive_string_phase_social_intelligence():
    merged = _taxonomy.derive_canonical(
        "scrapecreators:foo", {"category": "social-intelligence", "phase": "discovery", "domain": ["drp"]}
    )
    assert merged["lifecycle_phase"] == "discovery"
    assert merged["taxonomy_domain"] == ["brand-drp"]


def test_derive_name_override_orchestration():
    merged = _taxonomy.derive_canonical("decision:plan_next", {"category": "agentic-recon", "phase": 2, "domain": ["web", "api"]})
    assert merged["taxonomy_domain"] == ["meta"]
    assert merged["lifecycle_phase"] == "orchestration"


def test_domain_priority_orders_scalar():
    merged = _taxonomy.derive_canonical("api:probe", {"category": "agentic-recon", "phase": 4, "domain": ["web", "api"]})
    assert merged["taxonomy_domain"][0] == "api"  # api outranks web


def test_validate_rejects_unknown_domain_and_phase():
    bad = {"taxonomy_domain": ["nope"], "lifecycle_phase": "wat", "purpose_count": "single", "primary_purpose": "x"}
    errs = _taxonomy.validate("t:bad", bad)
    assert any("taxonomy_domain" in e for e in errs)
    assert any("lifecycle_phase" in e for e in errs)


def test_validate_multi_requires_two_modes():
    bad = {"taxonomy_domain": ["web"], "lifecycle_phase": "scan", "purpose_count": "multi",
           "primary_purpose": "x", "secondary_purposes": [{"mode": "a", "purpose": "b"}]}
    assert any("secondary_purposes" in e for e in _taxonomy.validate("t:bad", bad))


def test_validate_alias_is_exempt():
    assert _taxonomy.validate("t:alias", {"alias_of": "t:real"}) == []


def test_merge_explicit_keys_win():
    meta = {
        "category": "vuln-scan", "phase": 4, "domain": ["web"],
        "purpose_count": "multi",
        "secondary_purposes": [{"mode": "a", "purpose": "x"}, {"mode": "b", "purpose": "y"}],
        "primary_purpose": "hand-authored",
    }
    merged = _taxonomy.merge_canonical("t:x", meta)
    assert merged["purpose_count"] == "multi"
    assert merged["primary_purpose"] == "hand-authored"
    assert len(merged["secondary_purposes"]) == 2
    assert _taxonomy.validate("t:x", merged) == []


def test_to_registry_entry_shape():
    entry = _taxonomy.to_registry_entry(
        {"taxonomy_domain": ["api", "web"], "lifecycle_phase": "assessment",
         "purpose_count": "single", "primary_purpose": "p", "secondary_purposes": []}
    )
    assert entry == {
        "taxonomyDomain": "api",
        "taxonomyDomains": ["api", "web"],
        "lifecyclePhase": "assessment",
        "purposeCount": "single",
        "primaryPurpose": "p",
        "secondaryPurposes": [],
    }


# --------------------------------------------------------------------------- #
# Layer 2 — committed generated artifact
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def generated():
    if not os.path.exists(GENERATED_JSON):
        pytest.skip("tool-taxonomy.generated.json not present (run the generator)")
    return json.load(open(GENERATED_JSON))


def test_generated_covers_full_tool_set(generated):
    # 91 agent tools + >=1 platform supplement tool.
    assert len(generated) >= 92, f"expected >=92 taxonomy entries, got {len(generated)}"


def test_generated_every_entry_is_canonical(generated):
    for name, entry in generated.items():
        assert entry["lifecyclePhase"] in _taxonomy.CANONICAL_PHASES, f"{name}: phase"
        assert entry["taxonomyDomain"] in _taxonomy.CANONICAL_DOMAINS, f"{name}: domain"
        for dom in entry["taxonomyDomains"]:
            assert dom in _taxonomy.CANONICAL_DOMAINS, f"{name}: domains[{dom}]"
        assert entry["purposeCount"] in _taxonomy.PURPOSE_COUNTS, f"{name}: purposeCount"
        assert entry["primaryPurpose"], f"{name}: empty primaryPurpose"


def test_generated_multi_entries_enumerate_modes(generated):
    multi = {n: e for n, e in generated.items() if e["purposeCount"] == "multi"}
    assert len(multi) >= 6, f"expected >=6 multi-purpose entries, got {len(multi)}"
    for name, entry in multi.items():
        modes = entry["secondaryPurposes"]
        assert len(modes) >= 2, f"{name}: multi needs >=2 modes"
        for mode in modes:
            assert mode.get("mode") and mode.get("purpose"), f"{name}: mode/purpose empty"


def test_known_multi_tools_are_multi(generated):
    for name in KNOWN_MULTI:
        assert name in generated, f"{name} missing from generated taxonomy"
        assert generated[name]["purposeCount"] == "multi", f"{name} should be multi"


def test_nessus_flagship_infra_and_was(generated):
    nessus = generated.get("nessus:launch_scan")
    assert nessus, "nessus:launch_scan missing"
    assert nessus["purposeCount"] == "multi"
    modes = {m["mode"] for m in nessus["secondaryPurposes"]}
    assert {"infra", "was"} <= modes, f"Nessus must enumerate infra + was, got {modes}"


def test_supplement_entries_valid():
    data = json.load(open(SUPPLEMENT_JSON))
    entries = {k: v for k, v in data.items() if not k.startswith("_")}
    assert entries
    for name, sup in entries.items():
        merged = {
            "taxonomy_domain": sup.get("taxonomyDomains") or [sup.get("taxonomyDomain")],
            "lifecycle_phase": sup.get("lifecyclePhase"),
            "purpose_count": sup.get("purposeCount", "single"),
            "primary_purpose": sup.get("primaryPurpose", ""),
            "secondary_purposes": sup.get("secondaryPurposes", []),
        }
        assert _taxonomy.validate(name, merged) == [], f"supplement '{name}' invalid"
