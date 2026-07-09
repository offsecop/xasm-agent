"""
agent/tools/_taxonomy.py

Canonical tool-taxonomy vocabulary + derivation/validation helpers (issue #559).

This module is the SINGLE SOURCE OF TRUTH for the canonical taxonomy dimensions
layered on top of the legacy plugin ``metadata`` triple
(``category: str``, ``phase: int``, ``domain: list[str]``).

Canonical dimensions (ADDITIVE — the legacy keys are left untouched so persona
dispatch filters in the backend keep matching on ``category``):

  - ``taxonomy_domain``   : canonical domain bucket(s) the tool operates on
  - ``lifecycle_phase``   : canonical kill-chain phase
  - ``purpose_count``     : "single" | "multi"
  - ``primary_purpose``   : one-line human capability summary
  - ``secondary_purposes``: list[{mode, purpose}]  (multi-purpose tools only)
  - ``alias_of``          : (optional) another tool name this one aliases

Tools MAY declare these explicitly. Un-enriched tools have the fields backfilled
from the legacy triple by :func:`derive_canonical`, so every tool is covered with
no 91-file edit. The generator (``agent/scripts/generate_tool_taxonomy.py``)
merges explicit keys over the derived ones via :func:`merge_canonical` and then
runs :func:`validate`.
"""
from __future__ import annotations

from typing import Any, Dict, List

# --------------------------------------------------------------------------- #
# Canonical vocabularies
# --------------------------------------------------------------------------- #
CANONICAL_DOMAINS = frozenset(
    {"web", "infra", "api", "osint", "dns", "brand-drp", "code", "meta"}
)

CANONICAL_PHASES = frozenset(
    {
        "recon-passive",
        "recon-active",
        "discovery",
        "assessment",
        "scan",
        "exploit-test",
        "post-exploit",
        "enrichment",
        "auth",
        "reporting",
        "orchestration",
    }
)

PURPOSE_COUNTS = frozenset({"single", "multi"})

# Sort/UX hint only — NOT a dispatch key.
PHASE_ORDINAL: Dict[str, int] = {
    "auth": -1,
    "recon-passive": 0,
    "recon-active": 1,
    "discovery": 2,
    "assessment": 3,
    "scan": 4,
    "exploit-test": 5,
    "post-exploit": 6,
    "enrichment": 7,
    "reporting": 8,
    "orchestration": 9,
}

# --------------------------------------------------------------------------- #
# Derivation maps (legacy -> canonical)
# --------------------------------------------------------------------------- #
# (legacy category, str(legacy phase)) -> canonical lifecycle_phase.
# Covers every (category, phase) pair present in agent/tools as of #559.
CATEGORY_PHASE_TO_LIFECYCLE: Dict[tuple, str] = {
    ("agentic-recon", "2"): "discovery",
    ("agentic-recon", "3"): "assessment",
    ("agentic-recon", "4"): "assessment",
    ("agentic-recon", "5"): "exploit-test",
    ("auth", "0"): "auth",
    ("brand", "0"): "discovery",
    ("brand", "3"): "recon-active",
    ("brand", "4"): "enrichment",
    ("browser-dast", "4"): "scan",
    ("discovery", "2"): "discovery",
    ("drp_discovery", "5"): "recon-active",
    ("drp_enrichment", "6"): "enrichment",
    ("enrichment", "2"): "enrichment",
    ("enumeration", "3"): "discovery",
    ("exploit", "5"): "exploit-test",
    ("exploit-test", "4"): "exploit-test",
    ("exploit-test", "5"): "exploit-test",
    ("http.sequence", "3"): "assessment",
    ("recon", "1"): "recon-passive",
    ("recon", "2"): "recon-active",
    ("sca-web", "3"): "scan",
    ("screenshot", "3"): "enrichment",
    ("social-intelligence", "discovery"): "discovery",
    ("social-intelligence", "evidence-capture"): "enrichment",
    ("vuln-scan", "2"): "scan",
    ("vuln-scan", "3"): "scan",
    ("vuln-scan", "4"): "scan",
}

# Fallback by category alone (also covers backend-only code.* registry tools that
# have no agent/tools/*.py file).
CATEGORY_TO_LIFECYCLE: Dict[str, str] = {
    "recon": "recon-passive",
    "discovery": "discovery",
    "enumeration": "discovery",
    "enrichment": "enrichment",
    "agentic-recon": "discovery",
    "vuln-scan": "scan",
    "sca-web": "scan",
    "browser-dast": "scan",
    "exploit-test": "exploit-test",
    "exploit": "exploit-test",
    "auth": "auth",
    "screenshot": "enrichment",
    "brand": "recon-active",
    "drp_discovery": "recon-active",
    "drp_enrichment": "enrichment",
    "social-intelligence": "discovery",
    "http.sequence": "assessment",
    "code.read": "recon-active",
    "code.search": "recon-active",
    "code.surface": "recon-active",
    "code.xref": "recon-active",
    "code.deps": "recon-active",
    "code.history": "recon-active",
    "code.analysis": "assessment",
    "code.taint": "assessment",
    "code.secrets": "recon-passive",
}

# legacy domain token -> canonical domain. ``None`` marks a toolchain *qualifier*
# (not a real domain) that is dropped when a real domain co-occurs.
DOMAIN_TOKEN_TO_CANONICAL: Dict[str, Any] = {
    "web": "web",
    "javascript": "web",
    "dast": "web",
    "phishing": "web",
    "infra": "infra",
    "infrastructure": "infra",
    "cloud": "infra",
    "ssl": "infra",
    "cve": "infra",
    "api": "api",
    "osint": "osint",
    "social": "osint",
    "threat_intelligence": "osint",
    "darkweb": "osint",
    "dns": "dns",
    "brand-drp": "brand-drp",
    "brand_protection": "brand-drp",
    "brand-monitor": "brand-drp",
    "brand": "brand-drp",
    "drp": "brand-drp",
    "vip": "brand-drp",
    "ads": "brand-drp",
    "code": "code",
    "CODE": "code",
    # qualifiers (dropped when a real domain is present)
    "sca": None,
    "origami": None,
    "secrets": None,
}

# scalar primary-domain priority (first match wins for ``taxonomyDomain``)
DOMAIN_PRIORITY: List[str] = [
    "code",
    "api",
    "web",
    "dns",
    "infra",
    "brand-drp",
    "osint",
    "meta",
]

# Pure-orchestration tools with no single target domain.
NAME_OVERRIDES: Dict[str, Dict[str, Any]] = {
    "decision:plan_next": {
        "taxonomy_domain": ["meta"],
        "lifecycle_phase": "orchestration",
    },
    "decision:exploitation_queue": {
        "taxonomy_domain": ["meta"],
        "lifecycle_phase": "orchestration",
    },
    "surface:graph": {
        "taxonomy_domain": ["meta"],
        "lifecycle_phase": "orchestration",
    },
}

# Human-readable labels for the auto-composed primary_purpose.
DOMAIN_LABEL: Dict[str, str] = {
    "web": "web",
    "infra": "infrastructure",
    "api": "API",
    "osint": "OSINT",
    "dns": "DNS",
    "brand-drp": "brand/DRP",
    "code": "code",
    "meta": "workflow",
}
PHASE_LABEL: Dict[str, str] = {
    "recon-passive": "passive recon",
    "recon-active": "active recon",
    "discovery": "discovery/enumeration",
    "assessment": "assessment",
    "scan": "vulnerability scan",
    "exploit-test": "exploitation test",
    "post-exploit": "post-exploitation",
    "enrichment": "enrichment",
    "auth": "authentication",
    "reporting": "reporting",
    "orchestration": "orchestration",
}

# Canonical taxonomy keys (the additive surface).
CANONICAL_KEYS = (
    "taxonomy_domain",
    "lifecycle_phase",
    "purpose_count",
    "primary_purpose",
    "secondary_purposes",
    "alias_of",
)


def _canonical_domains(meta: Dict[str, Any]) -> List[str]:
    """Map the legacy ``domain`` token list to canonical domains, priority-ordered."""
    raw = meta.get("domain") or []
    if isinstance(raw, str):
        raw = [raw]
    mapped: List[str] = []
    for tok in raw:
        canon = DOMAIN_TOKEN_TO_CANONICAL.get(
            tok, DOMAIN_TOKEN_TO_CANONICAL.get(str(tok).lower(), "__unknown__")
        )
        if canon in (None, "__unknown__"):
            continue  # qualifier or unknown token
        if canon not in mapped:
            mapped.append(canon)
    if not mapped:
        # Only qualifiers / unknown tokens — these are all web/code scanners.
        mapped = ["web"]
    mapped.sort(
        key=lambda d: DOMAIN_PRIORITY.index(d) if d in DOMAIN_PRIORITY else 99
    )
    return mapped


def derive_canonical(name: str, meta: Dict[str, Any]) -> Dict[str, Any]:
    """Backfill canonical taxonomy fields from the legacy (category, phase, domain)
    triple. Explicit canonical keys present on ``meta`` are NOT applied here — the
    caller layers them on top via :func:`merge_canonical`."""
    override = NAME_OVERRIDES.get(name, {})
    domains = override.get("taxonomy_domain") or _canonical_domains(meta)
    category = meta.get("category")
    phase = meta.get("phase")
    lifecycle = (
        override.get("lifecycle_phase")
        or CATEGORY_PHASE_TO_LIFECYCLE.get((category, str(phase)))
        or CATEGORY_TO_LIFECYCLE.get(category)
        or "discovery"
    )
    primary_domain = domains[0]
    primary_purpose = (
        f"{DOMAIN_LABEL.get(primary_domain, primary_domain)} "
        f"{PHASE_LABEL.get(lifecycle, lifecycle)}"
    )
    return {
        "taxonomy_domain": domains,
        "lifecycle_phase": lifecycle,
        "purpose_count": "single",
        "primary_purpose": primary_purpose,
        "secondary_purposes": [],
    }


def merge_canonical(name: str, meta: Dict[str, Any]) -> Dict[str, Any]:
    """Return the derived canonical fields with any explicit (hand-authored) keys
    layered on top. Explicit keys always win."""
    out = derive_canonical(name, meta)
    for key in CANONICAL_KEYS:
        if key in meta and meta[key] not in (None, [], ""):
            out[key] = meta[key]
    return out


def validate(name: str, meta: Dict[str, Any]) -> List[str]:
    """Validate the MERGED canonical fields. Returns a list of human-readable
    errors ([] == valid). Alias tools are exempt (they inherit target taxonomy)."""
    errors: List[str] = []
    if meta.get("alias_of"):
        return errors

    domains = meta.get("taxonomy_domain")
    if not isinstance(domains, list) or not domains:
        errors.append(f"{name}: taxonomy_domain must be a non-empty list")
    else:
        for dom in domains:
            if dom not in CANONICAL_DOMAINS:
                errors.append(
                    f"{name}: taxonomy_domain '{dom}' not in CANONICAL_DOMAINS"
                )

    phase = meta.get("lifecycle_phase")
    if phase not in CANONICAL_PHASES:
        errors.append(f"{name}: lifecycle_phase '{phase}' not in CANONICAL_PHASES")

    count = meta.get("purpose_count")
    if count not in PURPOSE_COUNTS:
        errors.append(f"{name}: purpose_count '{count}' not in {{single, multi}}")

    purpose = meta.get("primary_purpose")
    if not isinstance(purpose, str) or not purpose.strip():
        errors.append(f"{name}: primary_purpose must be a non-empty string")

    secondary = meta.get("secondary_purposes", [])
    if count == "multi":
        if not isinstance(secondary, list) or len(secondary) < 2:
            errors.append(
                f"{name}: purpose_count='multi' requires >=2 secondary_purposes"
            )
        else:
            for entry in secondary:
                if (
                    not isinstance(entry, dict)
                    or not entry.get("mode")
                    or not entry.get("purpose")
                ):
                    errors.append(
                        f"{name}: each secondary_purpose needs a non-empty mode + purpose"
                    )
    return errors


# --------------------------------------------------------------------------- #
# Registry sync (#559 follow-up) — map plugin metadata onto the backend
# ToolRegistryEntry dispatch fields, using ONLY the existing persona-filter
# category vocabulary so adding a tool never introduces a new dispatch key.
# --------------------------------------------------------------------------- #
# The 22 categories the personas' allowedToolFilters already reference. New
# registry rows MUST use one of these (asserted by the generator + the jest lock).
REGISTRY_CATEGORIES = frozenset(
    {
        "agentic-recon",
        "auth",
        "brand",
        "code.analysis",
        "code.deps",
        "code.history",
        "code.read",
        "code.search",
        "code.secrets",
        "code.surface",
        "code.taint",
        "code.xref",
        "dast",
        "dast-web",
        "exploit-test",
        "http.sequence",
        "osint",
        "recon",
        "recon-infra",
        "recon-passive",
        "recon-web",
        "sca-web",
    }
)

# plugin category -> registry category. `enumeration`/`recon`/`screenshot` are
# refined by domain below.
PLUGIN_TO_REGISTRY_CATEGORY: Dict[str, str] = {
    "vuln-scan": "dast",
    "browser-dast": "dast",
    "exploit-test": "exploit-test",
    "exploit": "exploit-test",
    "agentic-recon": "agentic-recon",
    "sca-web": "sca-web",
    "auth": "auth",
    "http.sequence": "http.sequence",
    "brand": "brand",
    "drp_discovery": "osint",
    "drp_enrichment": "osint",
    "social-intelligence": "osint",
    "discovery": "recon-web",
    "enrichment": "recon-passive",
}

# category -> default risk level (matches the curated seed convention).
REGISTRY_RISK_BY_CATEGORY: Dict[str, str] = {
    "exploit-test": "MEDIUM",
    "dast": "MEDIUM",
    "dast-web": "MEDIUM",
    "agentic-recon": "MEDIUM",
    "recon": "LOW",
    "recon-web": "LOW",
    "recon-infra": "LOW",
    "recon-passive": "LOW",
    "osint": "LOW",
    "brand": "LOW",
    "auth": "LOW",
    "sca-web": "LOW",
    "http.sequence": "LOW",
}


def registry_category(plugin_category: Any, taxonomy_domains: List[str]) -> str:
    """Map a plugin `category` (+ canonical domains) to a registry category from
    the existing persona-filter vocabulary."""
    mapped = PLUGIN_TO_REGISTRY_CATEGORY.get(plugin_category)
    if mapped:
        return mapped
    infra = any(d in ("infra", "dns") for d in taxonomy_domains)
    if plugin_category == "enumeration":
        return "recon-infra" if infra else "recon-web"
    if plugin_category == "screenshot":
        return "recon-infra" if infra else "recon-web"
    if plugin_category == "recon":
        if "osint" in taxonomy_domains:
            return "osint"
        return "recon-infra" if infra else "recon-web"
    if isinstance(plugin_category, str) and plugin_category.startswith("code."):
        return plugin_category if plugin_category in REGISTRY_CATEGORIES else "code.read"
    return "recon-web"  # safe in-vocabulary fallback


def registry_risk(reg_category: str) -> str:
    return REGISTRY_RISK_BY_CATEGORY.get(reg_category, "LOW")


def display_name_for(tool_name: str) -> str:
    """`nuclei:critical_scan` -> `Nuclei Critical Scan`."""
    parts = tool_name.replace(":", " ").replace("_", " ").replace(".", " ").split()
    return " ".join(w[:1].upper() + w[1:] for w in parts if w)


def to_registry_entry(merged: Dict[str, Any]) -> Dict[str, Any]:
    """Map a MERGED canonical dict to the backend ToolRegistryEntry JSON shape
    (camelCase). The single source of the canonical -> registry field mapping,
    shared by the generator and the freshness test."""
    domains = merged.get("taxonomy_domain") or ["web"]
    return {
        "taxonomyDomain": domains[0],
        "taxonomyDomains": domains,
        "lifecyclePhase": merged.get("lifecycle_phase"),
        "purposeCount": merged.get("purpose_count"),
        "primaryPurpose": merged.get("primary_purpose"),
        "secondaryPurposes": merged.get("secondary_purposes", []),
    }
