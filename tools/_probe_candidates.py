"""Shared candidate-collection contract and sweep harness for native probes (#1649).

The calibrated native probes were VERIFIERS, not detectors: each took a single
caller-named sink and fired one payload at it. `web:xxe_probe` is the whole of
it — one field, one payload, one request, with `endpointPath` and
`injectionField` required. The caller had to know where the vulnerability was
before running the tool that is supposed to find it. The clearest tell was
`expectedProbeStatus` being required: the caller had to declare the vulnerable
response's status code up front, which is only knowable after exploiting it.

The probes written BEFORE the calibration wave all sweep a candidate collection
and take exactly one required field:

    web_security_controls_probe          forms[], urls[]
    web_command_injection_timing_probe   endpoints[]
    web_file_upload_rce_probe            uploadPaths[], webrootCandidates[]

This module restores that shape as a shared contract, so a probe can accept
discovered request candidates and sweep them under the existing budget, scope
and approval seams.

THE CANDIDATE SHAPE
-------------------
Deliberately a lossless projection of the form dict that
`_agentic_exploration_common.extract_html_map` ALREADY emits and that
`param:discover`, `surface:graph` and `web:security_controls_probe` already
produce and consume — so neither the producer nor the consumer has to invent a
new format:

    {
      "url": "https://host/product/stock",   # absolute, same-origin
      "method": "POST",
      "contentType": "application/x-www-form-urlencoded",
      "fields": {"productId": "1", "storeId": "1"},   # name -> observed baseline
      "source": "browser:map_app"                     # provenance, for the trace
    }

`fields` is a name -> OBSERVED BASELINE VALUE map rather than a name list,
because every calibrated probe needs a benign control request before its attack
request, and the baseline value is exactly what makes that control meaningful.

No credentials ever travel in a candidate — session material stays on the
dispatcher's auth-session enrichment seam.
"""

from __future__ import annotations

from typing import Any, Awaitable, Callable, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

from tools._agentic_exploration_common import (
    dedupe_keep_order,
    extract_html_map,
    fetch_text,
    normalize_url,
    same_origin,
)

# Sweep bounds. Clamped, never trusted from the caller — an unbounded sweep on a
# large application is a self-inflicted denial of service against the target.
DEFAULT_MAX_CANDIDATES = 12
HARD_MAX_CANDIDATES = 40
DEFAULT_MAX_DISCOVERY_PAGES = 8
HARD_MAX_DISCOVERY_PAGES = 25
DEFAULT_REQUEST_BUDGET = 60
HARD_REQUEST_BUDGET = 240

# Never inject into a field whose name suggests it carries a credential, a CSRF
# token or session material. Mirrors the per-probe `_SENSITIVE_FIELD` guards.
SENSITIVE_FIELD_PATTERN = (
    "auth", "csrf", "token", "session", "cookie", "password", "passwd",
    "pass", "secret", "apikey", "api_key", "api-key",
)


def is_sensitive_field(name: str) -> bool:
    lowered = str(name or "").lower()
    return any(marker in lowered for marker in SENSITIVE_FIELD_PATTERN)


def _clamp(value: Any, default: int, hard_max: int) -> int:
    try:
        parsed = int(value) if value is not None else default
    except (TypeError, ValueError):
        parsed = default
    return max(1, min(parsed, hard_max))


def _candidate_key(candidate: Dict[str, Any]) -> Tuple[str, str, Tuple[str, ...]]:
    """Dedupe identity: same method + URL + field names is the same sink."""
    return (
        str(candidate.get("method") or "GET").upper(),
        str(candidate.get("url") or ""),
        tuple(sorted((candidate.get("fields") or {}).keys())),
    )


def normalize_candidate(
    raw: Any,
    base_url: str,
    *,
    source: str = "caller",
) -> Optional[Dict[str, Any]]:
    """Coerce one raw entry into the canonical candidate shape, or None.

    Accepts the canonical shape, the `extract_html_map` form dict
    (`{action, method, fields: [{name, type}], fieldCount}`), and a bare URL
    string. Anything off-origin or without an injectable field is dropped.
    """
    if isinstance(raw, str):
        url = normalize_url(urljoin(base_url, raw))
        if not same_origin(base_url, url):
            return None
        return {"url": url, "method": "GET", "contentType": "", "fields": {}, "source": source}

    if not isinstance(raw, dict):
        return None

    # `action` is the form-dict spelling; `url`/`endpointPath` the canonical one.
    raw_url = raw.get("url") or raw.get("action") or raw.get("endpointPath") or raw.get("endpoint")
    if not raw_url:
        return None
    url = normalize_url(urljoin(base_url, str(raw_url)))
    if not same_origin(base_url, url):
        return None

    fields: Dict[str, str] = {}
    raw_fields = raw.get("fields")
    if isinstance(raw_fields, dict):
        # Canonical: name -> observed baseline value.
        for name, value in raw_fields.items():
            if name and not is_sensitive_field(name):
                fields[str(name)] = "" if value is None else str(value)
    elif isinstance(raw_fields, list):
        # extract_html_map form dict: [{name, type}, ...]. No observed values,
        # so a benign default stands in for the control request.
        for field in raw_fields:
            if not isinstance(field, dict):
                continue
            name = field.get("name")
            if not name or is_sensitive_field(name):
                continue
            field_type = str(field.get("type") or "text").lower()
            if field_type in {"submit", "button", "image", "reset", "file"}:
                continue
            fields[str(name)] = str(field.get("value") or "1")

    method = str(raw.get("method") or ("POST" if fields else "GET")).upper()
    content_type = str(
        raw.get("contentType")
        or raw.get("enctype")
        or ("application/x-www-form-urlencoded" if method == "POST" else "")
    )
    return {
        "url": url,
        "method": method,
        "contentType": content_type,
        "fields": fields,
        "source": str(raw.get("source") or source),
    }


def normalize_candidates(
    parameters: Dict[str, Any],
    base_url: str,
    *,
    max_candidates: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """Build the sweep list from every input shape a producer might emit.

    Reads `candidates` (canonical), plus the raw `forms` / `urls` / `endpoints`
    arrays that discovery already ships, so nothing breaks if a producer has not
    been normalized yet. Deduped on (method, url, field names), order preserved
    so the highest-signal producer wins.
    """
    cap = _clamp(max_candidates or parameters.get("maxCandidates"), DEFAULT_MAX_CANDIDATES, HARD_MAX_CANDIDATES)
    collected: List[Dict[str, Any]] = []

    for key, default_source in (
        ("candidates", "caller"),
        ("forms", "forms"),
        ("endpoints", "endpoints"),
        ("urls", "urls"),
    ):
        raw_list = parameters.get(key)
        if not isinstance(raw_list, list):
            continue
        for raw in raw_list:
            candidate = normalize_candidate(raw, base_url, source=default_source)
            if candidate:
                collected.append(candidate)

    seen = set()
    unique: List[Dict[str, Any]] = []
    for candidate in collected:
        key = _candidate_key(candidate)
        if key in seen:
            continue
        seen.add(key)
        unique.append(candidate)
        if len(unique) >= cap:
            break
    return unique


async def discover_candidates(
    session: Any,
    base_url: str,
    *,
    headers: Optional[Dict[str, str]] = None,
    max_pages: Optional[int] = None,
    max_candidates: Optional[int] = None,
    seed_urls: Optional[Iterable[str]] = None,
) -> List[Dict[str, Any]]:
    """Bounded same-origin form discovery for when no candidates were supplied.

    This is what decouples a probe from the routing work: it can find its own
    sinks from a bare target, exactly as `web_security_controls_probe` does with
    `discoverFromTarget`. Routing then improves precision rather than being a
    hard dependency.
    """
    page_cap = _clamp(max_pages, DEFAULT_MAX_DISCOVERY_PAGES, HARD_MAX_DISCOVERY_PAGES)
    candidate_cap = _clamp(max_candidates, DEFAULT_MAX_CANDIDATES, HARD_MAX_CANDIDATES)

    queue: List[str] = [normalize_url(base_url)]
    for url in seed_urls or []:
        absolute = normalize_url(urljoin(base_url, str(url)))
        if same_origin(base_url, absolute):
            queue.append(absolute)
    queue = dedupe_keep_order(queue, page_cap * 4)

    visited: set = set()
    found: List[Dict[str, Any]] = []
    cursor = 0

    while cursor < len(queue) and len(visited) < page_cap and len(found) < candidate_cap:
        url = queue[cursor]
        cursor += 1
        if url in visited:
            continue
        visited.add(url)
        try:
            page = await fetch_text(session, url, headers=headers, max_bytes=400_000)
        except Exception:
            continue  # one unreachable page never aborts discovery
        if page.get("status", 0) >= 400 or not page.get("text"):
            continue

        html_map = extract_html_map(page["text"], page.get("url") or url)
        for form in html_map.get("forms", []):
            candidate = normalize_candidate(form, base_url, source="self-discovery")
            if candidate and candidate["fields"]:
                found.append(candidate)

        # Breadth-first expansion, same-origin only.
        for link in html_map.get("links", []):
            if len(queue) >= page_cap * 4:
                break
            absolute = normalize_url(link)
            if same_origin(base_url, absolute) and absolute not in visited:
                queue.append(absolute)

    seen = set()
    unique: List[Dict[str, Any]] = []
    for candidate in found:
        key = _candidate_key(candidate)
        if key in seen:
            continue
        seen.add(key)
        unique.append(candidate)
        if len(unique) >= candidate_cap:
            break
    return unique


def injectable_fields(candidate: Dict[str, Any]) -> List[str]:
    """Field names worth injecting into, sensitive ones already excluded."""
    return [name for name in (candidate.get("fields") or {}) if not is_sensitive_field(name)]


class RequestBudget:
    """Shared request counter so a sweep cannot outgrow its allowance.

    Mirrors `web_file_upload_rce_probe`'s `self._reqs` guard, but shared across
    candidates rather than per-candidate, which is what actually bounds a sweep.
    """

    def __init__(self, limit: Any = None) -> None:
        self.limit = _clamp(limit, DEFAULT_REQUEST_BUDGET, HARD_REQUEST_BUDGET)
        self.used = 0

    def remaining(self) -> int:
        return max(0, self.limit - self.used)

    def spend(self, count: int = 1) -> None:
        self.used += count

    def exhausted(self, need: int = 1) -> bool:
        return self.remaining() < need


async def sweep(
    candidates: List[Dict[str, Any]],
    probe: Callable[[Dict[str, Any]], Awaitable[Dict[str, Any]]],
    *,
    budget: Optional[RequestBudget] = None,
    requests_per_candidate: int = 2,
    stop_on_first: bool = True,
) -> Dict[str, Any]:
    """Run `probe` over each candidate and report per-candidate outcomes.

    `probe` returns a dict; a truthy `confirmed` key means the vulnerability
    fired for that candidate. Contract points that matter:

    - ONE CANDIDATE NEVER ABORTS THE SWEEP. An exception is captured as that
      candidate's outcome and the sweep continues — the
      `web_command_injection_timing_probe` idiom.
    - EVERY candidate gets an outcome row, so the result names the real sink and
      a caller can see what was tried and why the rest did not fire.
    - `stop_on_first` defaults to True: these are active probes, and once one has
      confirmed there is no reason to keep attacking the remaining sinks.
    """
    budget = budget or RequestBudget()
    outcomes: List[Dict[str, Any]] = []
    fired: Optional[Dict[str, Any]] = None

    for index, candidate in enumerate(candidates):
        row = {
            "index": index,
            "url": candidate.get("url"),
            "method": candidate.get("method"),
            "source": candidate.get("source"),
            "confirmed": False,
        }
        if budget.exhausted(requests_per_candidate):
            row["skipped"] = "request budget exhausted"
            outcomes.append(row)
            continue
        try:
            result = await probe(candidate)
        except Exception as exc:  # never let one candidate abort the sweep
            row["error"] = str(exc)[:300]
            outcomes.append(row)
            continue

        spent = int(result.get("requestCount") or requests_per_candidate)
        budget.spend(spent)
        row["requestCount"] = spent
        if result.get("reason"):
            row["reason"] = str(result["reason"])[:300]
        if result.get("confirmed"):
            row["confirmed"] = True
            outcomes.append(row)
            fired = {"candidate": candidate, "result": result, "index": index}
            if stop_on_first:
                break
            continue
        outcomes.append(row)

    return {
        "fired": fired,
        "candidateOutcomes": outcomes,
        "candidatesSwept": len(outcomes),
        "candidatesTotal": len(candidates),
        "requestsUsed": budget.used,
        "requestBudget": budget.limit,
    }
