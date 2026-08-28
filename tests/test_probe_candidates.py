import pytest

from tools._probe_candidates import (
    DEFAULT_MAX_CANDIDATES,
    HARD_MAX_CANDIDATES,
    RequestBudget,
    injectable_fields,
    is_sensitive_field,
    normalize_candidate,
    normalize_candidates,
    sweep,
)

BASE = "https://app.test/"


# --- the candidate shape -----------------------------------------------------


def test_accepts_the_canonical_candidate_shape():
    candidate = normalize_candidate(
        {
            "url": "https://app.test/product/stock",
            "method": "POST",
            "contentType": "application/x-www-form-urlencoded",
            "fields": {"productId": "1", "storeId": "1"},
            "source": "browser:map_app",
        },
        BASE,
    )
    assert candidate == {
        "url": "https://app.test/product/stock",
        "method": "POST",
        "contentType": "application/x-www-form-urlencoded",
        "fields": {"productId": "1", "storeId": "1"},
        "source": "browser:map_app",
    }


def test_accepts_the_form_dict_discovery_already_emits():
    """extract_html_map's shape, unchanged — the whole point of the contract is
    that no producer has to learn a new format."""
    candidate = normalize_candidate(
        {
            "action": "/product/stock",
            "method": "POST",
            "fields": [{"name": "productId", "type": "text"}, {"name": "storeId", "type": "text"}],
            "fieldCount": 2,
        },
        BASE,
    )
    assert candidate["url"] == "https://app.test/product/stock"
    assert candidate["method"] == "POST"
    # No observed values in that shape, so a benign default stands in for the
    # control request.
    assert candidate["fields"] == {"productId": "1", "storeId": "1"}


def test_accepts_a_bare_url_string():
    candidate = normalize_candidate("/search?q=1", BASE)
    assert candidate["url"] == "https://app.test/search?q=1"
    assert candidate["method"] == "GET"


def test_drops_off_origin_candidates():
    assert normalize_candidate("https://evil.test/steal", BASE) is None
    assert normalize_candidate({"url": "https://evil.test/x", "fields": {"a": "1"}}, BASE) is None


def test_never_offers_a_credential_or_csrf_field_for_injection():
    candidate = normalize_candidate(
        {
            "action": "/login",
            "method": "POST",
            "fields": [
                {"name": "username", "type": "text"},
                {"name": "password", "type": "password"},
                {"name": "csrf", "type": "hidden"},
                {"name": "session_token", "type": "hidden"},
            ],
        },
        BASE,
    )
    assert list(candidate["fields"]) == ["username"]
    assert injectable_fields(candidate) == ["username"]
    assert is_sensitive_field("csrfToken") is True
    assert is_sensitive_field("productId") is False


def test_skips_submit_and_file_inputs():
    candidate = normalize_candidate(
        {
            "action": "/x",
            "method": "POST",
            "fields": [
                {"name": "q", "type": "text"},
                {"name": "go", "type": "submit"},
                {"name": "upload", "type": "file"},
            ],
        },
        BASE,
    )
    assert list(candidate["fields"]) == ["q"]


# --- collection --------------------------------------------------------------


def test_merges_every_input_shape_and_dedupes():
    candidates = normalize_candidates(
        {
            "candidates": [
                {"url": "/product/stock", "method": "POST", "fields": {"productId": "1"}}
            ],
            # Same sink arriving from a second producer — must not double up.
            "forms": [
                {
                    "action": "/product/stock",
                    "method": "POST",
                    "fields": [{"name": "productId", "type": "text"}],
                },
                {"action": "/search", "method": "GET", "fields": [{"name": "q", "type": "text"}]},
            ],
            "urls": ["/about"],
        },
        BASE,
    )
    urls = [c["url"] for c in candidates]
    assert urls == [
        "https://app.test/product/stock",
        "https://app.test/search",
        "https://app.test/about",
    ]
    # The canonical entry wins, so the observed baseline value survives.
    assert candidates[0]["fields"] == {"productId": "1"}
    assert candidates[0]["source"] == "caller"


def test_caps_the_candidate_list():
    many = [{"url": f"/p{i}", "method": "POST", "fields": {"a": "1"}} for i in range(100)]
    assert len(normalize_candidates({"candidates": many}, BASE)) == DEFAULT_MAX_CANDIDATES
    # A caller-supplied cap is honoured but clamped to the hard ceiling.
    assert len(normalize_candidates({"candidates": many, "maxCandidates": 3}, BASE)) == 3
    assert (
        len(normalize_candidates({"candidates": many, "maxCandidates": 9999}, BASE))
        == HARD_MAX_CANDIDATES
    )


def test_empty_input_is_an_empty_list_not_an_error():
    assert normalize_candidates({}, BASE) == []
    assert normalize_candidates({"candidates": "not-a-list"}, BASE) == []


# --- the sweep ---------------------------------------------------------------


def _candidates(n):
    return [
        {"url": f"https://app.test/p{i}", "method": "POST", "fields": {"a": "1"}, "source": "t"}
        for i in range(n)
    ]


@pytest.mark.asyncio
async def test_sweep_names_the_firing_candidate_and_stops_there():
    async def probe(candidate):
        confirmed = candidate["url"].endswith("/p2")
        return {"confirmed": confirmed, "requestCount": 2}

    result = await sweep(_candidates(5), probe)

    assert result["fired"]["index"] == 2
    assert result["fired"]["candidate"]["url"] == "https://app.test/p2"
    # Stop-on-first: the remaining sinks are not attacked.
    assert result["candidatesSwept"] == 3
    assert result["candidatesTotal"] == 5
    assert [row["confirmed"] for row in result["candidateOutcomes"]] == [False, False, True]


@pytest.mark.asyncio
async def test_sweep_reports_every_candidate_outcome_when_nothing_fires():
    async def probe(candidate):
        return {"confirmed": False, "requestCount": 2, "reason": "marker absent"}

    result = await sweep(_candidates(3), probe)

    assert result["fired"] is None
    assert result["candidatesSwept"] == 3
    assert all(row["reason"] == "marker absent" for row in result["candidateOutcomes"])


@pytest.mark.asyncio
async def test_one_failing_candidate_never_aborts_the_sweep():
    async def probe(candidate):
        if candidate["url"].endswith("/p0"):
            raise RuntimeError("connection reset")
        return {"confirmed": candidate["url"].endswith("/p1"), "requestCount": 2}

    result = await sweep(_candidates(3), probe)

    assert result["candidateOutcomes"][0]["error"] == "connection reset"
    assert result["fired"]["index"] == 1


@pytest.mark.asyncio
async def test_sweep_stops_at_the_request_budget_and_says_so():
    async def probe(candidate):
        return {"confirmed": False, "requestCount": 4}

    result = await sweep(_candidates(10), probe, budget=RequestBudget(9), requests_per_candidate=4)

    assert result["requestsUsed"] == 8
    assert result["requestBudget"] == 9
    # Not silently truncated — the skipped candidates are reported.
    skipped = [row for row in result["candidateOutcomes"] if row.get("skipped")]
    assert len(skipped) == 8
    assert skipped[0]["skipped"] == "request budget exhausted"


@pytest.mark.asyncio
async def test_sweep_can_continue_past_a_confirmation_when_asked():
    async def probe(candidate):
        return {"confirmed": True, "requestCount": 2}

    result = await sweep(_candidates(3), probe, stop_on_first=False)

    assert result["candidatesSwept"] == 3
    assert all(row["confirmed"] for row in result["candidateOutcomes"])


def test_request_budget_is_clamped():
    assert RequestBudget(None).limit > 0
    assert RequestBudget(999_999).limit <= 240
    assert RequestBudget(0).limit >= 1
    assert RequestBudget("nonsense").limit > 0
