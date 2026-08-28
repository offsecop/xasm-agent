from multidict import CIMultiDict
import pytest

from tools.web_cache_poisoning_probe import (
    CachePoisoningProbeTool,
    build_http_evidence_step,
    build_nuclei_finding,
    cache_header_matches,
    validate_probe_parameters,
)


def _parameters(**overrides):
    params = {
        "target": "https://lab.test/",
        "mode": "fat-get-query-body",
        "proofLevel": "lab-state-change",
        "statusPath": "/",
        "cachePath": "/js/geolocate.js?callback=setCountryCookie",
        "bodyField": "callback",
        "bodyValue": "alert(1)",
        "unsolvedMarker": "Not solved",
        "solvedMarker": "Solved",
        "cleanMarker": 'setCountryCookie({"country"',
        "poisonMarker": "alert(1)",
        "cacheStatusHeader": "X-Cache",
        "cacheMissMarker": "miss",
        "cacheHitMarker": "hit",
        "expectedStatus": 200,
        "maxPoisonAttempts": 4,
        "retryDelayMs": 100,
        "maxSolveChecks": 3,
        "solvePollIntervalMs": 100,
        "engagement": "lab",
        "allowUnsafeMethods": True,
        "timeoutSeconds": 5,
    }
    params.update(overrides)
    return params


def _response(status, body, headers=None, truncated=False):
    return {
        "status": status,
        "reason": "OK",
        "headers": CIMultiDict(headers or {}),
        "body": body,
        "truncated": truncated,
    }


def test_registration_and_schema_expose_only_bounded_fat_get_mode():
    tool = CachePoisoningProbeTool()

    assert tool.name == "web:cache_poisoning_probe"
    assert tool.metadata["category"] == "exploit-test"
    assert tool.schema["properties"]["mode"]["enum"] == ["fat-get-query-body"]
    assert "headers" not in tool.schema["properties"]
    assert "cookies" not in tool.schema["properties"]
    assert "rawRequest" not in tool.schema["properties"]


def test_validation_requires_explicit_engagement_scope_and_bounded_waits():
    assert validate_probe_parameters(_parameters()) == (True, "")
    assert validate_probe_parameters(_parameters(engagement="standard"))[0] is False
    assert validate_probe_parameters(_parameters(allowUnsafeMethods=False))[0] is False
    assert validate_probe_parameters(_parameters(target="https://user:pass@lab.test/"))[0] is False
    assert validate_probe_parameters(_parameters(cachePath="//evil.test/"))[0] is False
    assert validate_probe_parameters(_parameters(bodyField="bad field"))[0] is False
    assert validate_probe_parameters(_parameters(bodyValue="x\r\nInjected: yes"))[0] is False
    assert validate_probe_parameters(_parameters(cacheStatusHeader="X-Cache\r\nX-Evil"))[0] is False
    assert validate_probe_parameters(
        _parameters(
            maxPoisonAttempts=45,
            retryDelayMs=2_000,
            maxSolveChecks=30,
            solvePollIntervalMs=2_000,
        )
    )[0] is False


def test_cache_header_matching_is_case_insensitive_and_requires_marker():
    headers = CIMultiDict({"X-Cache": "miss, edge-node"})

    assert cache_header_matches(headers, "x-cache", "MISS")
    assert not cache_header_matches(headers, "X-Cache", "hit")
    assert not cache_header_matches(headers, "Cache-Status", "miss")


def test_http_evidence_preserves_get_body_and_cache_headers():
    response = _response(
        200,
        "alert(1)({})",
        {
            "Content-Type": "application/javascript",
            "X-Cache": "miss",
            "Age": "0",
            "Set-Cookie": "session=must-not-be-retained",
        },
    )

    step = build_http_evidence_step(
        "poison-cache-miss",
        "GET",
        "https://lab.test/js/geolocate.js?callback=setCountryCookie",
        "callback=alert%281%29",
        response,
        "X-Cache",
    )

    assert step["request"].startswith(
        "GET /js/geolocate.js?callback=setCountryCookie HTTP/1.1"
    )
    assert "Content-Type: application/x-www-form-urlencoded" in step["request"]
    assert step["request"].endswith("\r\n\r\ncallback=alert%281%29")
    assert "X-Cache: miss" in step["response"]
    assert "Age: 0" in step["response"]
    assert "Set-Cookie" not in step["response"]
    assert len(step["requestSha256"]) == 64
    assert len(step["responseSha256"]) == 64


def test_finding_shape_is_cwe_349_and_keeps_typed_proof():
    verification = {
        "verified": True,
        "mode": "fat-get-query-body",
        "cacheUrl": "https://lab.test/cache",
    }

    finding = build_nuclei_finding("https://lab.test/", verification)

    assert finding["template-id"] == "xasm-fat-get-cache-poisoning-verified"
    assert finding["info"]["classification"]["cwe-id"] == ["CWE-349"]
    assert finding["matched-at"] == "https://lab.test/cache"
    assert finding["evidence"] is verification


@pytest.mark.asyncio
async def test_execute_retries_until_miss_then_proves_clean_hit_and_solved(monkeypatch):
    tool = CachePoisoningProbeTool()
    calls = []
    responses = [
        _response(200, "Lab status: Not solved"),
        _response(
            200,
            'const setCountryCookie = (country) => {};\nsetCountryCookie({"country":"UK"});',
            {"X-Cache": "hit"},
        ),
        _response(
            200,
            'const setCountryCookie = (country) => {};\nalert(1)({"country":"UK"});',
            {"X-Cache": "miss"},
        ),
        _response(
            200,
            'const setCountryCookie = (country) => {};\nalert(1)({"country":"UK"});',
            {"X-Cache": "hit", "Age": "0"},
        ),
        _response(200, "Lab status: Not solved"),
        _response(200, "Lab status: Solved"),
    ]

    async def fake_request(_session, url, body=None):
        calls.append((url, body))
        return responses.pop(0)

    async def no_sleep(_seconds):
        return None

    monkeypatch.setattr(tool, "_request", fake_request)
    monkeypatch.setattr("tools.web_cache_poisoning_probe.asyncio.sleep", no_sleep)

    output = await tool.execute(_parameters())

    assert output["success"] is True
    assert output["fallback"] is False
    assert output["requestCount"] == 6
    verification = output["verification"]
    assert verification["poisonAttempts"] == 2
    assert verification["cleanChecks"] == 1
    assert verification["solveChecks"] == 2
    assert verification["poisonAcceptedOnMiss"] is True
    assert verification["cleanRequestHadBody"] is False
    assert verification["cleanPoisonServedOnHit"] is True
    assert verification["solvedBefore"] is False
    assert verification["solvedAfter"] is True
    assert [step["label"] for step in verification["httpEvidence"]["steps"]] == [
        "unsolved-baseline",
        "poison-cache-miss",
        "clean-cache-hit",
        "solved-confirmation",
    ]
    assert calls[2][1] == "callback=alert%281%29"
    assert calls[3][1] is None
    assert output["findings"][0]["evidence"] is verification


@pytest.mark.asyncio
async def test_execute_fails_closed_when_clean_request_is_not_a_poisoned_hit(monkeypatch):
    tool = CachePoisoningProbeTool()
    responses = [
        _response(200, "Lab status: Not solved"),
        _response(
            200,
            'const setCountryCookie = (country) => {};\nalert(1)({"country":"UK"});',
            {"X-Cache": "miss"},
        ),
        _response(
            200,
            'const setCountryCookie = (country) => {};\nsetCountryCookie({"country":"UK"});',
            {"X-Cache": "hit"},
        ),
    ]

    async def fake_request(_session, _url, body=None):
        if responses:
            return responses.pop(0)
        return _response(
            200,
            'const setCountryCookie = (country) => {};\nsetCountryCookie({"country":"UK"});',
            {"X-Cache": "hit"},
        )

    async def no_sleep(_seconds):
        return None

    monkeypatch.setattr(tool, "_request", fake_request)
    monkeypatch.setattr("tools.web_cache_poisoning_probe.asyncio.sleep", no_sleep)

    output = await tool.execute(_parameters(maxPoisonAttempts=2))

    assert output["success"] is False
    assert output["fallback"] is False
    assert output["findings"] == []
    assert "payload-free poisoned cache-hit" in output["error"]
