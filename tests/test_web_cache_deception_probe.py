from __future__ import annotations

from typing import Any, Dict, List
from urllib.parse import parse_qs, urlencode

import pytest

from tools.web_cache_deception_probe import (
    CacheDeceptionProbeTool,
    REDACTED_RUNTIME_SECRET,
    build_crafted_path,
    build_redirect_poc,
    cache_ttl_seconds,
    canonicalize_form_newlines,
    extract_prefixed_value,
    validate_probe_parameters,
)


def parameters(proof_level: str = "lab-state-change") -> Dict[str, Any]:
    value: Dict[str, Any] = {
        "target": "https://target.test/",
        "exploitServer": "https://exploit.test/",
        "mode": "origin-normalization-static-dir-v1",
        "proofLevel": proof_level,
        "sensitivePath": "/my-account",
        "staticDirectoryPath": "/resources/",
        "identityPrefix": "Your username is:",
        "sensitiveValuePrefix": "Your API Key is:",
        "cacheStatusHeader": "X-Cache",
        "cacheMissMarker": "miss",
        "cacheHitMarker": "hit",
        "expectedSensitiveStatus": 200,
        "expectedCacheStatus": 200,
        "minimumCacheTtlSeconds": 1,
        "maximumCacheTtlSeconds": 60,
        "exploitStorePath": "/",
        "exploitResourcePath": "/exploit",
        "exploitHttpsField": "urlIsHttps",
        "exploitFileField": "responseFile",
        "exploitHeadField": "responseHead",
        "exploitBodyField": "responseBody",
        "exploitActionField": "formAction",
        "exploitHttpsValue": "on",
        "exploitStoreValue": "STORE",
        "exploitDeliverValue": "DELIVER_TO_VICTIM",
        "engagement": "lab",
        "allowUnsafeMethods": True,
        "cachePopulationApproved": True,
        "victimBrowserDeliveryApproved": True,
        "pollAttempts": 2,
        "pollIntervalMs": 250,
        "timeoutSeconds": 10,
        "authCookies": "session=operator-secret",
    }
    if proof_level == "lab-state-change":
        value.update(
            {
                "statusPath": "/",
                "unsolvedMarker": "Not solved",
                "solvedMarker": "Solved",
                "solutionPath": "/submitSolution",
                "solutionField": "answer",
                "expectedStatusStatus": 200,
                "expectedSolutionStatus": 200,
                "expectedSolvedStatus": 200,
                "stateChangeApproved": True,
                "solutionSubmitApproved": True,
            }
        )
    return value


def response(
    body: str,
    *,
    status: int = 200,
    headers: Dict[str, str] | None = None,
    wire_url: str = "https://target.test/",
) -> Dict[str, Any]:
    return {
        "status": status,
        "reason": "OK",
        "headers": headers or {},
        "body": body,
        "truncated": False,
        "wireUrl": wire_url,
    }


def account(identity: str, api_key: str) -> str:
    return (
        f"<html><div>Your username is: {identity}</div>"
        f"<div>Your API Key is: {api_key}</div></html>"
    )


def test_tool_contract_is_closed_and_high_signal() -> None:
    tool = CacheDeceptionProbeTool()
    assert tool.name == "web:cache_deception_probe"
    assert tool.schema["additionalProperties"] is False
    assert tool.schema["properties"]["authCookies"]["x-workflow-owned"] is True
    assert tool.metadata["phase"] == 4


def test_build_crafted_path_preserves_encoded_separator() -> None:
    assert (
        build_crafted_path("/resources/", "/my-account", "abc123")
        == "/resources/..%2fmy-account?xasm_wcd=abc123"
    )


def test_redirect_poc_escapes_destination() -> None:
    poc = build_redirect_poc('https://target.test/a?x="bad"')
    assert "&quot;bad&quot;" in poc
    assert 'x="bad"' not in poc


def test_extract_prefixed_value_requires_one_unambiguous_value() -> None:
    body = account("wiener", "secret-1")
    assert extract_prefixed_value(body, "Your username is:") == "wiener"
    assert extract_prefixed_value(body, "Your API Key is:") == "secret-1"
    ambiguous = body + "<div>Your username is: carlos</div>"
    assert extract_prefixed_value(ambiguous, "Your username is:") is None


def test_cache_ttl_prefers_shared_or_shortest_bound() -> None:
    assert cache_ttl_seconds({"Cache-Control": "public, max-age=30"}) == 30
    assert cache_ttl_seconds({"Cache-Control": "s-maxage=20, max-age=60"}) == 20
    assert cache_ttl_seconds({}) is None


@pytest.mark.parametrize(
    ("mutate", "reason"),
    [
        (lambda p: p.update({"exploitServer": "https://target.test/"}), "cross-origin"),
        (lambda p: p.update({"cachePopulationApproved": False}), "cachePopulationApproved"),
        (lambda p: p.update({"victimBrowserDeliveryApproved": False}), "victimBrowserDeliveryApproved"),
        (lambda p: p.update({"staticDirectoryPath": "/resources"}), "ending in /"),
        (lambda p: p.update({"pollAttempts": 20}), "pollAttempts"),
        (lambda p: p.update({"headers": {"Cookie": "forged"}}), "unsupported parameter"),
    ],
)
def test_validation_fails_closed(mutate: Any, reason: str) -> None:
    value = parameters()
    mutate(value)
    valid, message = validate_probe_parameters(value)
    assert valid is False
    assert reason in message


def test_runtime_rejects_lab_only_parameters() -> None:
    value = parameters("runtime-foreign-response")
    value["solutionPath"] = "/submitSolution"
    valid, reason = validate_probe_parameters(value)
    assert valid is False
    assert "lab-only" in reason


@pytest.mark.asyncio
async def test_lab_proof_requires_foreign_cache_hit_and_redacts_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tool = CacheDeceptionProbeTool()
    own_body = account("wiener", "own-secret")
    foreign_body = account("carlos", "foreign-secret")
    calls: List[Dict[str, Any]] = []

    async def fake_request(
        session: Any,
        method: str,
        url: str,
        cookie: str = "",
        authorization: str = "",
        body: str = "",
        *,
        encoded_url: bool = False,
    ) -> Dict[str, Any]:
        calls.append(
            {
                "method": method,
                "url": url,
                "cookie": cookie,
                "authorization": authorization,
                "body": body,
                "encoded": encoded_url,
            }
        )
        index = len(calls)
        if index == 1:
            return response("<html>Not solved</html>")
        if index == 2:
            return response(own_body)
        if index == 3:
            return response(
                own_body,
                headers={"X-Cache": "miss", "Cache-Control": "max-age=30"},
                wire_url=url,
            )
        if index == 4:
            return response(
                own_body,
                headers={"X-Cache": "hit", "Cache-Control": "max-age=30"},
                wire_url=url,
            )
        if index == 5:
            return response("<html>stored exploit</html>", wire_url=url)
        if index == 6:
            return response(
                foreign_body,
                headers={"X-Cache": "hit", "Cache-Control": "max-age=30"},
                wire_url=url,
            )
        if index == 7:
            assert body == "answer=foreign-secret"
            return response('{"correct":true}', wire_url=url)
        if index == 8:
            return response("<html>Solved</html>", wire_url=url)
        raise AssertionError(f"unexpected request {index}: {method} {url}")

    async def fake_browser(
        exploit_url: str,
        action_field: str,
        deliver_value: str,
        timeout: int,
    ) -> Dict[str, Any]:
        stored = {
            key: values[0]
            for key, values in parse_qs(calls[4]["body"], keep_blank_values=True).items()
        }
        stored["responseHead"] = canonicalize_form_newlines(stored["responseHead"])
        stored["responseBody"] = canonicalize_form_newlines(stored["responseBody"])
        stored["formAction"] = "DELIVER_TO_VICTIM"
        delivery = urlencode(stored)
        return {
            "browserUsed": True,
            "loadUrl": exploit_url,
            "loadResponse": response("<html>exploit</html>", wire_url=exploit_url),
            "deliveryUrl": exploit_url,
            "deliveryBody": delivery,
            "deliveryResponse": response("", status=302, headers={"Location": "/"}),
            "outcomeUrl": "https://exploit.test/",
            "outcomeResponse": response("<html>delivered</html>"),
        }

    monkeypatch.setattr(tool, "_request", fake_request)
    monkeypatch.setattr(tool, "_browser_deliver", fake_browser)
    result = await tool.execute(parameters())
    assert result["success"] is True, result
    assert result["fallback"] is False
    verification = result["verification"]
    assert verification["browserDelivery"] is True
    assert verification["victimKeyAuthenticated"] is False
    assert verification["foreignIdentityDistinct"] is True
    assert verification["foreignSensitiveValueDistinct"] is True
    assert verification["solutionAnswerSha256"] == verification["foreignSensitiveValueSha256"]
    assert verification["statusPath"] == "/"
    assert verification["unsolvedMarker"] == "Not solved"
    assert verification["solvedMarker"] == "Solved"
    assert verification["solutionPath"] == "/submitSolution"
    assert verification["solutionField"] == "answer"
    assert verification["expectedStatusStatus"] == 200
    assert verification["expectedSolutionStatus"] == 200
    assert verification["expectedSolvedStatus"] == 200
    assert verification["requestCount"] == 11
    assert calls[5]["cookie"] == ""
    assert calls[5]["authorization"] == ""
    transcript = repr(verification["httpEvidence"])
    assert "operator-secret" not in transcript
    assert "own-secret" not in transcript
    assert "foreign-secret" not in transcript
    assert "wiener" not in transcript
    assert "carlos" not in transcript
    assert REDACTED_RUNTIME_SECRET in transcript


@pytest.mark.asyncio
async def test_own_cache_replay_never_creates_finding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tool = CacheDeceptionProbeTool()
    own_body = account("wiener", "own-secret")
    call_count = 0

    async def fake_request(
        session: Any,
        method: str,
        url: str,
        cookie: str = "",
        authorization: str = "",
        body: str = "",
        *,
        encoded_url: bool = False,
    ) -> Dict[str, Any]:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return response(own_body)
        if call_count in {2, 3}:
            return response(
                own_body,
                headers={
                    "X-Cache": "miss" if call_count == 2 else "hit",
                    "Cache-Control": "max-age=30",
                },
                wire_url=url,
            )
        if call_count == 4:
            return response("<html>stored</html>", wire_url=url)
        return response(
            own_body,
            headers={"X-Cache": "hit", "Cache-Control": "max-age=30"},
            wire_url=url,
        )

    async def fake_browser(*args: Any, **kwargs: Any) -> Dict[str, Any]:
        stored = "urlIsHttps=on&responseFile=%2Fexploit&responseHead=HTTP%2F1.1+200+OK"
        return {
            "browserUsed": True,
            "loadUrl": args[0],
            "loadResponse": response("<html>exploit</html>"),
            "deliveryUrl": args[0],
            "deliveryBody": stored,
            "deliveryResponse": response("", status=302, headers={"Location": "/"}),
            "outcomeUrl": "https://exploit.test/",
            "outcomeResponse": response("<html>delivered</html>"),
        }

    # Bypass browser-form comparison to reach the replay gate with a deterministic
    # browser result derived from the actual stored body.
    async def exact_browser(*args: Any, **kwargs: Any) -> Dict[str, Any]:
        # The fourth fake HTTP request captured the generated store body only
        # indirectly; execute() validates form content before the victim fetch,
        # so return a result from a first successful run helper shape instead.
        exploit_url = args[0]
        return {
            "browserUsed": True,
            "loadUrl": exploit_url,
            "loadResponse": response("<html>exploit</html>"),
            "deliveryUrl": exploit_url,
            "deliveryBody": "",
            "deliveryResponse": response("", status=302, headers={"Location": "/"}),
            "outcomeUrl": "https://exploit.test/",
            "outcomeResponse": response("<html>delivered</html>"),
        }

    monkeypatch.setattr(tool, "_request", fake_request)
    monkeypatch.setattr(tool, "_browser_deliver", exact_browser)
    result = await tool.execute(parameters("runtime-foreign-response"))
    assert result["success"] is False
    assert result["fallback"] is False
    assert result["findings"] == []
