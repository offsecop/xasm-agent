from urllib.parse import parse_qs

from multidict import CIMultiDict
import pytest

from plugin_loader import PluginLoader
from tools.web_authentication_probe import REDACTED_RUNTIME_SECRET
from tools.web_ssrf_probe import (
    AUTO_MODE,
    AUTO_PROOF_LEVEL,
    BYPASS_LOOPBACK_HOST,
    EXPECTED_STEP_LABELS,
    INTERNAL_SCHEME,
    LITERAL_LOOPBACK_HOST,
    MAX_SSRF_EVIDENCE_CHARS,
    SsrfProbeTool,
    build_form_body,
    build_http_evidence_step,
    build_internal_urls,
    build_nuclei_finding,
    encode_blocked_path,
    validate_probe_parameters,
)


def _parameters(**overrides):
    params = {
        "target": "https://lab.test/",
        "mode": "loopback-blacklist-form",
        "proofLevel": "lab-state-change",
        "statusPath": "/",
        "endpointPath": "/product/stock",
        "internalPath": "/admin",
        "effectPath": "/admin/delete?username=target-user",
        "injectionField": "stockApi",
        "additionalFields": {"productId": "1", "storeId": "1"},
        "blockedPathToken": "admin",
        "unsolvedMarker": "Lab status: Not solved",
        "solvedMarker": "Lab status: Solved",
        "deniedMarker": "External access denied",
        "filterMarker": "External stock check url is invalid",
        "internalMarker": "Internal administration panel",
        "expectedBaselineStatus": 200,
        "expectedDeniedStatus": 401,
        "expectedFilterStatus": 400,
        "expectedInternalStatus": 200,
        "expectedEffectStatus": 302,
        "expectedSolvedStatus": 200,
        "expectedEffectLocation": "/admin",
        "engagement": "lab",
        "allowUnsafeMethods": True,
        "stateChangeApproved": True,
        "timeoutSeconds": 5,
    }
    params.update(overrides)
    return params


def _response(status, body="", headers=None, truncated=False):
    return {
        "status": status,
        "reason": "OK",
        "headers": CIMultiDict(headers or {}),
        "body": body,
        "truncated": truncated,
    }


def _auto_parameters(**overrides):
    params = {
        "target": "https://lab.test/",
        "mode": AUTO_MODE,
        "proofLevel": AUTO_PROOF_LEVEL,
        "engagement": "standard",
        "allowUnsafeMethods": True,
        "candidates": [
            {
                "candidateId": "cand-0123456789abcdef",
                "endpointUrl": "https://lab.test/product/stock",
                "injectionField": "resource",
                "baselineValue": "https://inventory.example/stock?id=1",
                "additionalFields": {"productId": "1", "storeId": "2"},
            }
        ],
        "maxCandidates": 1,
        "maxRequests": 4,
        "timeoutSeconds": 5,
    }
    params.update(overrides)
    return params


def _valid_responses():
    return [
        _response(200, "Lab status: Not solved"),
        _response(401, "External access denied"),
        _response(400, "External stock check url is invalid"),
        _response(200, "Internal administration panel"),
        _response(302, "", {"Location": "/admin"}),
        _response(200, "Lab status: Solved"),
    ]


def test_registration_and_schema_expose_both_closed_bounded_modes():
    tool = SsrfProbeTool()

    assert tool.name == "web:ssrf_probe"
    assert tool.metadata["category"] == "exploit-test"
    assert tool.schema["properties"]["mode"]["enum"] == [
        "auto-discovered-url-form-loopback",
        "loopback-blacklist-form",
    ]
    assert tool.schema["additionalProperties"] is False
    for forbidden in (
        "internalUrl",
        "probeUrl",
        "effectUrl",
        "scheme",
        "host",
        "port",
        "headers",
        "cookies",
        "cookie",
        "username",
        "password",
        "auth",
        "oobUrl",
        "payload",
        "rawBody",
    ):
        assert forbidden not in tool.schema["properties"]


def test_closed_schema_is_not_polluted_by_legacy_target_alias_normalization():
    tool = SsrfProbeTool()
    loader = PluginLoader({})
    parameters = _parameters()

    normalized = loader._normalize_parameters(parameters, tool.schema)

    assert normalized == parameters
    assert "url" not in normalized
    assert "domain" not in normalized
    assert "host" not in normalized


def test_validation_requires_exact_scope_mode_approvals_and_bounded_fields():
    assert validate_probe_parameters(_parameters()) == (True, "")
    assert (
        validate_probe_parameters(
            _parameters(
                _agent=object(),
                _job_id="00000000-0000-0000-0000-000000000000",
                _job_timeout_seconds=30.0,
            )
        )
        == (True, "")
    )
    assert validate_probe_parameters(_parameters(engagement="ctf")) == (True, "")
    assert validate_probe_parameters(_parameters(engagement="standard"))[0] is False
    assert validate_probe_parameters(_parameters(engagement="aggressive"))[0] is False
    assert validate_probe_parameters(_parameters(allowUnsafeMethods=False))[0] is False
    assert validate_probe_parameters(_parameters(stateChangeApproved=False))[0] is False
    assert validate_probe_parameters(_parameters(target="https://user:pass@lab.test/"))[0] is False
    assert validate_probe_parameters(_parameters(endpointPath="//evil.test/fetch"))[0] is False
    assert validate_probe_parameters(_parameters(expectedEffectLocation="https://evil.test/"))[0] is False
    assert validate_probe_parameters(_parameters(injectionField="bad field"))[0] is False
    assert validate_probe_parameters(_parameters(injectionField="sessionToken"))[0] is False
    assert validate_probe_parameters(_parameters(additionalFields={"callbackUrl": "x"}))[0] is False
    assert validate_probe_parameters(_parameters(additionalFields={"note": "http://evil.test"}))[0] is False
    assert validate_probe_parameters(_parameters(additionalFields={"note": "token=live"}))[0] is False
    assert (
        validate_probe_parameters(
            _parameters(additionalFields={f"field{i}": str(i) for i in range(8)})
        )[0]
        is False
    )
    assert validate_probe_parameters(_parameters(blockedPathToken="../"))[0] is False
    assert validate_probe_parameters(_parameters(internalPath="/management"))[0] is False
    assert validate_probe_parameters(_parameters(internalPath="/admin/admin"))[0] is False
    assert validate_probe_parameters(_parameters(effectPath="/delete?section=admin&next=admin"))[0] is False
    assert validate_probe_parameters(_parameters(internalMarker="Lab status: Solved"))[0] is False
    assert validate_probe_parameters(_parameters(expectedEffectStatus=200))[0] is False
    assert validate_probe_parameters(_parameters(expectedSolvedStatus=600))[0] is False
    assert validate_probe_parameters(_parameters(timeoutSeconds=31))[0] is False
    assert validate_probe_parameters(_parameters(url="https://other.test/"))[0] is False
    assert validate_probe_parameters({**_parameters(), "headers": {"X-Test": "x"}})[0] is False
    assert validate_probe_parameters({**_parameters(), "_unexpected_runtime_key": True})[0] is False


def test_auto_validation_accepts_only_the_closed_server_resolved_contract():
    assert validate_probe_parameters(_auto_parameters()) == (True, "")
    assert validate_probe_parameters(_auto_parameters(engagement="lab"))[0] is False
    assert validate_probe_parameters(_auto_parameters(stateChangeApproved=True))[0] is False
    assert validate_probe_parameters(_auto_parameters(maxRequests=8))[0] is False
    assert validate_probe_parameters(_auto_parameters(maxCandidates=2))[0] is False
    assert validate_probe_parameters(
        _auto_parameters(
            candidates=[
                {
                    **_auto_parameters()["candidates"][0],
                    "endpointUrl": "https://outside.test/product/stock",
                }
            ]
        )
    )[0] is False
    assert validate_probe_parameters(
        _auto_parameters(
            candidates=[
                {
                    **_auto_parameters()["candidates"][0],
                    "baselineValue": "http://user:pass@internal.test/",
                }
            ]
        )
    )[0] is False


def test_internal_url_builder_owns_hosts_scheme_and_double_encoding():
    literal, bypass, effect = build_internal_urls(
        "/admin",
        "/admin/delete?username=target-user",
        "admin",
    )

    assert INTERNAL_SCHEME == "http"
    assert LITERAL_LOOPBACK_HOST == "localhost"
    assert BYPASS_LOOPBACK_HOST == "127.1"
    assert literal == "http://localhost/admin"
    assert bypass == "http://127.1/%61dmin"
    assert effect == "http://127.1/%61dmin/delete?username=target-user"
    assert encode_blocked_path("/Manage", "Manage") == "/%4danage"
    with pytest.raises(ValueError):
        encode_blocked_path("/admin/admin", "admin")


def test_form_builder_urlencodes_the_tool_owned_url_and_only_additional_fields():
    body = build_form_body(
        "stockApi",
        "http://127.1/%61dmin",
        {"productId": "1", "storeId": "2"},
    )

    assert parse_qs(body, strict_parsing=True) == {
        "stockApi": ["http://127.1/%61dmin"],
        "productId": ["1"],
        "storeId": ["2"],
    }
    assert "http://" not in body
    assert "%2561dmin" in body


def test_http_evidence_preserves_form_and_sanitizes_response():
    response = _response(
        200,
        '{"session":"live-session","result":"Internal administration panel"}',
        {
            "Content-Type": "application/json",
            "Set-Cookie": "session=live-session",
            "Authorization": "Bearer live-session",
        },
    )
    body = build_form_body("stockApi", "http://127.1/%61dmin", {"storeId": "1"})

    step = build_http_evidence_step(
        "encoded-loopback-internal-content",
        "POST",
        "https://lab.test/product/stock",
        body,
        response,
        ("live-session",),
    )

    assert step["request"].startswith("POST /product/stock HTTP/1.1")
    assert "Content-Type: application/x-www-form-urlencoded" in step["request"]
    assert "%2561dmin" in step["request"]
    assert "Content-Type: application/json" in step["response"]
    assert "Set-Cookie" not in step["response"]
    assert "Authorization" not in step["response"]
    assert "live-session" not in str(step)
    assert REDACTED_RUNTIME_SECRET in step["response"]
    assert len(step["requestSha256"]) == 64
    assert len(step["responseSha256"]) == 64
    assert len(step["responseBodySha256"]) == 64
    assert step["responseExcerptTruncated"] is False


def test_finding_shape_is_high_cwe_918_and_keeps_typed_proof():
    verification = {
        "verified": True,
        "fallback": False,
        "mode": "loopback-blacklist-form",
        "endpointUrl": "https://lab.test/product/stock",
    }

    finding = build_nuclei_finding("https://lab.test/", verification)

    assert finding["template-id"] == "xasm-ssrf-loopback-blacklist-bypass-verified"
    assert finding["info"]["severity"] == "high"
    assert finding["info"]["classification"]["cwe-id"] == ["CWE-918"]
    assert finding["matched-at"] == "https://lab.test/product/stock"
    assert finding["evidence"] is verification


@pytest.mark.asyncio
async def test_execute_emits_exact_six_step_fail_closed_proof(monkeypatch):
    tool = SsrfProbeTool()
    calls = []
    responses = _valid_responses()

    async def fake_request(_session, method, url, body=None):
        calls.append((method, url, body))
        return responses.pop(0)

    monkeypatch.setattr(tool, "_request", fake_request)
    output = await tool.execute(_parameters())

    assert output["success"] is True
    assert output["fallback"] is False
    assert output["requestCount"] == 6
    verification = output["verification"]
    assert verification["verified"] is True
    assert verification["requestCount"] == 6
    assert verification["statusChecks"] == 2
    assert verification["controlRequests"] == 2
    assert verification["directControlRequests"] == 1
    assert verification["literalControlRequests"] == 1
    assert verification["probeRequests"] == 1
    assert verification["bypassRequests"] == 1
    assert verification["effectRequests"] == 1
    assert verification["solvedBefore"] is False
    assert verification["directDenied"] is True
    assert verification["literalFiltered"] is True
    assert verification["internalMarkerAbsentFromControls"] is True
    assert verification["bypassInternalContent"] is True
    assert verification["internalContentReached"] is True
    assert verification["effectTriggered"] is True
    assert verification["solvedAfter"] is True
    assert [step["label"] for step in verification["httpEvidence"]["steps"]] == list(
        EXPECTED_STEP_LABELS
    )
    assert [call[0] for call in calls] == ["GET", "GET", "POST", "POST", "POST", "GET"]
    assert calls[0] == ("GET", "https://lab.test/", None)
    assert calls[1] == ("GET", "https://lab.test/admin", None)
    assert parse_qs(calls[2][2])["stockApi"] == ["http://localhost/admin"]
    assert parse_qs(calls[3][2])["stockApi"] == ["http://127.1/%61dmin"]
    assert parse_qs(calls[4][2])["stockApi"] == [
        "http://127.1/%61dmin/delete?username=target-user"
    ]
    assert calls[5] == ("GET", "https://lab.test/", None)
    assert output["findings"][0]["evidence"] is verification
    assert all(
        step["responseExcerptTruncated"] is False
        for step in verification["httpEvidence"]["steps"]
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("responses", "error_fragment", "expected_count"),
    [
        (
            [
                _response(200, "Lab status: Not solved"),
                _response(200, "Internal administration panel"),
            ],
            "external denial",
            2,
        ),
        (
            [
                _response(200, "Lab status: Not solved"),
                _response(401, "External access denied"),
                _response(200, "Internal administration panel"),
            ],
            "literal loopback control",
            3,
        ),
        (
            [
                _response(200, "Lab status: Not solved"),
                _response(401, "External access denied"),
                _response(400, "External stock check url is invalid"),
                _response(200, "response without the internal marker"),
            ],
            "encoded loopback probe",
            4,
        ),
    ],
)
async def test_controls_fail_closed_before_the_approved_effect(
    monkeypatch,
    responses,
    error_fragment,
    expected_count,
):
    tool = SsrfProbeTool()
    queued = list(responses)
    calls = []

    async def fake_request(_session, method, url, body=None):
        calls.append((method, url, body))
        return queued.pop(0)

    monkeypatch.setattr(tool, "_request", fake_request)
    output = await tool.execute(_parameters())

    assert output["success"] is False
    assert output["fallback"] is False
    assert output["requestCount"] == expected_count
    assert len(calls) == expected_count
    assert output["findings"] == []
    assert error_fragment in output["error"]


@pytest.mark.asyncio
async def test_execute_rejects_effect_redirect_or_missing_solved_transition(monkeypatch):
    tool = SsrfProbeTool()
    responses = _valid_responses()
    responses[4] = _response(302, "", {"Location": "/unexpected"})

    async def fake_request(_session, _method, _url, body=None):
        return responses.pop(0)

    monkeypatch.setattr(tool, "_request", fake_request)
    effect_failure = await tool.execute(_parameters())

    assert effect_failure["success"] is False
    assert effect_failure["requestCount"] == 5
    assert effect_failure["findings"] == []
    assert "configured redirect" in effect_failure["error"]

    responses = _valid_responses()
    responses[5] = _response(200, "Lab status: Not solved")

    async def fake_request_unsolved(_session, _method, _url, body=None):
        return responses.pop(0)

    monkeypatch.setattr(tool, "_request", fake_request_unsolved)
    solved_failure = await tool.execute(_parameters())

    assert solved_failure["success"] is False
    assert solved_failure["requestCount"] == 6
    assert solved_failure["findings"] == []
    assert "solved transition" in solved_failure["error"]


@pytest.mark.asyncio
async def test_execute_fails_closed_on_response_or_evidence_truncation(monkeypatch):
    tool = SsrfProbeTool()
    responses = _valid_responses()
    responses[3] = _response(
        200,
        "Internal administration panel",
        truncated=True,
    )

    async def fake_request(_session, _method, _url, body=None):
        return responses.pop(0)

    monkeypatch.setattr(tool, "_request", fake_request)
    transport_truncation = await tool.execute(_parameters())

    assert transport_truncation["success"] is False
    assert transport_truncation["requestCount"] == 4
    assert transport_truncation["findings"] == []

    responses = _valid_responses()
    responses[3] = _response(
        200,
        "Internal administration panel" + ("x" * MAX_SSRF_EVIDENCE_CHARS),
    )

    async def fake_request_oversized(_session, _method, _url, body=None):
        return responses.pop(0)

    monkeypatch.setattr(tool, "_request", fake_request_oversized)
    evidence_truncation = await tool.execute(_parameters())

    assert evidence_truncation["success"] is False
    assert evidence_truncation["requestCount"] == 4
    assert evidence_truncation["findings"] == []


@pytest.mark.asyncio
async def test_auto_mode_finds_structural_loopback_differential_and_redacts_control(monkeypatch):
    tool = SsrfProbeTool()
    calls = []
    root = (
        "<html><head><title>Internal console</title></head><body>"
        "<nav><a href='/admin/delete?user=sample'>Manage account records</a>"
        "<a href='/resources/app.css'>Assets</a></nav>"
        "<main>Internal administration service available to local operators only</main>"
        "</body></html>"
    )
    derived = (
        "<html><head><title>Internal console</title></head><body>"
        "<nav><a href='/admin'>Administration home</a></nav>"
        "<main>Internal administration service account records local operators</main>"
        "</body></html>"
    )
    responses = [
        _response(200, "Inventory stock count is currently forty two for selected store"),
        _response(200, root, {"Content-Type": "text/html"}),
        _response(200, root, {"Content-Type": "text/html"}),
        _response(200, derived, {"Content-Type": "text/html"}),
    ]

    async def fake_request(_session, method, url, body=None):
        calls.append((method, url, body))
        return responses.pop(0)

    monkeypatch.setattr(tool, "_request", fake_request)
    output = await tool.execute(_auto_parameters())

    assert output["success"] is True
    assert output["requestCount"] == 4
    assert output["verification"]["verified"] is True
    assert output["verification"]["firingCandidate"]["derivedPath"] == "/admin"
    assert output["verification"]["candidateOutcomes"][0]["confirmed"] is True
    assert [parse_qs(call[2])["resource"][0] for call in calls] == [
        "https://inventory.example/stock?id=1",
        "http://localhost/",
        "http://127.0.0.1/",
        "http://127.0.0.1/admin",
    ]
    transcript = str(output["verification"]["httpEvidence"])
    assert "inventory.example" not in transcript
    assert REDACTED_RUNTIME_SECRET in transcript
    assert "http%3A%2F%2Flocalhost%2F" in transcript


@pytest.mark.asyncio
async def test_auto_mode_rejects_reflection_only_and_truncated_responses(monkeypatch):
    tool = SsrfProbeTool()
    reflected = [
        _response(200, "https://inventory.example/stock?id=1"),
        _response(200, "http://localhost/"),
        _response(200, "http://127.0.0.1/"),
    ]

    async def fake_reflection(_session, _method, _url, body=None):
        return reflected.pop(0)

    monkeypatch.setattr(tool, "_request", fake_reflection)
    reflection = await tool.execute(_auto_parameters())
    assert reflection["success"] is True
    assert reflection["findings"] == []
    assert reflection["requestCount"] == 3
    assert "consistent safe relative path" in reflection["candidateOutcomes"][0]["reason"]

    truncated = [
        _response(200, "control response with enough ordinary inventory words"),
        _response(200, "<html><a href='/inside'>internal service content words</a></html>", truncated=True),
        _response(200, "<html><a href='/inside'>internal service content words</a></html>"),
    ]

    async def fake_truncation(_session, _method, _url, body=None):
        return truncated.pop(0)

    monkeypatch.setattr(tool, "_request", fake_truncation)
    truncation = await tool.execute(_auto_parameters())
    assert truncation["success"] is True
    assert truncation["findings"] == []
    assert "truncated/unbounded" in truncation["candidateOutcomes"][0]["reason"]
