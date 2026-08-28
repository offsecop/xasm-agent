import asyncio
import json

from multidict import CIMultiDict

from tools.web_os_command_injection_probe import (
    BASELINE_VALUE,
    LAB_STEP_LABELS,
    RUNTIME_STEP_LABELS,
    OsCommandInjectionProbeTool,
    _sha256,
    build_evidence_step,
    extract_form_token,
    validate_probe_parameters,
)


def base_parameters(**overrides):
    value = {
        "target": "https://target.example/",
        "mode": "form-time-delay-v1",
        "proofLevel": "runtime-timing",
        "formPath": "/feedback",
        "submitPath": "/feedback/submit",
        "injectionParameter": "email",
        "csrfField": "csrf",
        "baseFields": {
            "name": "xasm calibration",
            "subject": "bounded probe",
            "message": "authorized validation",
        },
        "expectedFormStatus": 200,
        "expectedSubmitStatus": 200,
        "delaySeconds": 10,
        "maxControlSeconds": 3,
        "engagement": "lab",
        "allowUnsafeMethods": True,
        "commandExecutionApproved": True,
        "timeoutSeconds": 20,
    }
    value.update(overrides)
    return value


def response(body="", duration=40, status=200, headers=None, truncated=False):
    return {
        "status": status,
        "reason": "OK",
        "headers": CIMultiDict(headers or {"Content-Type": "text/html; charset=utf-8"}),
        "body": body,
        "truncated": truncated,
        "durationMs": duration,
    }


def form(token):
    return response(f'<form><input type="hidden" name="csrf" value="{token}"></form>')


def install_responses(tool, values):
    queue = list(values)

    async def fake_request(_session, _method, _url, _timeout_seconds, _body=None):
        assert queue, "unexpected extra request"
        return queue.pop(0)

    tool._request = fake_request
    return queue


def test_parameter_contract_accepts_closed_runtime_mode():
    assert validate_probe_parameters(base_parameters()) == (True, "")
    assert OsCommandInjectionProbeTool().schema["properties"]["maxControlSeconds"][
        "type"
    ] == ["number", "integer"]


def test_parameter_contract_accepts_lab_state_mode():
    params = base_parameters(
        proofLevel="lab-state-change",
        statusPath="/",
        unsolvedMarker="Not solved",
        solvedMarker="Solved",
        expectedStatusStatus=200,
    )
    assert validate_probe_parameters(params) == (True, "")


def test_parameter_contract_rejects_commands_headers_and_unsafe_base_fields():
    for key, value in (
        ("command", "id"),
        ("payload", "x||sleep 10||"),
        ("headers", {"X-Test": "yes"}),
        ("authCookies", "session=secret"),
    ):
        params = base_parameters()
        params[key] = value
        valid, reason = validate_probe_parameters(params)
        assert not valid
        assert "unsupported parameter" in reason

    params = base_parameters(baseFields={"message": "hello;whoami"})
    valid, reason = validate_probe_parameters(params)
    assert not valid
    assert "inert value" in reason


def test_parameter_contract_rejects_sensitive_or_reserved_fields():
    for overrides in (
        {"injectionParameter": "password"},
        {"csrfField": "message"},
        {"baseFields": {"email": "duplicate"}},
        {"baseFields": {"api_key": "secret"}},
    ):
        valid, _ = validate_probe_parameters(base_parameters(**overrides))
        assert not valid


def test_parameter_contract_rejects_runtime_lab_fields_and_weak_timing():
    params = base_parameters(statusPath="/")
    valid, reason = validate_probe_parameters(params)
    assert not valid
    assert "only allowed for lab-state-change" in reason

    for overrides in (
        {"delaySeconds": 1},
        {"delaySeconds": 11},
        {"maxControlSeconds": 8},
        {"timeoutSeconds": 10},
        {"commandExecutionApproved": False},
    ):
        valid, _ = validate_probe_parameters(base_parameters(**overrides))
        assert not valid


def test_extract_form_token_is_exact_and_bounded():
    html = (
        '<input name="csrf_backup" value="wrong">'
        '<input type="hidden" name="csrf" value="right-token">'
    )
    assert extract_form_token(html, "csrf") == "right-token"
    assert extract_form_token(html, "token") is None


def test_evidence_redacts_csrf_cookie_and_response_occurrences():
    step = build_evidence_step(
        "baseline-submit",
        "POST",
        "https://target.example/feedback/submit",
        "csrf=secret-token&email=xasm-safe%40example.invalid",
        "session=raw-cookie",
        response(
            '<input name="csrf" value="secret-token">',
            headers={"Set-Cookie": "session=raw-cookie", "Content-Type": "text/html"},
        ),
        ["secret-token"],
    )
    serialized = json.dumps(step)
    assert "secret-token" not in serialized
    assert "raw-cookie" not in serialized
    assert "<redacted-runtime-secret>" in serialized


def test_runtime_proof_requires_two_delays_and_recovery():
    tool = OsCommandInjectionProbeTool()
    remaining = install_responses(
        tool,
        [
            form("csrf-a"),
            response("baseline", 100),
            form("csrf-b"),
            response("primary", 10_200),
            form("csrf-c"),
            response("recovery", 120),
            form("csrf-d"),
            response("confirmation", 10_100),
        ],
    )
    output = asyncio.run(tool.execute(base_parameters()))
    assert not remaining
    assert output["success"] is True
    assert output["fallback"] is False
    assert output["verification"]["verified"] is True
    assert output["verification"]["controlsFast"] is True
    assert output["verification"]["primaryDelayed"] is True
    assert output["verification"]["confirmationDelayed"] is True
    assert output["verification"]["requestCount"] == 8
    assert tuple(step["label"] for step in output["verification"]["evidence"]) == RUNTIME_STEP_LABELS
    assert output["verification"]["fixedPayloadSha256"] == _sha256("x||sleep 10||")
    assert len(output["findings"]) == 1
    assert output["findings"][0]["info"]["classification"]["cwe-id"] == ["CWE-78"]

    transcript = "\n".join(
        step["request"] for step in output["verification"]["evidence"]
    )
    assert "x%7C%7Csleep+10%7C%7C" in transcript
    assert BASELINE_VALUE.replace("@", "%40") in transcript
    for token in ("csrf-a", "csrf-b", "csrf-c", "csrf-d"):
        assert token not in json.dumps(output)


def test_lab_state_proof_requires_unsolved_to_solved_transition():
    tool = OsCommandInjectionProbeTool()
    install_responses(
        tool,
        [
            response("<p>Not solved</p>", 20),
            form("csrf-a"),
            response("baseline", 90),
            form("csrf-b"),
            response("primary", 10_100),
            form("csrf-c"),
            response("recovery", 110),
            form("csrf-d"),
            response("confirmation", 10_050),
            response("<p>Solved</p>", 20),
        ],
    )
    params = base_parameters(
        proofLevel="lab-state-change",
        statusPath="/",
        unsolvedMarker="Not solved",
        solvedMarker="Solved",
        expectedStatusStatus=200,
    )
    output = asyncio.run(tool.execute(params))
    assert output["verification"]["verified"] is True
    assert output["verification"]["solvedBefore"] is False
    assert output["verification"]["solvedAfter"] is True
    assert output["verification"]["requestCount"] == 10
    assert tuple(step["label"] for step in output["verification"]["evidence"]) == LAB_STEP_LABELS
    assert len(output["findings"]) == 1


def test_single_slow_response_is_not_a_finding():
    tool = OsCommandInjectionProbeTool()
    install_responses(
        tool,
        [
            form("csrf-a"),
            response("baseline", 90),
            form("csrf-b"),
            response("primary", 10_100),
            form("csrf-c"),
            response("recovery", 100),
            form("csrf-d"),
            response("confirmation", 150),
        ],
    )
    output = asyncio.run(tool.execute(base_parameters()))
    assert output["verification"]["verified"] is False
    assert output["verification"]["primaryDelayed"] is True
    assert output["verification"]["confirmationDelayed"] is False
    assert output["findings"] == []


def test_always_slow_or_failed_recovery_is_not_a_finding():
    tool = OsCommandInjectionProbeTool()
    install_responses(
        tool,
        [
            form("csrf-a"),
            response("baseline", 5_500),
            form("csrf-b"),
            response("primary", 10_100),
            form("csrf-c"),
            response("recovery", 5_200),
            form("csrf-d"),
            response("confirmation", 10_200),
        ],
    )
    output = asyncio.run(tool.execute(base_parameters()))
    assert output["verification"]["controlsFast"] is False
    assert output["verification"]["verified"] is False
    assert output["findings"] == []


def test_missing_csrf_and_redirect_fail_closed():
    tool = OsCommandInjectionProbeTool()
    install_responses(tool, [response("<form></form>")])
    output = asyncio.run(tool.execute(base_parameters()))
    assert output["success"] is True
    assert output["verification"]["verified"] is False
    assert "CSRF" in output["verification"]["reason"]
    assert output["findings"] == []

    tool = OsCommandInjectionProbeTool()
    install_responses(
        tool,
        [
            form("csrf-a"),
            response("", headers={"Location": "/other"}),
        ],
    )
    output = asyncio.run(tool.execute(base_parameters()))
    assert output["verification"]["verified"] is False
    assert "unexpected or unsafe" in output["verification"]["reason"]


def test_solved_before_is_rejected_without_executing_the_form():
    tool = OsCommandInjectionProbeTool()
    remaining = install_responses(tool, [response("<p>Solved</p>")])
    params = base_parameters(
        proofLevel="lab-state-change",
        statusPath="/",
        unsolvedMarker="Not solved",
        solvedMarker="Solved",
        expectedStatusStatus=200,
    )
    output = asyncio.run(tool.execute(params))
    assert not remaining
    assert output["verification"]["verified"] is False
    assert output["verification"]["requestCount"] == 1
    assert output["findings"] == []
