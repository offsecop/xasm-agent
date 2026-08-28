import hashlib
import json
from urllib.parse import parse_qs, urlsplit

import aiohttp
from multidict import CIMultiDict
import pytest

from tools.web_ssti_probe import (
    EXPECTED_LAB_STEP_LABELS,
    EXPECTED_RUNTIME_STEP_LABELS,
    SstiProbeTool,
    build_http_evidence_step,
    build_nuclei_finding,
    build_probe_payloads,
    validate_effect_target_path,
    validate_probe_parameters,
)


FIXED_NONCE = "0123456789abcdef0123456789abcdef"


def _runtime_parameters(**overrides):
    parameters = {
        "target": "https://lab.test/",
        "mode": "erb-query-v1",
        "proofLevel": "runtime-evaluation",
        "endpointPath": "/",
        "injectionParameter": "message",
        "expectedProbeStatus": 200,
        "engagement": "aggressive",
        "allowUnsafeMethods": True,
        "timeoutSeconds": 5,
    }
    parameters.update(overrides)
    return parameters


def _lab_parameters(**overrides):
    parameters = _runtime_parameters(
        proofLevel="lab-state-change",
        engagement="lab",
        statusPath="/",
        unsolvedMarker="Lab status: Not solved",
        solvedMarker="Congratulations, you solved the lab!",
        expectedStatusStatus=200,
        effectTargetPath="/home/carlos/morale.txt",
        expectedEffectStatus=200,
        stateChangeApproved=True,
    )
    parameters.update(overrides)
    return parameters


def _response(status=200, body="", headers=None, truncated=False, redirected=False):
    return {
        "status": status,
        "reason": "OK",
        "headers": CIMultiDict(headers or {}),
        "body": body,
        "truncated": truncated,
        "redirected": redirected,
    }


def _payload_from_url(url, parameter="message"):
    values = parse_qs(urlsplit(url).query, strict_parsing=True)
    return values[parameter][0]


def _runtime_success_responses():
    return [
        _response(body=f"Echo: xasm-ssti-{FIXED_NONCE}-literal"),
        _response(body=f"Rendered: xasm-ssti-{FIXED_NONCE}-eval-2537"),
        _response(body=f"Rendered: xasm-ssti-{FIXED_NONCE}-fp-4087"),
        _response(body=f"Rendered: xasm-ssti-{FIXED_NONCE}-uid-1001"),
    ]


def test_registration_schema_and_metadata_expose_only_bounded_erb_contract():
    tool = SstiProbeTool()

    assert tool.name == "web:ssti_probe"
    assert tool.metadata["category"] == "exploit-test"
    assert tool.metadata["phase"] == 4
    assert tool.schema["additionalProperties"] is False
    assert tool.schema["properties"]["mode"]["enum"] == ["erb-query-v1"]
    assert tool.schema["properties"]["proofLevel"]["enum"] == [
        "lab-state-change",
        "runtime-evaluation",
    ]
    for forbidden in (
        "payload",
        "template",
        "command",
        "cmd",
        "headers",
        "cookies",
        "cookie",
        "body",
        "rawRequest",
        "proxy",
        "origin",
        "callbackUrl",
        "method",
    ):
        assert forbidden not in tool.schema["properties"]


@pytest.mark.parametrize(
    "overrides",
    [
        {"payload": "<%= 1 %>"},
        {"command": "id"},
        {"headers": {"X-Test": "x"}},
        {"target": "https://user:pass@lab.test/"},
        {"target": "https://lab.test/?x=1"},
        {"url": "https://lab.test/", "target": "https://lab.test/"},
        {"endpointPath": "//evil.test/"},
        {"endpointPath": "/probe?x=1"},
        {"endpointPath": "/probe#frag"},
        {"endpointPath": "/a/../probe"},
        {"injectionParameter": "sessionToken"},
        {"injectionParameter": "bad field"},
        {"expectedProbeStatus": 600},
        {"engagement": "standard"},
        {"allowUnsafeMethods": False},
        {"timeoutSeconds": 2},
        {"timeoutSeconds": 31},
    ],
)
def test_runtime_validation_rejects_unbounded_scope_and_forbidden_parameters(overrides):
    assert validate_probe_parameters(_runtime_parameters(**overrides))[0] is False


def test_runtime_validation_accepts_target_alias_and_rejects_lab_only_fields():
    parameters = _runtime_parameters()
    parameters["url"] = parameters.pop("target")
    assert validate_probe_parameters(parameters) == (True, "")
    assert validate_probe_parameters(
        _runtime_parameters(_agent=object())
    ) == (True, "")
    assert validate_probe_parameters(
        _runtime_parameters(
            _job_id="job-1280",
            _job_timeout_seconds=3600,
        )
    ) == (True, "")
    assert validate_probe_parameters(_runtime_parameters(_payload="owned"))[0] is False
    assert validate_probe_parameters(
        _runtime_parameters(effectTargetPath="/tmp/disposable.txt")
    )[0] is False
    assert validate_probe_parameters(_runtime_parameters(stateChangeApproved=True))[0] is False


@pytest.mark.parametrize(
    "path",
    [
        "/home/carlos/morale.txt",
        "/home/xasm/disposable-marker",
        "/tmp/xasm-ssti-proof.txt",
        "/var/tmp/test-fixture.dat",
    ],
)
def test_effect_path_accepts_only_normalized_disposable_roots(path):
    assert validate_effect_target_path(path) == path


@pytest.mark.parametrize(
    "path",
    [
        "",
        "tmp/file",
        "/home/",
        "/tmp",
        "/etc/xasm.txt",
        "/opt/test.txt",
        "/tmp/../etc/passwd",
        "/tmp/file..txt",
        "/tmp//proof.txt",
        "/tmp/./proof.txt",
        "/tmp/proof file",
        "/tmp/*.txt",
        '/tmp/"proof"',
        "/tmp/#{ENV.to_s}",
        "/tmp/file(1).txt",
        "/tmp/file;id",
        "/tmp/file|id",
        "/tmp/file$HOME",
        "/tmp/proof\nfile",
        "/home/user/.ssh/fixture",
        "/home/user/id_rsa",
        "/home/user/authorized_keys",
        "/tmp/passwd",
        "/tmp/shadow",
        "/tmp/.env",
        "/tmp/hosts",
        "/tmp/resolv.conf",
        "/tmp/app.conf",
        "/tmp/config.json",
        "/tmp/client.key",
    ],
)
def test_effect_path_rejects_traversal_globs_quotes_and_critical_files(path):
    assert validate_effect_target_path(path) is None


def test_lab_validation_requires_effect_approval_markers_statuses_and_lab_scope():
    assert validate_probe_parameters(_lab_parameters()) == (True, "")
    assert validate_probe_parameters(_lab_parameters(engagement="ctf")) == (True, "")
    assert validate_probe_parameters(_lab_parameters(engagement="aggressive"))[0] is False
    assert validate_probe_parameters(_lab_parameters(stateChangeApproved=False))[0] is False
    assert validate_probe_parameters(_lab_parameters(statusPath="/?status=1"))[0] is False
    assert validate_probe_parameters(
        _lab_parameters(solvedMarker="Lab status: Not solved")
    )[0] is False
    assert validate_probe_parameters(_lab_parameters(expectedEffectStatus=199))[0] is False
    assert validate_probe_parameters(
        _lab_parameters(effectTargetPath="/etc/passwd")
    )[0] is False


def test_payload_builder_uses_only_the_reviewed_exact_erb_templates():
    payloads = build_probe_payloads(FIXED_NONCE, "/home/carlos/morale.txt")

    assert payloads == {
        "literal": f"xasm-ssti-{FIXED_NONCE}-literal",
        "arithmeticPrimary": (
            f'<%= "xasm-ssti-{FIXED_NONCE}-eval-" + (43*59).to_s %>'
        ),
        "arithmeticFingerprint": (
            f'<%= "xasm-ssti-{FIXED_NONCE}-fp-" + (61*67).to_s %>'
        ),
        "runtimeUid": (
            f'<%= "xasm-ssti-{FIXED_NONCE}-uid-" + Process.uid.to_s %>'
        ),
        "effect": '<%= File.delete("/home/carlos/morale.txt") %>',
    }
    with pytest.raises(ValueError, match="nonce"):
        build_probe_payloads("short")
    with pytest.raises(ValueError, match="approved"):
        build_probe_payloads(FIXED_NONCE, "/etc/passwd")


@pytest.mark.asyncio
async def test_runtime_evaluation_emits_exact_four_gets_and_typed_proof(
    monkeypatch,
):
    monkeypatch.setattr("tools.web_ssti_probe.secrets.token_hex", lambda _size: FIXED_NONCE)
    tool = SstiProbeTool()
    queued = _runtime_success_responses()
    calls = []

    async def fake_request(_session, url):
        calls.append(url)
        return queued.pop(0)

    monkeypatch.setattr(tool, "_request", fake_request)
    output = await tool.execute(_runtime_parameters())

    assert output["success"] is True
    assert output["fallback"] is False
    assert output["requestCount"] == 4
    assert len(calls) == 4
    assert all(url.startswith("https://lab.test/?message=") for url in calls)
    assert [_payload_from_url(url) for url in calls] == list(
        build_probe_payloads(FIXED_NONCE).values()
    )

    verification = output["verification"]
    assert verification["verified"] is True
    assert verification["proofLevel"] == "runtime-evaluation"
    assert verification["nonce"] == FIXED_NONCE
    assert verification["requestCount"] == 4
    assert verification["baselineRequests"] == 0
    assert verification["controlRequests"] == 1
    assert verification["evaluationRequests"] == 3
    assert verification["effectRequests"] == 0
    assert verification["solvedChecks"] == 0
    assert verification["redirectsFollowed"] is False
    assert verification["literalControlReflected"] is True
    assert verification["arithmeticPrimaryEvaluated"] is True
    assert verification["erbFingerprintConfirmed"] is True
    assert verification["runtimeUidEvaluated"] is True
    assert set(verification["payloads"]) == {
        "literal",
        "arithmeticPrimary",
        "arithmeticFingerprint",
        "runtimeUid",
    }
    assert [step["label"] for step in verification["httpEvidence"]["steps"]] == list(
        EXPECTED_RUNTIME_STEP_LABELS
    )
    assert [step["carrierRole"] for step in verification["httpEvidence"]["steps"]] == [
        "literal-control",
        "arithmetic-primary",
        "arithmetic-fingerprint",
        "runtime-uid",
    ]
    assert all(
        step["request"].startswith("GET /?message=")
        and step["responseExcerptTruncated"] is False
        for step in verification["httpEvidence"]["steps"]
    )
    assert output["findings"][0]["evidence"] is verification


@pytest.mark.asyncio
async def test_lab_state_change_emits_exact_seven_gets_with_effect_last(
    monkeypatch,
):
    monkeypatch.setattr("tools.web_ssti_probe.secrets.token_hex", lambda _size: FIXED_NONCE)
    tool = SstiProbeTool()
    queued = [
        _response(body="Lab status: Not solved"),
        *_runtime_success_responses(),
        _response(body="File removed"),
        _response(body="Congratulations, you solved the lab!"),
    ]
    calls = []

    async def fake_request(_session, url):
        calls.append(url)
        return queued.pop(0)

    monkeypatch.setattr(tool, "_request", fake_request)
    output = await tool.execute(_lab_parameters(endpointPath="/product"))

    assert output["success"] is True
    assert output["requestCount"] == 7
    assert calls[0] == "https://lab.test/"
    assert calls[6] == "https://lab.test/"
    assert _payload_from_url(calls[5]) == (
        '<%= File.delete("/home/carlos/morale.txt") %>'
    )
    verification = output["verification"]
    assert verification["baselineRequests"] == 1
    assert verification["controlRequests"] == 1
    assert verification["evaluationRequests"] == 3
    assert verification["effectRequests"] == 1
    assert verification["solvedChecks"] == 1
    assert verification["solvedBefore"] is False
    assert verification["effectTriggered"] is True
    assert verification["solvedAfter"] is True
    assert verification["effectTargetPath"] == "/home/carlos/morale.txt"
    assert [step["label"] for step in verification["httpEvidence"]["steps"]] == list(
        EXPECTED_LAB_STEP_LABELS
    )
    assert [step["carrierRole"] for step in verification["httpEvidence"]["steps"]] == [
        "none",
        "literal-control",
        "arithmetic-primary",
        "arithmetic-fingerprint",
        "runtime-uid",
        "approved-effect",
        "none",
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("responses", "expected_count", "error_fragment"),
    [
        (
            [
                _response(body=f"xasm-ssti-{FIXED_NONCE}-literal"),
                _response(body="A natural number: 2537"),
            ],
            2,
            "primary marker",
        ),
        (
            [
                _response(
                    body=(
                        f"xasm-ssti-{FIXED_NONCE}-literal "
                        f"xasm-ssti-{FIXED_NONCE}-eval-2537"
                    )
                )
            ],
            1,
            "outside its owning step",
        ),
        (
            [
                _response(
                    body=(
                        f"xasm-ssti-{FIXED_NONCE}-literal "
                        f"xasm-ssti-{FIXED_NONCE}-literal"
                    )
                )
            ],
            1,
            "missing or ambiguous",
        ),
        (
            [
                _response(body=f"xasm-ssti-{FIXED_NONCE}-literal"),
                _response(
                    body=(
                        f"xasm-ssti-{FIXED_NONCE}-eval-2537 "
                        f"xasm-ssti-{FIXED_NONCE}-eval-2537"
                    )
                ),
            ],
            2,
            "missing, ambiguous",
        ),
        (
            [
                _response(body=f"xasm-ssti-{FIXED_NONCE}-literal"),
                _response(
                    body=(
                        f"xasm-ssti-{FIXED_NONCE}-eval-2537 "
                        f'&lt;%= &quot;xasm-ssti-{FIXED_NONCE}-eval-&quot; '
                        "+ (43*59).to_s %&gt;"
                    )
                ),
            ],
            2,
            "reflected raw",
        ),
    ],
)
async def test_false_positives_natural_numbers_cross_step_markers_and_reflection_fail_closed(
    monkeypatch,
    responses,
    expected_count,
    error_fragment,
):
    monkeypatch.setattr("tools.web_ssti_probe.secrets.token_hex", lambda _size: FIXED_NONCE)
    tool = SstiProbeTool()
    queued = list(responses)

    async def fake_request(_session, _url):
        return queued.pop(0)

    monkeypatch.setattr(tool, "_request", fake_request)
    output = await tool.execute(_runtime_parameters())

    assert output["success"] is False
    assert output["fallback"] is False
    assert output["requestCount"] == expected_count
    assert output["findings"] == []
    assert error_fragment in output["error"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("bad_response", "error_fragment"),
    [
        (_response(status=500, body="error"), "unexpected status"),
        (_response(body="partial", truncated=True), "truncated"),
        (
            _response(status=302, headers={"Location": "/next"}),
            "redirected",
        ),
        (
            _response(status=200, body="ignored", redirected=True),
            "redirected",
        ),
    ],
)
async def test_wrong_status_truncation_and_redirects_fail_before_evaluation(
    monkeypatch,
    bad_response,
    error_fragment,
):
    monkeypatch.setattr("tools.web_ssti_probe.secrets.token_hex", lambda _size: FIXED_NONCE)
    tool = SstiProbeTool()

    async def fake_request(_session, _url):
        return bad_response

    monkeypatch.setattr(tool, "_request", fake_request)
    output = await tool.execute(_runtime_parameters())

    assert output["success"] is False
    assert output["requestCount"] == 1
    assert output["evaluationRequests"] == 0
    assert output["findings"] == []
    assert error_fragment in output["error"]


@pytest.mark.asyncio
async def test_timeout_or_tls_transport_failure_returns_no_finding(monkeypatch):
    tool = SstiProbeTool()

    async def fake_request(_session, _url):
        raise aiohttp.ClientConnectorCertificateError(
            connection_key=None,
            certificate_error=ValueError("certificate verify failed"),
        )

    monkeypatch.setattr(tool, "_request", fake_request)
    output = await tool.execute(_runtime_parameters())

    assert output["success"] is False
    assert output["fallback"] is False
    assert output["requestCount"] == 0
    assert output["findings"] == []


@pytest.mark.asyncio
async def test_solved_before_stops_lab_proof_before_literal_or_effect(monkeypatch):
    tool = SstiProbeTool()
    calls = []

    async def fake_request(_session, url):
        calls.append(url)
        return _response(body="Congratulations, you solved the lab!")

    monkeypatch.setattr(tool, "_request", fake_request)
    output = await tool.execute(_lab_parameters())

    assert output["success"] is False
    assert output["requestCount"] == 1
    assert output["baselineRequests"] == 1
    assert output["controlRequests"] == 0
    assert output["effectRequests"] == 0
    assert len(calls) == 1
    assert "fresh unsolved state" in output["error"]


@pytest.mark.asyncio
async def test_effect_failure_occurs_after_all_read_only_probes_and_skips_confirmation(
    monkeypatch,
):
    monkeypatch.setattr("tools.web_ssti_probe.secrets.token_hex", lambda _size: FIXED_NONCE)
    tool = SstiProbeTool()
    queued = [
        _response(body="Lab status: Not solved"),
        *_runtime_success_responses(),
        _response(status=500, body="failed"),
    ]
    calls = []

    async def fake_request(_session, url):
        calls.append(url)
        return queued.pop(0)

    monkeypatch.setattr(tool, "_request", fake_request)
    output = await tool.execute(_lab_parameters())

    assert output["success"] is False
    assert output["requestCount"] == 6
    assert output["evaluationRequests"] == 3
    assert output["effectRequests"] == 1
    assert output["solvedChecks"] == 0
    assert len(calls) == 6
    assert _payload_from_url(calls[-1]).startswith("<%= File.delete(")
    assert output["findings"] == []


def test_evidence_hashes_lengths_full_sanitized_transcripts_and_candidate_shape():
    response = _response(
        body=(
            f"xasm-ssti-{FIXED_NONCE}-eval-2537 "
            '{"session":"live-session"}'
        ),
        headers={
            "Content-Type": "text/html",
            "Set-Cookie": "session=live-session; HttpOnly",
        },
    )
    payload = build_probe_payloads(FIXED_NONCE)["arithmeticPrimary"]
    url = (
        "https://lab.test/?message=%3C%25%3D+%22xasm-ssti-"
        f"{FIXED_NONCE}-eval-%22%2B%2843%2A59%29.to_s+%25%3E"
    )
    step = build_http_evidence_step(
        "erb-arithmetic-primary",
        url,
        response,
        "arithmetic-primary",
        payload,
    )

    assert step["request"].startswith("GET /?message=")
    assert payload not in step["request"]
    assert "Set-Cookie: <redacted-runtime-secret>" in step["response"]
    assert "live-session" not in json.dumps(step)
    assert step["responseExcerptTruncated"] is False
    assert step["payloadSha256"] == hashlib.sha256(payload.encode()).hexdigest()
    assert step["requestSha256"] == hashlib.sha256(step["request"].encode()).hexdigest()
    assert step["responseSha256"] == hashlib.sha256(step["response"].encode()).hexdigest()
    body = step["response"].split("\r\n\r\n", 1)[1]
    assert step["responseBodySha256"] == hashlib.sha256(body.encode()).hexdigest()
    assert step["responseBodyLength"] == len(body.encode())

    verification = {
        "verified": True,
        "fallback": False,
        "mode": "erb-query-v1",
        "endpointPath": "/",
    }
    finding = build_nuclei_finding("https://lab.test/", verification)
    assert finding["template-id"] == "xasm-erb-ssti-verified-candidate"
    assert finding["info"]["severity"] == "high"
    assert finding["info"]["classification"]["cwe-id"] == ["CWE-1336"]
    assert finding["evidence"] is verification
