import asyncio
import hashlib
import json
import re

from multidict import CIMultiDict
import pytest

from plugin_loader import PluginLoader
from tools.web_authentication_probe import REDACTED_RUNTIME_SECRET
from tools.web_file_upload_probe import (
    ATTACK_MIME,
    CONTROL_MIME,
    EXPECTED_LAB_STEP_LABELS,
    EXPECTED_RUNTIME_STEP_LABELS,
    FileUploadProbeError,
    FileUploadProbeTool,
    _canonical_file_part,
    _request_timeout_seconds,
    build_multipart_body,
    build_nuclei_finding,
    build_php_payload,
    parse_upload_form,
    validate_approved_read_path,
    validate_probe_parameters,
    validate_serve_path_template,
)


FIXED_NONCE = "0123456789abcdef0123456789abcdef"
SESSION = "analytics=bounded; session=server-owned-session-material"
AUTHORIZATION = "Bearer server-owned-authorization-material"
CONTROL_CSRF = "control-csrf-server-secret"
ATTACK_CSRF = "attack-csrf-server-secret"
READ_PATH = "/home/carlos/secret"
READ_VALUE = "0123456789ABCDEF0123456789ABCDEF"


def _runtime_parameters(**overrides):
    parameters = {
        "target": "https://lab.test/",
        "mode": "php-multipart-content-type-bypass-v1",
        "proofLevel": "runtime-execution",
        "uploadFormPath": "/my-account",
        "uploadPath": "/my-account/avatar",
        "servePathTemplate": "/files/avatars/{filename}",
        "fileField": "avatar",
        "expectedFormStatus": 200,
        "expectedControlUploadStatus": 200,
        "expectedControlRejectionMarker": "Only image files are allowed",
        "expectedAbsenceStatus": 404,
        "expectedAbsenceMarker": "Not Found",
        "expectedAttackUploadStatus": 200,
        "expectedAttackAcceptanceMarker": "has been uploaded",
        "expectedExecutionStatus": 200,
        "expectedCleanupStatus": 404,
        "engagement": "aggressive",
        "allowUnsafeMethods": True,
        "fileUploadApproved": True,
        "serverSideExecutionApproved": True,
        "stateChangeApproved": True,
        "selfCleanupApproved": True,
        "timeoutSeconds": 5,
        "authCookies": SESSION,
        "cookie": SESSION,
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
        solutionPath="/submitSolution",
        expectedStatusStatus=200,
        expectedSolutionStatus=200,
        expectedSolvedStatus=200,
        approvedReadPath=READ_PATH,
        sensitiveFileReadApproved=True,
        solutionSubmitApproved=True,
    )
    parameters.update(overrides)
    return parameters


def _response(
    status=200,
    body="",
    headers=None,
    truncated=False,
    redirected=False,
):
    return {
        "status": status,
        "reason": "Not Found" if status == 404 else "OK",
        "headers": CIMultiDict(headers or {}),
        "body": body,
        "truncated": truncated,
        "redirected": redirected,
    }


def _form(csrf, action="/my-account/avatar", extra=""):
    return (
        "<!doctype html><html><body>"
        f'<form method="POST" enctype="multipart/form-data" action="{action}">'
        f'<input type="hidden" name="csrf" value="{csrf}">'
        '<input type="hidden" name="user" value="wiener">'
        '<input type="file" name="avatar">'
        f"{extra}</form></body></html>"
    )


def _expected_marker():
    return "xasm-upload-" + hashlib.sha256(
        f"xasm-file-upload:{FIXED_NONCE}".encode("ascii")
    ).hexdigest()


def _runtime_success_responses():
    return [
        _response(body=_form(CONTROL_CSRF), headers={"Set-Cookie": "session=rotated"}),
        _response(body="Only image files are allowed"),
        _response(404, "Not Found"),
        _response(body=_form(ATTACK_CSRF)),
        _response(body="The file has been uploaded"),
        _response(body=_expected_marker()),
        _response(404, "Not Found"),
    ]


def _lab_success_responses():
    return [
        _response(body="Lab status: Not solved"),
        _response(body=_form(CONTROL_CSRF)),
        _response(body="Only image files are allowed"),
        _response(404, "Not Found"),
        _response(body=_form(ATTACK_CSRF)),
        _response(body="The file has been uploaded"),
        _response(body=f"{_expected_marker()}\n{READ_VALUE}"),
        _response(404, "Not Found"),
        _response(
            body='{"correct":true}',
            headers={"Content-Type": "application/json"},
        ),
        _response(body="Congratulations, you solved the lab!"),
    ]


def test_schema_metadata_and_hidden_auth_expose_only_one_bounded_mode():
    tool = FileUploadProbeTool()

    assert tool.name == "web:file_upload_probe"
    assert tool.metadata["category"] == "exploit-test"
    assert tool.metadata["phase"] == 4
    assert tool.metadata["purpose_count"] == "single"
    assert tool.schema["additionalProperties"] is False
    assert tool.schema["properties"]["mode"]["enum"] == [
        "php-multipart-content-type-bypass-v1"
    ]
    assert tool.schema["properties"]["proofLevel"]["enum"] == [
        "lab-state-change",
        "runtime-execution",
    ]
    for field in ("authCookies", "cookie", "authHeaders"):
        assert tool.schema["properties"][field]["x-hidden"] is True
        assert tool.schema["properties"][field]["x-workflow-owned"] is True
    assert tool.schema["properties"]["authHeaders"]["additionalProperties"] is False
    assert set(tool.schema["properties"]["authHeaders"]["properties"]) == {
        "Authorization"
    }
    for forbidden in (
        "payload",
        "php",
        "command",
        "cmd",
        "filename",
        "extension",
        "fileMime",
        "mime",
        "boundary",
        "headers",
        "body",
        "rawBody",
        "rawRequest",
        "proxy",
        "callback",
        "alternateOrigin",
        "method",
        "answer",
        "username",
        "password",
    ):
        assert forbidden not in tool.schema["properties"]


def test_schema_normalization_and_runtime_private_handles_are_accepted():
    tool = FileUploadProbeTool()
    parameters = _runtime_parameters()

    assert PluginLoader({})._normalize_parameters(parameters, tool.schema) == parameters
    assert validate_probe_parameters(parameters) == (True, "")
    assert validate_probe_parameters(
        {
            **parameters,
            "_agent": object(),
            "_job_id": "job-1282",
            "_job_timeout_seconds": 120.0,
        }
    ) == (True, "")


def test_target_accepts_only_a_pure_origin():
    without_slash = _runtime_parameters(target="https://lab.test")
    assert validate_probe_parameters(without_slash) == (True, "")
    assert validate_probe_parameters(
        _runtime_parameters(target="https://lab.test/")
    ) == (True, "")
    assert validate_probe_parameters(
        _runtime_parameters(target="https://lab.test/base")
    )[0] is False

    url_parameters = _runtime_parameters()
    url_parameters.pop("target")
    url_parameters["url"] = "https://lab.test"
    assert validate_probe_parameters(url_parameters) == (True, "")
    url_parameters["url"] = "https://lab.test/base"
    assert validate_probe_parameters(url_parameters)[0] is False


def test_request_timeout_reserves_watchdog_budget_for_cleanup():
    parameters = _lab_parameters(
        timeoutSeconds=30,
        _job_timeout_seconds=120.0,
    )
    request_timeout = _request_timeout_seconds(parameters)

    assert request_timeout == pytest.approx(9.0)
    assert request_timeout * 12 < parameters["_job_timeout_seconds"]
    assert _request_timeout_seconds(
        _runtime_parameters(timeoutSeconds=5, _job_timeout_seconds=120.0)
    ) == pytest.approx(5.0)


@pytest.mark.parametrize(
    "overrides",
    [
        {"target": "https://user:pass@lab.test/"},
        {"target": "https://lab.test/?next=x"},
        {"url": "https://lab.test/"},
        {"mode": "generic-upload"},
        {"proofLevel": "arbitrary"},
        {"uploadFormPath": "//evil.test/form"},
        {"uploadFormPath": "/form?x=1"},
        {"uploadPath": "/a/../upload"},
        {"servePathTemplate": "/files/{filename}.php"},
        {"servePathTemplate": "https://evil.test/{filename}"},
        {"fileField": "bad field"},
        {"expectedFormStatus": 302},
        {"expectedControlUploadStatus": 500},
        {"expectedAbsenceStatus": 200},
        {"expectedAttackUploadStatus": 400},
        {"expectedExecutionStatus": 302},
        {"expectedCleanupStatus": 200},
        {"expectedAttackUploadLocation": "/account"},
        {"expectedControlRejectionMarker": "same", "expectedAbsenceMarker": "same"},
        {"engagement": "standard"},
        {"allowUnsafeMethods": False},
        {"fileUploadApproved": False},
        {"serverSideExecutionApproved": False},
        {"stateChangeApproved": False},
        {"selfCleanupApproved": False},
        {"authCookies": "", "cookie": ""},
        {"authCookies": SESSION, "cookie": "session=different"},
        {"authHeaders": {"X-Test": "not-allowed"}},
        {"authHeaders": {"Authorization": "bad\nheader"}},
        {"timeoutSeconds": 31},
        {"payload": "<?php system($_GET['c']); ?>"},
        {"filename": "../shell.php"},
        {"headers": {"Cookie": "caller"}},
    ],
)
def test_runtime_validation_rejects_unbounded_or_caller_controlled_inputs(overrides):
    assert validate_probe_parameters(_runtime_parameters(**overrides))[0] is False


def test_control_status_200_and_server_injected_authorization_are_supported():
    parameters = _runtime_parameters(
        authHeaders={"Authorization": AUTHORIZATION},
        expectedControlUploadStatus=200,
    )

    assert validate_probe_parameters(parameters) == (True, "")


def test_redirect_upload_requires_one_exact_same_origin_location():
    parameters = _runtime_parameters(
        expectedAttackUploadStatus=302,
        expectedAttackUploadLocation="/my-account",
    )

    assert validate_probe_parameters(parameters) == (True, "")
    assert validate_probe_parameters(
        _runtime_parameters(expectedAttackUploadStatus=302)
    )[0] is False
    assert validate_probe_parameters(
        _runtime_parameters(
            expectedAttackUploadStatus=302,
            expectedAttackUploadLocation="//evil.test",
        )
    )[0] is False


def test_lab_contract_is_conditional_and_runtime_omits_all_lab_inputs():
    assert validate_probe_parameters(_lab_parameters()) == (True, "")
    assert validate_probe_parameters(_lab_parameters(engagement="ctf")) == (True, "")
    assert validate_probe_parameters(_lab_parameters(engagement="aggressive"))[0] is False
    assert validate_probe_parameters(
        _lab_parameters(sensitiveFileReadApproved=False)
    )[0] is False
    assert validate_probe_parameters(
        _lab_parameters(solutionSubmitApproved=False)
    )[0] is False
    assert validate_probe_parameters(_runtime_parameters(statusPath="/"))[0] is False
    assert validate_probe_parameters(
        _runtime_parameters(sensitiveFileReadApproved=True)
    )[0] is False


@pytest.mark.parametrize(
    "path",
    [
        "/home/carlos/secret",
        "/home/test/proof.txt",
        "/tmp/xasm-upload-proof",
        "/var/tmp/xasm-proof.dat",
    ],
)
def test_approved_read_path_accepts_only_one_bounded_file(path):
    assert validate_approved_read_path(path) == path


@pytest.mark.parametrize(
    "path",
    [
        "",
        "home/carlos/secret",
        "/home/carlos/",
        "/home/carlos/nested/secret",
        "/home/carlos/../secret",
        "/home/carlos//secret",
        "/home/carlos/secret%00.php",
        "/etc/passwd",
        "/home/carlos/.ssh",
        "/home/carlos/id_rsa",
        "/home/carlos/private.pem",
        "/tmp/.env",
        "/tmp/*",
        '/tmp/"proof"',
        "/tmp/proof;id",
    ],
)
def test_approved_read_path_rejects_traversal_globs_and_critical_files(path):
    assert validate_approved_read_path(path) is None


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("/files/avatars/{filename}", True),
        ("/uploads/{filename}", True),
        ("/files/{filename}.php", False),
        ("/files/{filename}/raw", False),
        ("/files/{filename}?download=1", False),
        ("//evil.test/{filename}", False),
        ("/files/../{filename}", False),
    ],
)
def test_serve_template_has_one_terminal_filename_segment(value, expected):
    assert bool(validate_serve_path_template(value)) is expected


def test_form_parser_requires_one_exact_same_origin_post_multipart_form():
    parsed = parse_upload_form(
        _form(CONTROL_CSRF),
        "https://lab.test/my-account",
        "https://lab.test/",
        "/my-account/avatar",
        "avatar",
    )

    assert parsed["actionUrl"] == "https://lab.test/my-account/avatar"
    assert parsed["fileFields"] == ["avatar"]
    assert parsed["hiddenFields"] == [
        ("csrf", CONTROL_CSRF),
        ("user", "wiener"),
    ]
    assert parsed["csrfField"] == ("csrf", CONTROL_CSRF)


@pytest.mark.parametrize(
    "html",
    [
        _form(CONTROL_CSRF, action="https://evil.test/upload"),
        _form(CONTROL_CSRF, action="/other"),
        _form(CONTROL_CSRF) + _form(ATTACK_CSRF),
        _form(CONTROL_CSRF, extra='<input type="file" name="other">'),
        (
            '<form method="POST" enctype="multipart/form-data" '
            'action="/my-account/avatar"><input type="file" name="avatar"></form>'
        ),
        _form(CONTROL_CSRF, extra='<input type="hidden" name="csrf" value="two">'),
    ],
)
def test_form_parser_rejects_cross_origin_drift_ambiguity_and_bad_csrf(html):
    with pytest.raises(FileUploadProbeError):
        parse_upload_form(
            html,
            "https://lab.test/my-account",
            "https://lab.test/",
            "/my-account/avatar",
            "avatar",
        )


def test_payloads_are_exact_nonce_bound_self_deleting_and_never_a_shell():
    runtime = build_php_payload(FIXED_NONCE)
    lab = build_php_payload(FIXED_NONCE, READ_PATH)

    assert runtime == {
        "source": (
            "<?php echo 'xasm-upload-' . hash('sha256', "
            f"'xasm-file-upload:{FIXED_NONCE}'); @unlink(__FILE__); ?>"
        ),
        "expectedMarker": _expected_marker(),
    }
    assert lab == {
        "source": (
            f"<?php $value = trim((string) file_get_contents('{READ_PATH}')); "
            f"echo 'xasm-upload-' . hash('sha256', 'xasm-file-upload:{FIXED_NONCE}') "
            '. "\\n" . $value; @unlink(__FILE__); ?>'
        ),
        "expectedMarker": _expected_marker(),
    }
    combined = runtime["source"] + lab["source"]
    assert "system(" not in combined
    assert "exec(" not in combined
    assert "shell_exec" not in combined
    assert "$_GET" not in combined
    with pytest.raises(ValueError, match="nonce"):
        build_php_payload("short")
    with pytest.raises(ValueError, match="approved"):
        build_php_payload(FIXED_NONCE, "/etc/passwd")


def test_multipart_file_part_is_identical_except_for_the_tool_owned_mime():
    payload = build_php_payload(FIXED_NONCE)["source"].encode()
    filename = f"xasm-upload-{FIXED_NONCE}.php"
    hidden = [("csrf", CONTROL_CSRF), ("user", "wiener")]
    control_body, control_part = build_multipart_body(
        f"xasm{FIXED_NONCE}",
        hidden,
        "avatar",
        filename,
        CONTROL_MIME,
        payload,
    )
    attack_body, attack_part = build_multipart_body(
        f"xasm{FIXED_NONCE}",
        hidden,
        "avatar",
        filename,
        ATTACK_MIME,
        payload,
    )

    assert CONTROL_MIME.encode() in control_body
    assert ATTACK_MIME.encode() in attack_body
    assert _canonical_file_part(control_part) == _canonical_file_part(attack_part)
    assert control_part != attack_part
    assert control_part.startswith(
        b'Content-Disposition: form-data; name="avatar"; '
        b'filename="xasm-upload-'
    )
    assert not control_part.startswith(b"--")
    assert control_part.endswith(payload)


@pytest.mark.asyncio
async def test_runtime_proof_emits_exact_seven_steps_with_fresh_csrf_and_redaction(
    monkeypatch,
):
    monkeypatch.setattr(
        "tools.web_file_upload_probe.secrets.token_hex",
        lambda _size: FIXED_NONCE,
    )
    tool = FileUploadProbeTool()
    queued = _runtime_success_responses()
    calls = []

    async def fake_request(
        _session,
        method,
        url,
        cookie="",
        body=b"",
        content_type="",
        authorization="",
    ):
        calls.append(
            {
                "method": method,
                "url": url,
                "cookie": cookie,
                "body": body,
                "contentType": content_type,
                "authorization": authorization,
            }
        )
        return queued.pop(0)

    monkeypatch.setattr(tool, "_request", fake_request)
    output = await tool.execute(
        _runtime_parameters(
            target="https://lab.test",
            authHeaders={"Authorization": AUTHORIZATION},
        )
    )

    assert output["success"] is True
    assert output["fallback"] is False
    assert output["target"] == "https://lab.test/"
    assert output["remainingArtifacts"] == 0
    assert output["requestCount"] == 7
    verification = output["verification"]
    assert verification["verified"] is True
    assert verification["target"] == "https://lab.test/"
    assert verification["requestCount"] == 7
    assert verification["formRequests"] == 2
    assert verification["controlUploadRequests"] == 1
    assert verification["absenceRequests"] == 1
    assert verification["attackUploadRequests"] == 1
    assert verification["executionRequests"] == 1
    assert verification["cleanupRequests"] == 1
    assert verification["controlRejected"] is True
    assert verification["controlArtifactAbsent"] is True
    assert verification["attackAccepted"] is True
    assert verification["mimeOnlyDifferential"] is True
    assert verification["phpExecuted"] is True
    assert verification["cleanupVerified"] is True
    assert verification["multipartProof"]["changedLeafCount"] == 1
    assert verification["multipartProof"]["changedLeaf"] == "filePartContentType"
    assert verification["multipartProof"]["controlMime"] == CONTROL_MIME
    assert verification["multipartProof"]["attackMime"] == ATTACK_MIME
    assert [step["label"] for step in verification["httpEvidence"]["steps"]] == list(
        EXPECTED_RUNTIME_STEP_LABELS
    )
    assert [
        step["carrierRole"] for step in verification["httpEvidence"]["steps"]
    ] == [
        "authenticated-form",
        "disallowed-mime-control",
        "artifact-absence",
        "authenticated-form",
        "image-mime-attack",
        "executed-marker",
        "cleanup-receipt",
    ]
    assert len(calls) == 7
    assert [bool(call["cookie"]) for call in calls] == [
        True,
        True,
        False,
        True,
        True,
        False,
        False,
    ]
    assert [bool(call["authorization"]) for call in calls] == [
        True,
        True,
        False,
        True,
        True,
        False,
        False,
    ]
    assert CONTROL_CSRF.encode() in calls[1]["body"]
    assert ATTACK_CSRF.encode() not in calls[1]["body"]
    assert ATTACK_CSRF.encode() in calls[4]["body"]
    assert CONTROL_CSRF.encode() not in calls[4]["body"]
    assert CONTROL_MIME.encode() in calls[1]["body"]
    assert ATTACK_MIME.encode() in calls[4]["body"]

    persisted = json.dumps(output, ensure_ascii=False)
    for secret in (
        SESSION,
        AUTHORIZATION,
        CONTROL_CSRF,
        ATTACK_CSRF,
        "server-owned-session-material",
        "rotated",
        "wiener",
    ):
        assert secret not in persisted
    assert REDACTED_RUNTIME_SECRET in persisted
    assert f"Cookie: {REDACTED_RUNTIME_SECRET}" in persisted
    assert f"Authorization: {REDACTED_RUNTIME_SECRET}" in persisted
    assert f'name=\\"user\\"\\r\\n\\r\\n{REDACTED_RUNTIME_SECRET}' in persisted
    for lab_only in (
        "sensitiveFileReadApproved",
        "solutionSubmitApproved",
        "solvedBefore",
        "effectTriggered",
        "solvedAfter",
        "approvedReadPathSha256",
        "readValueSha256",
        "submittedAnswerSha256",
    ):
        assert lab_only not in verification


@pytest.mark.asyncio
async def test_lab_proof_emits_exact_ten_steps_and_value_linked_redacted_solve(
    monkeypatch,
):
    monkeypatch.setattr(
        "tools.web_file_upload_probe.secrets.token_hex",
        lambda _size: FIXED_NONCE,
    )
    tool = FileUploadProbeTool()
    queued = _lab_success_responses()
    calls = []

    async def fake_request(
        _session,
        method,
        url,
        cookie="",
        body=b"",
        content_type="",
        authorization="",
    ):
        calls.append((method, url, cookie, body, content_type, authorization))
        return queued.pop(0)

    monkeypatch.setattr(tool, "_request", fake_request)
    output = await tool.execute(_lab_parameters())

    assert output["success"] is True
    assert output["requestCount"] == 10
    verification = output["verification"]
    assert verification["requestCount"] == 10
    assert verification["baselineRequests"] == 1
    assert verification["formRequests"] == 2
    assert verification["solvedChecks"] == 2
    assert verification["solutionRequests"] == 1
    assert verification["sensitiveFileReadApproved"] is True
    assert verification["solutionSubmitApproved"] is True
    assert verification["statusPath"] == "/"
    assert verification["solutionPath"] == "/submitSolution"
    assert verification["solvedBefore"] is False
    assert verification["effectTriggered"] is True
    assert verification["solvedAfter"] is True
    assert verification["readValueSha256"] == hashlib.sha256(
        READ_VALUE.encode()
    ).hexdigest()
    assert verification["readValueSha256"] == verification["submittedAnswerSha256"]
    assert verification["readValueLength"] == verification["submittedAnswerLength"]
    assert [step["label"] for step in verification["httpEvidence"]["steps"]] == list(
        EXPECTED_LAB_STEP_LABELS
    )
    assert [
        step["carrierRole"] for step in verification["httpEvidence"]["steps"]
    ] == [
        "none",
        "authenticated-form",
        "disallowed-mime-control",
        "artifact-absence",
        "authenticated-form",
        "image-mime-attack",
        "scoped-secret",
        "cleanup-receipt",
        "approved-solution",
        "none",
    ]
    assert calls[8][3] == f"answer={READ_VALUE}".encode()
    assert READ_PATH.encode() in calls[2][3]
    assert READ_PATH.encode() in calls[5][3]
    assert [bool(call[2]) for call in calls] == [
        False,
        True,
        True,
        False,
        True,
        True,
        False,
        False,
        False,
        False,
    ]

    persisted = json.dumps(output, ensure_ascii=False)
    assert READ_PATH not in persisted
    assert READ_VALUE not in persisted
    assert CONTROL_CSRF not in persisted
    assert ATTACK_CSRF not in persisted
    execution_step = verification["httpEvidence"]["steps"][6]
    assert execution_step["response"].endswith(
        f"{_expected_marker()}\n{REDACTED_RUNTIME_SECRET}"
    )
    solution_step = verification["httpEvidence"]["steps"][8]
    assert solution_step["request"].endswith(
        f"answer={REDACTED_RUNTIME_SECRET}"
    )


@pytest.mark.asyncio
async def test_unexpected_control_acceptance_runs_best_effort_self_cleanup(
    monkeypatch,
):
    monkeypatch.setattr(
        "tools.web_file_upload_probe.secrets.token_hex",
        lambda _size: FIXED_NONCE,
    )
    tool = FileUploadProbeTool()
    queued = [
        _response(body=_form(CONTROL_CSRF)),
        _response(body="The file has been uploaded"),
        _response(body=_expected_marker()),
        _response(404, "Not Found"),
    ]
    calls = []

    async def fake_request(
        _session,
        method,
        url,
        cookie="",
        body=b"",
        content_type="",
        authorization="",
    ):
        calls.append((method, url, cookie, body, content_type, authorization))
        return queued.pop(0)

    monkeypatch.setattr(tool, "_request", fake_request)
    output = await tool.execute(_runtime_parameters())

    assert output["success"] is False
    assert output["findings"] == []
    assert output["createdArtifacts"] == 1
    assert output["cleanupAttempted"] is True
    assert output["cleanupVerifiedOnFailure"] is True
    assert output["remainingArtifacts"] == 0
    assert output["residualArtifactWarning"] is False
    assert [call[0] for call in calls] == ["GET", "POST", "GET", "GET"]


@pytest.mark.asyncio
async def test_source_disclosure_after_attack_cleans_up_and_returns_no_finding(
    monkeypatch,
):
    monkeypatch.setattr(
        "tools.web_file_upload_probe.secrets.token_hex",
        lambda _size: FIXED_NONCE,
    )
    tool = FileUploadProbeTool()
    payload_source = build_php_payload(FIXED_NONCE)["source"]
    queued = _runtime_success_responses()[:5] + [
        _response(body=payload_source),
        _response(body=_expected_marker()),
        _response(404, "Not Found"),
    ]

    async def fake_request(
        _session,
        _method,
        _url,
        _cookie="",
        _body=b"",
        _content_type="",
        _authorization="",
        **_kwargs,
    ):
        return queued.pop(0)

    monkeypatch.setattr(tool, "_request", fake_request)
    output = await tool.execute(_runtime_parameters())

    assert output["success"] is False
    assert output["findings"] == []
    assert "source" in output["error"].lower()
    assert output["cleanupAttempted"] is True
    assert output["cleanupVerifiedOnFailure"] is True
    assert output["remainingArtifacts"] == 0


@pytest.mark.asyncio
async def test_cancellation_after_attack_post_shields_bounded_cleanup(monkeypatch):
    monkeypatch.setattr(
        "tools.web_file_upload_probe.secrets.token_hex",
        lambda _size: FIXED_NONCE,
    )
    tool = FileUploadProbeTool()
    queued_before_cancel = [
        _response(body=_form(CONTROL_CSRF)),
        _response(body="Only image files are allowed"),
        _response(404, "Not Found"),
        _response(body=_form(ATTACK_CSRF)),
    ]
    cleanup_responses = [
        _response(body=_expected_marker()),
        _response(404, "Not Found"),
    ]
    calls = []

    async def fake_request(
        _session,
        method,
        url,
        cookie="",
        body=b"",
        content_type="",
        authorization="",
    ):
        calls.append((method, url, cookie, body, content_type, authorization))
        if queued_before_cancel:
            return queued_before_cancel.pop(0)
        if method == "POST" and ATTACK_MIME.encode() in body:
            raise asyncio.CancelledError
        return cleanup_responses.pop(0)

    monkeypatch.setattr(tool, "_request", fake_request)

    with pytest.raises(asyncio.CancelledError):
        await tool.execute(
            _runtime_parameters(
                _job_timeout_seconds=120.0,
                authHeaders={"Authorization": AUTHORIZATION},
            )
        )

    assert cleanup_responses == []
    assert [call[0] for call in calls] == [
        "GET",
        "POST",
        "GET",
        "GET",
        "POST",
        "GET",
        "GET",
    ]
    assert all(call[1].endswith(f"/files/avatars/xasm-upload-{FIXED_NONCE}.php") for call in calls[-2:])
    assert all(call[2] == SESSION for call in calls[-2:])
    assert all(call[5] == AUTHORIZATION for call in calls[-2:])


@pytest.mark.asyncio
async def test_cleanup_failure_returns_explicit_residual_artifact_warning(
    monkeypatch,
):
    monkeypatch.setattr(
        "tools.web_file_upload_probe.secrets.token_hex",
        lambda _size: FIXED_NONCE,
    )
    tool = FileUploadProbeTool()
    queued = _runtime_success_responses()[:6] + [
        _response(body="still present"),
        _response(body="still present"),
        _response(body="still present"),
    ]

    async def fake_request(
        _session,
        _method,
        _url,
        _cookie="",
        _body=b"",
        _content_type="",
        _authorization="",
        **_kwargs,
    ):
        return queued.pop(0)

    monkeypatch.setattr(tool, "_request", fake_request)
    output = await tool.execute(_runtime_parameters())

    assert output["success"] is False
    assert output["findings"] == []
    assert output["cleanupAttempted"] is True
    assert output["cleanupVerifiedOnFailure"] is False
    assert output["remainingArtifacts"] == 1
    assert output["residualArtifactWarning"] is True


@pytest.mark.asyncio
async def test_solved_before_truncation_and_ambiguous_form_fail_closed(monkeypatch):
    monkeypatch.setattr(
        "tools.web_file_upload_probe.secrets.token_hex",
        lambda _size: FIXED_NONCE,
    )

    for parameters, responses in (
        (
            _lab_parameters(),
            [_response(body="Congratulations, you solved the lab!")],
        ),
        (
            _runtime_parameters(),
            [_response(body=_form(CONTROL_CSRF), truncated=True)],
        ),
        (
            _runtime_parameters(),
            [_response(body=_form(CONTROL_CSRF) + _form(ATTACK_CSRF))],
        ),
    ):
        tool = FileUploadProbeTool()
        queued = list(responses)

        async def fake_request(
            _session,
            _method,
            _url,
            _cookie="",
            _body=b"",
            _content_type="",
            _authorization="",
            **_kwargs,
        ):
            return queued.pop(0)

        monkeypatch.setattr(tool, "_request", fake_request)
        output = await tool.execute(parameters)
        assert output["success"] is False
        assert output["fallback"] is False
        assert output["findings"] == []
        assert output["createdArtifacts"] == 0
        assert output["remainingArtifacts"] == 0


def test_candidate_finding_is_high_cwe_434_and_keyed_to_upload_endpoint():
    verification = {
        "verified": True,
        "uploadPath": "/my-account/avatar",
        "httpEvidence": {"version": 1, "steps": []},
    }
    finding = build_nuclei_finding("https://lab.test/", verification)

    assert finding["matched-at"] == "https://lab.test/my-account/avatar"
    assert finding["info"]["severity"] == "high"
    assert finding["info"]["classification"]["cwe-id"] == ["CWE-434"]
    assert finding["evidence"] is verification
