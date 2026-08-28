import base64
import hashlib
import hmac
import json
import re

from multidict import CIMultiDict
import pytest

from tools.web_authentication_probe import REDACTED_RUNTIME_SECRET
from tools.web_jwt_probe import (
    EXPECTED_STEP_LABELS,
    FIXED_TRAVERSAL_KID,
    JwtProbeError,
    JwtProbeTool,
    forge_kid_path_traversal_tokens,
    parse_compact_jwt,
    validate_probe_parameters,
)


def _b64(value):
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def _token(
    header=None,
    payload=None,
    secret=b"real-secret",
):
    header = header or {"alg": "HS256", "kid": "jwt-key"}
    payload = payload or {"iss": "lab", "sub": "wiener", "exp": 2_000_000_000}
    header_segment = _b64(json.dumps(header, separators=(",", ":")).encode())
    payload_segment = _b64(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_segment}.{payload_segment}".encode()
    signature = hmac.new(secret, signing_input, hashlib.sha256).digest()
    return f"{header_segment}.{payload_segment}.{_b64(signature)}"


ORIGINAL_TOKEN = _token()


def _parameters(**overrides):
    params = {
        "target": "https://lab.test/",
        "mode": "kid-path-traversal-empty-hmac",
        "proofLevel": "lab-state-change",
        "statusPath": "/",
        "privilegePath": "/admin",
        "effectPath": "/admin/delete?username=carlos",
        "expectedEffectLocation": "/admin",
        "cookieName": "session",
        "identityClaim": "sub",
        "sourceIdentity": "wiener",
        "targetIdentity": "administrator",
        "unsolvedMarker": "Not solved",
        "deniedMarker": "Admin interface only available",
        "privilegeMarker": "Administration panel",
        "solvedMarker": "Congratulations, you solved the lab!",
        "expectedStatusStatus": 200,
        "expectedDeniedStatus": 401,
        "expectedPrivilegeStatus": 200,
        "expectedEffectStatus": 302,
        "expectedSolvedStatus": 200,
        "engagement": "lab",
        "allowUnsafeMethods": True,
        "stateChangeApproved": True,
        "timeoutSeconds": 5,
        "authCookies": f"analytics=bounded; session={ORIGINAL_TOKEN}",
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


def test_registration_schema_and_metadata_expose_only_bounded_mode():
    tool = JwtProbeTool()

    assert tool.name == "web:jwt_probe"
    assert tool.metadata["category"] == "exploit-test"
    assert tool.schema["additionalProperties"] is False
    assert tool.schema["properties"]["mode"]["enum"] == [
        "kid-path-traversal-empty-hmac"
    ]
    assert tool.schema["properties"]["authCookies"]["x-hidden"] is True
    for forbidden in (
        "jwt",
        "sessionToken",
        "alg",
        "kid",
        "secret",
        "key",
        "headers",
        "body",
        "method",
        "jwk",
        "jku",
        "wordlist",
        "proxy",
        "verifyTls",
    ):
        assert forbidden not in tool.schema["properties"]


def test_validation_requires_injected_session_lab_scope_and_effect_approvals():
    assert validate_probe_parameters(_parameters()) == (True, "")
    assert validate_probe_parameters(_parameters(engagement="ctf")) == (True, "")
    assert validate_probe_parameters(_parameters(engagement="standard"))[0] is False
    assert validate_probe_parameters(_parameters(allowUnsafeMethods=False))[0] is False
    assert validate_probe_parameters(_parameters(stateChangeApproved=False))[0] is False
    assert validate_probe_parameters(_parameters(authCookies=""))[0] is False
    assert validate_probe_parameters(_parameters(cookie="session=short", authCookies=""))[0] is False
    assert validate_probe_parameters(_parameters(effectPath="//evil.test/delete"))[0] is False
    assert validate_probe_parameters(_parameters(target="https://user:pass@lab.test"))[0] is False
    assert validate_probe_parameters(_parameters(identityClaim="__proto__"))[0] is False
    assert validate_probe_parameters(_parameters(sourceIdentity="wiener user"))[0] is False
    assert validate_probe_parameters(_parameters(expectedDeniedStatus=600))[0] is False
    assert validate_probe_parameters(_parameters(timeoutSeconds=31))[0] is False


def test_parser_and_forge_preserve_exact_claims_and_add_causal_control():
    parsed = parse_compact_jwt(ORIGINAL_TOKEN, "sub", "wiener")
    forged = forge_kid_path_traversal_tokens(parsed, "sub", "administrator")

    control_parts = forged["controlToken"].split(".")
    attack_parts = forged["attackToken"].split(".")
    control_header = json.loads(base64.urlsafe_b64decode(control_parts[0] + "=="))
    attack_header = json.loads(base64.urlsafe_b64decode(attack_parts[0] + "=="))
    payload = json.loads(base64.urlsafe_b64decode(control_parts[1] + "=="))

    assert control_parts[1] == attack_parts[1]
    assert control_header["kid"] == "jwt-key"
    assert attack_header["kid"] == FIXED_TRAVERSAL_KID
    assert payload == {"exp": 2_000_000_000, "iss": "lab", "sub": "administrator"}
    assert forged["changedPayloadClaims"] == ["sub"]
    assert forged["changedHeaderMembers"] == ["kid"]
    assert forged["controlToken"] != forged["attackToken"]


@pytest.mark.parametrize(
    "token",
    [
        "a.b.c",
        _token(header={"alg": "none", "kid": "jwt-key"}),
        _token(header={"alg": "HS256"}),
        _token(payload={"sub": "other"}),
        _token(payload={"sub": "wiener", "roles": ["user"]}),
        _token(payload={"sub": "wiener", "nested": {"role": "user"}}),
        _token().replace(".", ".=", 1),
        _token() + ".extra",
    ],
)
def test_parser_rejects_malformed_wrong_algorithm_missing_kid_or_unbounded_claims(token):
    with pytest.raises(JwtProbeError):
        parse_compact_jwt(token, "sub", "wiener")


def test_parser_rejects_duplicate_json_keys():
    header = _b64(b'{"alg":"HS256","kid":"one","kid":"two"}')
    payload = _b64(b'{"sub":"wiener"}')
    signature = _b64(b"x" * 32)
    with pytest.raises(JwtProbeError, match="duplicate"):
        parse_compact_jwt(f"{header}.{payload}.{signature}", "sub", "wiener")


@pytest.mark.asyncio
async def test_execute_proves_seven_steps_without_persisting_jwts(monkeypatch):
    tool = JwtProbeTool()
    responses = [
        _response(200, "Not solved"),
        _response(401, "Admin interface only available"),
        _response(401, "Admin interface only available"),
        _response(200, "Administration panel"),
        _response(401, "Admin interface only available"),
        _response(302, "", {"Location": "/admin"}),
        _response(200, "Congratulations, you solved the lab!"),
    ]
    calls = []

    async def fake_request(_session, url, cookie_name="", cookie_value=""):
        calls.append((url, cookie_name, cookie_value))
        return responses[len(calls) - 1]

    monkeypatch.setattr(tool, "_request", fake_request)
    result = await tool.execute(_parameters())

    assert result["success"] is True
    assert result["fallback"] is False
    assert result["requestCount"] == 7
    verification = result["verification"]
    assert verification["originalDenied"] is True
    assert verification["emptyHmacOriginalKidDenied"] is True
    assert verification["traversalPrivilegeGranted"] is True
    assert verification["originalReplayDenied"] is True
    assert verification["effectTriggered"] is True
    assert verification["solvedAfter"] is True
    assert [step["label"] for step in verification["httpEvidence"]["steps"]] == list(
        EXPECTED_STEP_LABELS
    )
    assert [step["carrierRole"] for step in verification["httpEvidence"]["steps"]] == [
        "none",
        "original",
        "empty-hmac-original-kid",
        "kid-traversal",
        "original",
        "kid-traversal",
        "none",
    ]
    assert calls[0][2] == ""
    assert calls[1][2] == ORIGINAL_TOKEN
    control_token = calls[2][2]
    attack_token = calls[3][2]
    assert control_token != ORIGINAL_TOKEN
    assert attack_token != ORIGINAL_TOKEN
    assert control_token != attack_token
    assert calls[4][2] == ORIGINAL_TOKEN
    assert calls[5][2] == attack_token
    assert calls[6][2] == ""

    persisted = json.dumps(result)
    for secret in (ORIGINAL_TOKEN, control_token, attack_token, "real-secret"):
        assert secret not in persisted
    assert REDACTED_RUNTIME_SECRET in persisted
    assert FIXED_TRAVERSAL_KID in persisted
    assert all(
        step["responseExcerptTruncated"] is False
        for step in verification["httpEvidence"]["steps"]
    )


@pytest.mark.asyncio
async def test_failure_of_negative_control_stops_before_attack_or_effect(monkeypatch):
    tool = JwtProbeTool()
    responses = [
        _response(200, "Not solved"),
        _response(401, "Admin interface only available"),
        _response(200, "Administration panel"),
    ]
    calls = []

    async def fake_request(_session, url, cookie_name="", cookie_value=""):
        calls.append((url, cookie_name, cookie_value))
        return responses[len(calls) - 1]

    monkeypatch.setattr(tool, "_request", fake_request)
    result = await tool.execute(_parameters())

    assert result["success"] is False
    assert result["fallback"] is False
    assert result["requestCount"] == 3
    assert result["findings"] == []
    assert len(calls) == 3


@pytest.mark.asyncio
async def test_response_jwt_and_cookie_headers_are_structurally_redacted(monkeypatch):
    tool = JwtProbeTool()
    responses = [
        _response(
            200,
            f"Not solved reflected={_token(payload={'sub': 'stranger'})}",
            {"Set-Cookie": f"session={ORIGINAL_TOKEN}; Secure; HttpOnly"},
        ),
        _response(401, "Admin interface only available"),
        _response(401, "Admin interface only available"),
        _response(200, "Administration panel"),
        _response(401, "Admin interface only available"),
        _response(302, "", {"Location": "/admin"}),
        _response(200, "Congratulations, you solved the lab!"),
    ]
    calls = []

    async def fake_request(_session, url, cookie_name="", cookie_value=""):
        calls.append((url, cookie_name, cookie_value))
        return responses[len(calls) - 1]

    monkeypatch.setattr(tool, "_request", fake_request)
    result = await tool.execute(_parameters())
    serialized = json.dumps(result)

    assert result["success"] is True
    assert "Set-Cookie: <redacted-runtime-secret>" in serialized
    assert (
        re.search(
            r"[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}",
            serialized,
        )
        is None
    )
    assert ORIGINAL_TOKEN not in serialized
