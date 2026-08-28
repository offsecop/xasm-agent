import json
import socket
from urllib.parse import parse_qs

from multidict import CIMultiDict
import pytest

from plugin_loader import PluginLoader
from tools.web_authentication_probe import REDACTED_RUNTIME_SECRET
from tools.web_oauth_probe import (
    AWS_ROLE_LIST_URL,
    EXPECTED_LAB_STEP_LABELS,
    EXPECTED_METADATA_STEP_LABELS,
    OAuthProbeError,
    OAuthProbeTool,
    PinnedPublicResolver,
    _resolve_public_addresses,
    build_nuclei_finding,
    build_registration_body,
    extract_oauth_provider_location,
    parse_credential_document,
    parse_oauth_provider_redirect,
    parse_oidc_discovery,
    parse_registration_response,
    parse_single_role,
    validate_logo_fetch_path_template,
    validate_probe_parameters,
)


APP_CLIENT_ID = "app-client-123"
ROLE_CLIENT_ID = "registered-role-client"
CREDENTIAL_CLIENT_ID = "registered-credential-client"
ROLE_CLIENT_SECRET = "role-client-secret-value"
CREDENTIAL_CLIENT_SECRET = "credential-client-secret-value"
ROLE_NAME = "xasm-test-role"
ACCESS_KEY_ID = "ASIAEXAMPLEACCESSKEY"
SECRET_ACCESS_KEY = "example-secret-access-key-material"
SESSION_TOKEN = "example-session-token-material"


def _parameters(**overrides):
    params = {
        "target": "https://app.test/",
        "providerOrigin": "https://oauth.provider.test",
        "mode": "openid-dynamic-registration-logo-ssrf-v1",
        "proofLevel": "metadata-proof",
        "oauthEntryPath": "/social-login",
        "callbackPath": "/oauth-callback",
        "logoFetchPathTemplate": "/client/{client_id}/logo",
        "engagement": "aggressive",
        "allowUnsafeMethods": True,
        "dynamicRegistrationApproved": True,
        "sensitiveMetadataReadApproved": True,
        "stateChangeApproved": True,
        "timeoutSeconds": 5,
    }
    params.update(overrides)
    return params


def _lab_parameters(**overrides):
    params = _parameters(
        proofLevel="lab-state-change",
        engagement="lab",
        statusPath="/",
        unsolvedMarker="Lab status: Not solved",
        solvedMarker="Congratulations, you solved the lab!",
        solutionPath="/submitSolution",
    )
    params.update(overrides)
    return params


def _response(status, body="", headers=None, truncated=False, redirected=False):
    return {
        "status": status,
        "reason": "Found" if 300 <= status < 400 else "OK",
        "headers": CIMultiDict(headers or {}),
        "body": body,
        "truncated": truncated,
        "redirected": redirected,
    }


def _provider_location(origin="https://oauth.provider.test"):
    return (
        f"{origin}/auth?client_id={APP_CLIENT_ID}"
        "&redirect_uri=https%3A%2F%2Fapp.test%2Foauth-callback"
        "&response_type=code&scope=openid"
    )


def _provider_meta_refresh(origin="https://oauth.provider.test"):
    return (
        "<!doctype html><html><head>"
        f"<meta http-equiv=refresh content='3;url={_provider_location(origin)}'>"
        "</head><body>Redirecting</body></html>"
    )


def _metadata_responses():
    return [
        _response(302, headers={"Location": _provider_location()}),
        _response(
            200,
            json.dumps(
                {
                    "issuer": "https://oauth.provider.test",
                    "authorization_endpoint": "https://oauth.provider.test/auth",
                    "token_endpoint": "https://oauth.provider.test/token",
                    "id_token_signing_alg_values_supported": [
                        "HS256",
                        "RS256",
                    ],
                    "registration_endpoint": "https://oauth.provider.test/reg",
                }
            ),
            {"Content-Type": "application/json"},
        ),
        _response(
            201,
            json.dumps(
                {
                    "client_id": ROLE_CLIENT_ID,
                    "client_secret": ROLE_CLIENT_SECRET,
                    "registration_access_token": "role-registration-token",
                }
            ),
            {"Content-Type": "application/json"},
        ),
        _response(200, ROLE_NAME + "\n", {"Content-Type": "text/plain"}),
        _response(
            201,
            json.dumps(
                {
                    "client_id": CREDENTIAL_CLIENT_ID,
                    "client_secret": CREDENTIAL_CLIENT_SECRET,
                    "registration_access_token": "credential-registration-token",
                }
            ),
            {"Content-Type": "application/json"},
        ),
        _response(
            200,
            json.dumps(
                {
                    "Code": "Success",
                    "AccessKeyId": ACCESS_KEY_ID,
                    "SecretAccessKey": SECRET_ACCESS_KEY,
                    "Token": SESSION_TOKEN,
                }
            ),
            {"Content-Type": "application/json"},
        ),
    ]


async def _public_addresses(_url):
    return [("203.0.113.10", socket.AF_INET)]


def test_registration_schema_and_metadata_expose_only_bounded_native_mode():
    tool = OAuthProbeTool()

    assert tool.name == "web:oauth_probe"
    assert tool.metadata["category"] == "exploit-test"
    assert tool.metadata["phase"] == 4
    assert tool.schema["additionalProperties"] is False
    assert tool.schema["properties"]["mode"]["enum"] == [
        "openid-dynamic-registration-logo-ssrf-v1"
    ]
    assert tool.schema["properties"]["providerOrigin"]["x-hidden"] is True
    assert tool.schema["properties"]["providerOrigin"]["x-workflow-owned"] is True
    for forbidden in (
        "role",
        "roleName",
        "metadataUrl",
        "logoUri",
        "registrationEndpoint",
        "discoveryUrl",
        "providerUrl",
        "redirectUri",
        "answer",
        "headers",
        "cookies",
        "cookie",
        "body",
        "rawBody",
        "method",
        "proxy",
        "oobUrl",
        "host",
        "port",
        "scheme",
    ):
        assert forbidden not in tool.schema["properties"]


def test_closed_schema_normalization_and_runtime_private_handles():
    tool = OAuthProbeTool()
    parameters = _parameters()
    normalized = PluginLoader({})._normalize_parameters(parameters, tool.schema)

    assert normalized == parameters
    assert validate_probe_parameters(parameters) == (True, "")
    assert (
        validate_probe_parameters(
            {
                **parameters,
                "_agent": object(),
                "_job_id": "00000000-0000-0000-0000-000000000000",
                "_job_timeout_seconds": 120.0,
            }
        )
        == (True, "")
    )


@pytest.mark.parametrize(
    "overrides",
    [
        {"providerOrigin": "http://oauth.provider.test"},
        {"providerOrigin": "https://user:pass@oauth.provider.test"},
        {"providerOrigin": "https://oauth.provider.test/path"},
        {"providerOrigin": "https://oauth.provider.test?next=x"},
        {"target": "https://user:pass@app.test/"},
        {"mode": "generic-oauth"},
        {"proofLevel": "arbitrary"},
        {"oauthEntryPath": "//evil.test/auth"},
        {"callbackPath": "/oauth/../callback"},
        {"logoFetchPathTemplate": "/client/{client_id}/image"},
        {"logoFetchPathTemplate": "/client/{client_id}/{client_id}/logo"},
        {"logoFetchPathTemplate": "https://evil.test/client/{client_id}/logo"},
        {"engagement": "standard"},
        {"allowUnsafeMethods": False},
        {"dynamicRegistrationApproved": False},
        {"sensitiveMetadataReadApproved": False},
        {"stateChangeApproved": False},
        {"timeoutSeconds": 31},
        {"headers": {"X-Test": "x"}},
        {"role": "admin"},
        {"metadataUrl": AWS_ROLE_LIST_URL},
    ],
)
def test_validation_rejects_unbounded_or_caller_owned_inputs(overrides):
    assert validate_probe_parameters(_parameters(**overrides))[0] is False


def test_validation_enforces_conditional_lab_contract_and_state_approval_for_both():
    assert validate_probe_parameters(_lab_parameters()) == (True, "")
    assert validate_probe_parameters(_lab_parameters(engagement="ctf")) == (True, "")
    assert validate_probe_parameters(_lab_parameters(engagement="aggressive"))[0] is False
    assert validate_probe_parameters(_lab_parameters(stateChangeApproved=False))[0] is False
    assert validate_probe_parameters(_lab_parameters(unsolvedMarker="same", solvedMarker="same"))[0] is False
    assert validate_probe_parameters(_lab_parameters(solutionPath="//evil.test"))[0] is False
    assert validate_probe_parameters(_parameters(statusPath="/"))[0] is False


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("/client/{client_id}/logo", True),
        ("/oidc/clients/{client_id}/logo", True),
        ("/client/{client_id}/logo.png", False),
        ("/client/{client_id}/logo?size=1", False),
        ("/client/%7Bclient_id%7D/logo", False),
        ("/client/../{client_id}/logo", False),
        ("/client/{client_id}/other/logo", False),
    ],
)
def test_logo_fetch_template_is_a_single_terminal_client_id_logo_path(value, expected):
    assert bool(validate_logo_fetch_path_template(value)) is expected


def test_oauth_redirect_must_derive_exact_authorized_provider_and_callback():
    proof = parse_oauth_provider_redirect(
        _provider_location(),
        "https://app.test",
        "https://oauth.provider.test",
        "https://app.test/oauth-callback",
    )

    assert proof == {
        "providerOrigin": "https://oauth.provider.test",
        "clientId": APP_CLIENT_ID,
        "redirectUri": "https://app.test/oauth-callback",
        "responseType": "code",
    }
    with pytest.raises(OAuthProbeError, match="authorized provider origin"):
        parse_oauth_provider_redirect(
            _provider_location("https://other.provider.test"),
            "https://app.test",
            "https://oauth.provider.test",
            "https://app.test/oauth-callback",
        )
    with pytest.raises(OAuthProbeError, match="workflow-owned callback"):
        parse_oauth_provider_redirect(
            (
                "https://oauth.provider.test/auth?client_id=x"
                "&redirect_uri=https%3A%2F%2Fevil.test%2Fcallback"
                "&response_type=code"
            ),
            "https://app.test",
            "https://oauth.provider.test",
            "https://app.test/oauth-callback",
        )
    with pytest.raises(OAuthProbeError, match="workflow-owned callback"):
        parse_oauth_provider_redirect(
            (
                "https://oauth.provider.test/auth?client_id=x"
                "&redirect_uri=https%3A%2F%2Fapp.test%2Fother-callback"
                "&response_type=code"
            ),
            "https://app.test",
            "https://oauth.provider.test",
            "https://app.test/oauth-callback",
        )
    with pytest.raises(OAuthProbeError, match="response_type"):
        parse_oauth_provider_redirect(
            (
                "https://oauth.provider.test/auth?client_id=x"
                "&redirect_uri=https%3A%2F%2Fapp.test%2Fcallback"
                "&response_type=unknown"
            ),
            "https://app.test",
            "https://oauth.provider.test",
            "https://app.test/oauth-callback",
        )


def test_oauth_location_accepts_one_bounded_header_or_meta_refresh():
    assert (
        extract_oauth_provider_location(
            _response(302, headers={"Location": _provider_location()})
        )
        == _provider_location()
    )
    assert (
        extract_oauth_provider_location(_response(200, _provider_meta_refresh()))
        == _provider_location()
    )


@pytest.mark.parametrize(
    "response",
    [
        _response(200, "<script>location='https://oauth.provider.test/auth'</script>"),
        _response(200, "<meta http-equiv=refresh content='11;url=https://oauth.provider.test/auth'>"),
        _response(200, "<meta http-equiv=refresh content='0;url=/relative'>"),
        _response(200, "<meta http-equiv=refresh content='0;url=https://oauth.provider.test/auth>"),
        _response(
            200,
            "<meta http-equiv=refresh content='0;url=https://oauth.provider.test/one'>"
            "<meta http-equiv=refresh content='0;url=https://oauth.provider.test/two'>",
        ),
        _response(
            200,
            "<meta http-equiv=refresh content='0;url=https://oauth.provider.test/auth'>",
            {"Location": "https://oauth.provider.test/other"},
        ),
        _response(302),
    ],
)
def test_oauth_location_rejects_missing_ambiguous_or_malformed_redirects(response):
    with pytest.raises(OAuthProbeError):
        extract_oauth_provider_location(response)


def test_oidc_discovery_and_registration_are_strict_same_origin_https():
    assert (
        parse_oidc_discovery(
            '{"registration_endpoint":"https://oauth.provider.test/reg"}',
            "https://oauth.provider.test",
        )
        == "https://oauth.provider.test/reg"
    )
    for document in (
        '{"registration_endpoint":"http://oauth.provider.test/reg"}',
        '{"registration_endpoint":"https://evil.test/reg"}',
        '{"registration_endpoint":"https://oauth.provider.test/reg?next=x"}',
        '{"registration_endpoint":"https://oauth.provider.test/reg","registration_endpoint":"https://evil.test"}',
    ):
        with pytest.raises(OAuthProbeError):
            parse_oidc_discovery(document, "https://oauth.provider.test")


def test_registration_builders_and_parsers_own_metadata_and_bound_secrets():
    body = build_registration_body(
        "xasm-oauth-0123456789abcdef-role-list",
        "https://app.test/oauth-callback",
        AWS_ROLE_LIST_URL,
    )

    assert json.loads(body) == {
        "client_name": "xasm-oauth-0123456789abcdef-role-list",
        "logo_uri": AWS_ROLE_LIST_URL,
        "redirect_uris": ["https://app.test/oauth-callback"],
    }
    client_id, sensitive = parse_registration_response(
        json.dumps(
            {
                "client_id": ROLE_CLIENT_ID,
                "client_secret": ROLE_CLIENT_SECRET,
                "registration_access_token": "registration-token",
            }
        )
    )
    assert client_id == ROLE_CLIENT_ID
    assert ROLE_CLIENT_ID in sensitive
    assert ROLE_CLIENT_SECRET in sensitive
    assert "registration-token" in sensitive
    assert parse_single_role(f"  {ROLE_NAME}\n") == ROLE_NAME
    with pytest.raises(OAuthProbeError):
        parse_single_role("first-role\nsecond-role")

    credentials = parse_credential_document(
        json.dumps(
            {
                "AccessKeyId": ACCESS_KEY_ID,
                "SecretAccessKey": SECRET_ACCESS_KEY,
                "Token": SESSION_TOKEN,
            }
        )
    )
    assert credentials["AccessKeyId"] == ACCESS_KEY_ID
    assert credentials["SecretAccessKey"] == SECRET_ACCESS_KEY
    with pytest.raises(OAuthProbeError):
        parse_credential_document(
            '{"AccessKeyId":"short","SecretAccessKey":"also-short"}'
        )
    with pytest.raises(OAuthProbeError):
        parse_credential_document(
            json.dumps(
                {
                    "AccessKeyId": ACCESS_KEY_ID,
                    "SecretAccessKey": SECRET_ACCESS_KEY,
                }
            )
        )


@pytest.mark.asyncio
async def test_dns_validation_rejects_private_literals_and_resolver_pins_only_hosts():
    with pytest.raises(OAuthProbeError, match="non-public"):
        await _resolve_public_addresses("https://127.0.0.1")
    assert await _resolve_public_addresses("https://8.8.8.8") == [
        ("8.8.8.8", socket.AF_INET)
    ]

    resolver = PinnedPublicResolver(
        {"oauth.provider.test": [("203.0.113.10", socket.AF_INET)]}
    )
    result = await resolver.resolve("oauth.provider.test", 443, socket.AF_INET)
    assert result[0]["host"] == "203.0.113.10"
    with pytest.raises(OSError, match="outside the pinned"):
        await resolver.resolve("rebinding.test", 443, socket.AF_INET)


@pytest.mark.asyncio
async def test_metadata_proof_emits_exact_six_requests_and_redacts_all_secrets(
    monkeypatch,
):
    tool = OAuthProbeTool()
    responses = _metadata_responses()
    calls = []

    async def fake_request(_session, method, url, body="", content_type=""):
        calls.append((method, url, body, content_type))
        return responses.pop(0)

    monkeypatch.setattr("tools.web_oauth_probe._resolve_public_addresses", _public_addresses)
    monkeypatch.setattr(tool, "_request", fake_request)
    output = await tool.execute(_parameters())

    assert output["success"] is True
    assert output["fallback"] is False
    assert output["requestCount"] == 6
    verification = output["verification"]
    assert verification["verified"] is True
    assert verification["providerOriginAuthorized"] is True
    assert verification["providerOriginDerived"] is True
    assert verification["registrationEndpointSameOrigin"] is True
    assert verification["registrationEndpoint"] == "https://oauth.provider.test/reg"
    assert verification["dnsPublicValidated"] is True
    assert verification["dnsPinned"] is True
    assert verification["createdArtifacts"] == 2
    assert verification["cleanupAvailable"] is False
    assert verification["cleanupAttempted"] is False
    assert verification["requestCount"] == 6
    assert verification["baselineRequests"] == 0
    assert verification["discoveryRequests"] == 2
    assert verification["registrationRequests"] == 2
    assert verification["logoFetchRequests"] == 2
    assert verification["effectRequests"] == 0
    assert verification["roleListFetched"] is True
    assert verification["singleRoleSelected"] is True
    assert verification["credentialsShapeVerified"] is True
    assert verification["secretMaterialRedacted"] is True
    assert verification["effectTriggered"] is False
    assert [step["label"] for step in verification["httpEvidence"]["steps"]] == list(
        EXPECTED_METADATA_STEP_LABELS
    )
    assert [call[0] for call in calls] == ["GET", "GET", "POST", "GET", "POST", "GET"]
    assert calls[0][1] == "https://app.test/social-login"
    assert calls[1][1] == (
        "https://oauth.provider.test/.well-known/openid-configuration"
    )
    assert calls[2][1] == "https://oauth.provider.test/reg"
    assert json.loads(calls[2][2])["logo_uri"] == AWS_ROLE_LIST_URL
    assert calls[3][1] == (
        f"https://oauth.provider.test/client/{ROLE_CLIENT_ID}/logo"
    )
    assert json.loads(calls[4][2])["logo_uri"] == (
        AWS_ROLE_LIST_URL + ROLE_NAME + "/"
    )
    assert calls[5][1] == (
        f"https://oauth.provider.test/client/{CREDENTIAL_CLIENT_ID}/logo"
    )
    assert output["findings"][0]["evidence"] is verification
    assert all(
        step["responseExcerptTruncated"] is False
        for step in verification["httpEvidence"]["steps"]
    )

    serialized = json.dumps(output)
    for secret in (
        APP_CLIENT_ID,
        ROLE_CLIENT_ID,
        CREDENTIAL_CLIENT_ID,
        ROLE_CLIENT_SECRET,
        CREDENTIAL_CLIENT_SECRET,
        "role-registration-token",
        "credential-registration-token",
        ROLE_NAME,
        ACCESS_KEY_ID,
        SECRET_ACCESS_KEY,
        SESSION_TOKEN,
    ):
        assert secret not in serialized
    assert REDACTED_RUNTIME_SECRET in serialized
    role_step = verification["httpEvidence"]["steps"][3]
    assert role_step["response"].endswith(
        f"\r\n\r\n{REDACTED_RUNTIME_SECRET}\n"
    )
    credential_step = verification["httpEvidence"]["steps"][5]
    assert f'"AccessKeyId": "{REDACTED_RUNTIME_SECRET}"' in credential_step["response"]
    assert f'"SecretAccessKey": "{REDACTED_RUNTIME_SECRET}"' in credential_step["response"]
    assert f'"Token": "{REDACTED_RUNTIME_SECRET}"' in credential_step["response"]
    discovery_step = verification["httpEvidence"]["steps"][1]
    discovery_body = discovery_step["response"].split("\r\n\r\n", 1)[1]
    discovery_document = json.loads(discovery_body)
    assert discovery_document["token_endpoint"] == "https://oauth.provider.test/token"
    assert discovery_document["id_token_signing_alg_values_supported"] == [
        "HS256",
        "RS256",
    ]


@pytest.mark.asyncio
async def test_metadata_proof_accepts_portable_200_meta_refresh_and_redacts_client_id(
    monkeypatch,
):
    tool = OAuthProbeTool()
    responses = _metadata_responses()
    responses[0] = _response(
        200,
        _provider_meta_refresh(),
        {"Content-Type": "text/html; charset=utf-8"},
    )
    calls = []

    async def fake_request(_session, method, url, body="", content_type=""):
        calls.append((method, url, body, content_type))
        return responses.pop(0)

    monkeypatch.setattr("tools.web_oauth_probe._resolve_public_addresses", _public_addresses)
    monkeypatch.setattr(tool, "_request", fake_request)
    output = await tool.execute(_parameters())

    assert output["success"] is True
    assert output["fallback"] is False
    assert output["requestCount"] == 6
    assert len(calls) == 6
    redirect_step = output["verification"]["httpEvidence"]["steps"][0]
    assert redirect_step["label"] == "oauth-provider-redirect"
    assert redirect_step["responseStatus"] == 200
    assert APP_CLIENT_ID not in redirect_step["response"]
    assert REDACTED_RUNTIME_SECRET in redirect_step["response"]


@pytest.mark.asyncio
async def test_lab_state_change_emits_exact_nine_requests_and_effect_last(
    monkeypatch,
):
    tool = OAuthProbeTool()
    responses = [
        _response(200, "Lab status: Not solved"),
        *_metadata_responses(),
        _response(200, '{"correct":true}', {"Content-Type": "application/json"}),
        _response(200, "Congratulations, you solved the lab!"),
    ]
    calls = []

    async def fake_request(_session, method, url, body="", content_type=""):
        calls.append((method, url, body, content_type))
        return responses.pop(0)

    monkeypatch.setattr("tools.web_oauth_probe._resolve_public_addresses", _public_addresses)
    monkeypatch.setattr(tool, "_request", fake_request)
    output = await tool.execute(_lab_parameters())

    assert output["success"] is True
    assert output["requestCount"] == 9
    verification = output["verification"]
    assert verification["baselineRequests"] == 1
    assert verification["registrationRequests"] == 2
    assert verification["effectRequests"] == 1
    assert verification["solvedChecks"] == 1
    assert verification["solvedBefore"] is False
    assert verification["effectTriggered"] is True
    assert verification["solvedAfter"] is True
    assert verification["baselineStatus"] == 200
    assert verification["solutionSubmitStatus"] == 200
    assert verification["solvedConfirmationStatus"] == 200
    assert verification["submittedAnswerSha256"] == (
        verification["credentialProof"]["secretAccessKeySha256"]
    )
    assert verification["submittedAnswerLength"] == (
        verification["credentialProof"]["secretAccessKeyLength"]
    )
    assert [step["label"] for step in verification["httpEvidence"]["steps"]] == list(
        EXPECTED_LAB_STEP_LABELS
    )
    assert calls[0] == ("GET", "https://app.test/", "", "")
    assert calls[-2][0:2] == ("POST", "https://app.test/submitSolution")
    assert parse_qs(calls[-2][2]) == {"answer": [SECRET_ACCESS_KEY]}
    assert calls[-1] == ("GET", "https://app.test/", "", "")
    persisted_submit = verification["httpEvidence"]["steps"][-2]["request"]
    assert "answer=<redacted-runtime-secret>" in persisted_submit
    assert SECRET_ACCESS_KEY not in json.dumps(output)


@pytest.mark.asyncio
async def test_solved_before_stops_before_provider_or_registration(monkeypatch):
    tool = OAuthProbeTool()
    calls = []

    async def fake_request(_session, method, url, body="", content_type=""):
        calls.append((method, url, body, content_type))
        return _response(200, "Congratulations, you solved the lab!")

    monkeypatch.setattr("tools.web_oauth_probe._resolve_public_addresses", _public_addresses)
    monkeypatch.setattr(tool, "_request", fake_request)
    output = await tool.execute(_lab_parameters())

    assert output["success"] is False
    assert output["fallback"] is False
    assert output["requestCount"] == 1
    assert output["createdArtifacts"] == 0
    assert output["cleanupAvailable"] is False
    assert output["cleanupAttempted"] is False
    assert output["findings"] == []
    assert len(calls) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("mutation", "expected_count", "expected_artifacts"),
    [
        (
            lambda responses: responses.__setitem__(
                0,
                _response(
                    302,
                    headers={
                        "Location": _provider_location(
                            "https://other.provider.test"
                        )
                    },
                ),
            ),
            1,
            0,
        ),
        (
            lambda responses: responses.__setitem__(
                1,
                _response(
                    200,
                    '{"registration_endpoint":"https://evil.test/reg"}',
                ),
            ),
            2,
            0,
        ),
        (
            lambda responses: responses.__setitem__(
                3,
                _response(200, "role-one\nrole-two"),
            ),
            4,
            1,
        ),
        (
            lambda responses: responses.__setitem__(
                5,
                _response(
                    200,
                    '{"AccessKeyId":"short","SecretAccessKey":"short"}',
                ),
            ),
            6,
            2,
        ),
        (
            lambda responses: responses.__setitem__(
                3,
                _response(200, ROLE_NAME, truncated=True),
            ),
            4,
            1,
        ),
    ],
)
async def test_fail_closed_controls_stop_without_finding(
    monkeypatch,
    mutation,
    expected_count,
    expected_artifacts,
):
    tool = OAuthProbeTool()
    responses = _metadata_responses()
    mutation(responses)
    calls = []

    async def fake_request(_session, method, url, body="", content_type=""):
        calls.append((method, url, body, content_type))
        return responses.pop(0)

    monkeypatch.setattr("tools.web_oauth_probe._resolve_public_addresses", _public_addresses)
    monkeypatch.setattr(tool, "_request", fake_request)
    output = await tool.execute(_parameters())

    assert output["success"] is False
    assert output["fallback"] is False
    assert output["requestCount"] == expected_count
    assert output["createdArtifacts"] == expected_artifacts
    assert output["cleanupAvailable"] is False
    assert output["cleanupAttempted"] is False
    assert output["findings"] == []
    assert len(calls) == expected_count


@pytest.mark.asyncio
async def test_private_dns_stops_before_any_request(monkeypatch):
    tool = OAuthProbeTool()
    calls = []

    async def private_addresses(_url):
        raise OAuthProbeError("authorized origin DNS returned a non-public address")

    async def fake_request(_session, method, url, body="", content_type=""):
        calls.append((method, url, body, content_type))
        return _response(500)

    monkeypatch.setattr("tools.web_oauth_probe._resolve_public_addresses", private_addresses)
    monkeypatch.setattr(tool, "_request", fake_request)
    output = await tool.execute(_parameters())

    assert output["success"] is False
    assert output["fallback"] is False
    assert output["requestCount"] == 0
    assert output["createdArtifacts"] == 0
    assert output["findings"] == []
    assert calls == []


def test_finding_is_high_cwe_918_and_carries_typed_proof():
    verification = {
        "verified": True,
        "fallback": False,
        "providerOrigin": "https://oauth.provider.test",
        "registrationEndpoint": "https://oauth.provider.test/reg",
    }

    finding = build_nuclei_finding("https://app.test/", verification)

    assert (
        finding["template-id"]
        == "xasm-oauth-oidc-dynamic-registration-ssrf-verified"
    )
    assert finding["matcher-name"] == "openid-dynamic-registration-logo-ssrf"
    assert finding["info"]["severity"] == "high"
    assert finding["info"]["classification"]["cwe-id"] == ["CWE-918"]
    assert finding["matched-at"] == "https://oauth.provider.test/reg"
    assert finding["evidence"] is verification
