from tools.web_prototype_pollution_probe import (
    JSON_SPACES_VALUE,
    STATUS_VALUE,
    PrototypePollutionProbeTool,
    build_http_evidence_step,
    build_nuclei_finding,
    build_polluted_body,
    extract_csrf_token,
    extract_status_values,
    json_indentation_score,
    sanitize_evidence_text,
    validate_probe_parameters,
    verify_oracle,
)


def _parameters(**overrides):
    params = {
        "endpoint": "https://lab.test/api/profile",
        "method": "POST",
        "baselineBody": {"name": "xasm"},
        "vector": "__proto__",
        "oracle": "json-spaces",
        "engagement": "lab",
        "allowUnsafeMethods": True,
    }
    params.update(overrides)
    return params


def test_registration_and_schema_are_bounded_to_safe_oracles():
    tool = PrototypePollutionProbeTool()

    assert tool.name == "web:prototype_pollution_probe"
    assert tool.metadata["category"] == "exploit-test"
    assert tool.schema["properties"]["oracle"]["enum"] == ["json-spaces", "status"]
    assert "property" not in tool.schema["properties"]
    assert "command" not in tool.schema["properties"]
    assert "oobUrl" not in tool.schema["properties"]


def test_validation_requires_explicit_high_risk_engagement_and_json_object():
    assert validate_probe_parameters(_parameters()) == (True, "")
    assert validate_probe_parameters(_parameters(engagement="standard"))[0] is False
    assert validate_probe_parameters(_parameters(allowUnsafeMethods=False))[0] is False
    assert validate_probe_parameters(_parameters(baselineBody="{}"))[0] is False
    assert validate_probe_parameters(_parameters(baselineBody={"__proto__": {"x": 1}}))[0] is False


def test_validation_requires_same_origin_csrf_source_and_named_fields():
    valid = _parameters(
        csrfSourceUrl="https://lab.test/account",
        csrfTokenName="sessionId",
        csrfBodyField="sessionId",
    )
    assert validate_probe_parameters(valid) == (True, "")
    assert validate_probe_parameters({**valid, "csrfSourceUrl": "https://evil.test/account"})[0] is False
    assert validate_probe_parameters({**valid, "csrfTokenName": ""})[0] is False


def test_polluted_body_supports_both_vectors_without_mutating_baseline():
    baseline = {"name": "xasm"}
    proto, prop, value = build_polluted_body(baseline, "__proto__", "json-spaces")
    constructor, status_prop, status_value = build_polluted_body(
        baseline, "constructor.prototype", "status"
    )

    assert baseline == {"name": "xasm"}
    assert proto["__proto__"] == {"json spaces": JSON_SPACES_VALUE}
    assert (prop, value) == ("json spaces", JSON_SPACES_VALUE)
    assert constructor["constructor"]["prototype"] == {"status": STATUS_VALUE}
    assert (status_prop, status_value) == ("status", STATUS_VALUE)


def test_csrf_extraction_handles_input_json_and_assignment_without_leaking_context():
    assert extract_csrf_token('<input value="abc123" name="sessionId">', "sessionId") == "abc123"
    assert extract_csrf_token('{"sessionId":"json-token"}', "sessionId") == "json-token"
    assert extract_csrf_token("window.sessionId = 'js-token';", "sessionId") == "js-token"
    assert extract_csrf_token('<input name="other" value="nope">', "sessionId") is None


def test_json_spaces_oracle_requires_clean_baseline_and_material_delta():
    compact = '{"name":"xasm"}'
    pretty = '{\n          "name": "xasm"\n}'

    assert json_indentation_score(compact) == 0
    assert json_indentation_score(pretty) == 10
    proof = verify_oracle("json-spaces", {"body": compact}, {"body": pretty})
    assert proof == {
        "verified": True,
        "baselineIndent": 0,
        "probeIndent": 10,
        "indentDelta": 10,
        "oracleValue": 10,
    }
    assert verify_oracle("json-spaces", {"body": pretty}, {"body": pretty})["verified"] is False


def test_status_oracle_requires_marker_absent_before_and_present_after():
    baseline = '{"error":"bad json","status":400,"statusCode":400}'
    probe = '{"error":"bad json","status":555,"statusCode":555}'

    assert extract_status_values(baseline) == (400, 400)
    proof = verify_oracle("status", {"body": baseline}, {"body": probe})
    assert proof["verified"] is True
    assert proof["oracleValue"] == STATUS_VALUE
    assert verify_oracle("status", {"body": probe}, {"body": probe})["verified"] is False


def test_http_evidence_redacts_runtime_secrets_without_destroying_indentation():
    raw = '{\n          "sessionId": "live-token",\n          "address": "xasm"\n}'
    sanitized = sanitize_evidence_text(raw, ("live-token",))

    assert "live-token" not in sanitized
    assert '"sessionId": "<redacted-runtime-secret>"' in sanitized
    assert '\n          "address"' in sanitized

    step = build_http_evidence_step(
        "pollution-probe",
        '{"sessionId":"live-token","__proto__":{"json spaces":10}}',
        {"status": 200, "contentType": "application/json", "body": raw},
        ("live-token",),
    )
    assert step["requestBody"] == (
        '{"sessionId":"<redacted-runtime-secret>","__proto__":{"json spaces":10}}'
    )
    assert step["responseStatus"] == 200
    assert step["responseBodyLength"] == len(raw.encode())
    assert len(step["responseBodySha256"]) == 64
    assert "live-token" not in str(step)


def test_finding_shape_is_cwe_1321_and_contains_only_typed_proof():
    verification = {
        "verified": True,
        "fallback": False,
        "oracle": "json-spaces",
        "vector": "__proto__",
        "baselineIndent": 0,
        "probeIndent": 10,
        "indentDelta": 10,
    }
    finding = build_nuclei_finding("https://lab.test/api/profile", verification)

    assert finding["template-id"] == "xasm-server-side-prototype-pollution-verified"
    assert finding["info"]["classification"]["cwe-id"] == ["CWE-1321"]
    assert finding["evidence"] is verification
