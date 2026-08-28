import asyncio
import json

import pytest

from tools.dalfox_xss_scan import (
    DALFOX_DEFAULT_CONCURRENCY,
    DALFOX_TIMEOUT_SECONDS,
    DalfoxXssScanTool,
)


class _Stream:
    def __init__(self, payload=b""):
        self._chunks = [payload] if payload else []

    async def read(self, _size=-1):
        return self._chunks.pop(0) if self._chunks else b""


class _CompletedProcess:
    def __init__(self, stdout=b"", stderr=b"", returncode=0):
        self.stdout = _Stream(stdout)
        self.stderr = _Stream(stderr)
        self.returncode = returncode
        self.killed = False

    async def wait(self):
        return self.returncode

    def kill(self):
        self.killed = True


def _poc(result_type, suffix=""):
    return {
        "type": result_type,
        "inject_type": "inATTR-double(1)-URL",
        "poc_type": "plain",
        "method": "GET",
        "data": f"https://lab.example/?search=poc{suffix}",
        "param": "search",
        "payload": '" autofocus onfocus=alert(1) x="',
        "evidence": "input value contains the controlled payload",
        "cwe": "CWE-79",
        "severity": "High",
    }


def test_parser_keeps_only_verified_v_records_from_v293_array():
    tool = DalfoxXssScanTool()
    raw = json.dumps([_poc("V"), _poc("R", "-reflected"), _poc("G", "-grep"), {}])

    findings, counts, parsed = tool._parse_dalfox_output(raw)

    assert parsed is True
    assert findings == [_poc("V")]
    assert counts == {"verified": 1, "reflected": 1, "grep": 1, "other": 0}


def test_parser_accepts_wrapper_and_comma_terminated_json_lines():
    tool = DalfoxXssScanTool()
    wrapped = json.dumps({"pocs": [_poc("V"), _poc("R")]})
    json_lines = f'{json.dumps(_poc("V"))},\n{json.dumps(_poc("R"))},\n'

    wrapped_findings, wrapped_counts, wrapped_parsed = tool._parse_dalfox_output(wrapped)
    line_findings, line_counts, line_parsed = tool._parse_dalfox_output(json_lines)

    assert wrapped_parsed is True
    assert wrapped_findings == [_poc("V")]
    assert wrapped_counts["reflected"] == 1
    assert line_parsed is True
    assert line_findings == [_poc("V")]
    assert line_counts["reflected"] == 1


@pytest.mark.asyncio
async def test_execute_delivers_only_verified_findings(monkeypatch):
    captured_command = []
    stdout = json.dumps([_poc("V"), _poc("R"), _poc("G"), {}]).encode()

    async def fake_exec(*command, **_kwargs):
        captured_command.extend(command)
        return _CompletedProcess(stdout=stdout)

    async def fake_attach(_self, findings, _targets, **_kwargs):
        return [
            {
                **finding,
                "request": "GET /?search=poc HTTP/1.1\r\nHost: lab.example\r\n\r\n",
                "response": "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<input value=poc>",
                "dom_execution": True,
            }
            for finding in findings
        ], 0

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
    monkeypatch.setattr(DalfoxXssScanTool, "_attach_verified_evidence", fake_attach)
    monkeypatch.setattr("tools.dalfox_xss_scan.os.makedirs", lambda *_args, **_kwargs: None)

    result = await DalfoxXssScanTool().execute(
        {"target": "https://lab.example/?search=calibration", "_job_id": "xss-calibration"}
    )

    assert result["success"] is True
    assert result["output"]["total_findings"] == 1
    assert result["output"]["findings"][0]["type"] == "V"
    assert result["output"]["observation_counts"] == {
        "verified": 1,
        "reflected": 1,
        "grep": 1,
        "other": 0,
        "evidence_capture_failed": 0,
        "verified_observations": 1,
        "evidence_backed_verified": 1,
    }
    assert result["output"]["findings"][0]["request"].startswith("GET ")
    assert result["output"]["findings"][0]["response"].startswith("HTTP/1.1 200")
    assert result["output"]["findings"][0]["dom_execution"] is True
    assert result["output"]["verification"] == "dalfox-v-only"
    assert captured_command[:3] == [
        "dalfox",
        "url",
        "https://lab.example/?search=calibration",
    ]
    assert "--skip-mining-all" in captured_command
    worker_index = captured_command.index("--worker")
    assert captured_command[worker_index + 1] == str(DALFOX_DEFAULT_CONCURRENCY)
    assert DALFOX_TIMEOUT_SECONDS < 600


def test_evidence_helpers_recover_parameter_and_redact_secrets():
    tool = DalfoxXssScanTool()
    poc_url = "https://lab.example/search?q=%3Csvg%2Fonload%3Dalert%281%29%3E"

    assert tool._resolve_parameter({"param": ""}, poc_url, ["https://lab.example/search?q="]) == "q"
    assert tool._resolve_payload({"payload": ""}, poc_url, "q") == "<svg/onload=alert(1)>"

    request = tool._request_transcript(
        poc_url,
        {
            "User-Agent": "xASM-Dalfox-Evidence/1.0",
            "Authorization": "Bearer top-secret-token",
            "Cookie": "session=top-secret-cookie",
        },
        ["top-secret-token", "top-secret-cookie"],
    )
    response = tool._response_transcript(
        200,
        "OK",
        {"Content-Type": "text/html", "Set-Cookie": "session=top-secret-cookie"},
        '<input value="poc"><script>const token="top-secret-token"</script>',
        ["top-secret-token", "top-secret-cookie"],
    )

    assert request.startswith("GET /search?q=")
    assert "Authorization: [REDACTED]" in request
    assert "Cookie: [REDACTED]" in request
    assert "top-secret" not in request
    assert response.startswith("HTTP/1.1 200 OK")
    assert "Set-Cookie: [REDACTED]" in response
    assert "top-secret" not in response


@pytest.mark.asyncio
async def test_execute_clamps_explicit_concurrency(monkeypatch):
    captured_command = []

    async def fake_exec(*command, **_kwargs):
        captured_command.extend(command)
        return _CompletedProcess(stdout=b"[{}]")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
    monkeypatch.setattr("tools.dalfox_xss_scan.os.makedirs", lambda *_args, **_kwargs: None)

    result = await DalfoxXssScanTool().execute(
        {
            "target": "https://lab.example/?search=calibration",
            "concurrency": 999,
            "skipParameterMining": False,
            "_job_id": "xss-concurrency",
        }
    )

    assert result["success"] is True
    assert "--skip-mining-all" not in captured_command
    worker_index = captured_command.index("--worker")
    assert captured_command[worker_index + 1] == "20"


@pytest.mark.asyncio
async def test_execute_fails_on_nonzero_exit(monkeypatch):
    async def fake_exec(*_command, **_kwargs):
        return _CompletedProcess(stderr=b"target connection failed", returncode=2)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
    monkeypatch.setattr("tools.dalfox_xss_scan.os.makedirs", lambda *_args, **_kwargs: None)

    result = await DalfoxXssScanTool().execute(
        {"target": "https://lab.example/?search=calibration", "_job_id": "xss-failed"}
    )

    assert result["success"] is False
    assert result["error"] == "Dalfox exited with status 2"
    assert result["output"]["findings"] == []
    assert "target connection failed" in result["raw_output"]


@pytest.mark.asyncio
async def test_execute_fails_on_malformed_nonempty_output(monkeypatch):
    async def fake_exec(*_command, **_kwargs):
        return _CompletedProcess(stdout=b"not-json")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
    monkeypatch.setattr("tools.dalfox_xss_scan.os.makedirs", lambda *_args, **_kwargs: None)

    result = await DalfoxXssScanTool().execute(
        {"target": "https://lab.example/?search=calibration", "_job_id": "xss-malformed"}
    )

    assert result["success"] is False
    assert result["error"] == "Dalfox returned malformed JSON output"
    assert result["output"]["findings"] == []
