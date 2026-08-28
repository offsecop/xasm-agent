import asyncio

import pytest

from tools.sqlmap_detection_scan import SqlmapDetectionScanTool


class _Stdout:
    def __init__(self, lines=None):
        self._lines = [line.encode() + b"\n" for line in (lines or [])]

    async def readline(self):
        return self._lines.pop(0) if self._lines else b""


class _CompletedProcess:
    def __init__(self, lines=None):
        self.stdout = _Stdout(lines)
        self.stderr = _Stdout()

    async def wait(self):
        return 0


class _ClientSession:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return False


@pytest.mark.asyncio
async def test_detection_scan_does_not_request_database_enumeration(monkeypatch):
    captured_command = []

    async def fake_exec(*command, **_kwargs):
        captured_command.extend(command)
        return _CompletedProcess()

    tool = SqlmapDetectionScanTool()
    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
    monkeypatch.setattr(tool, "_parse_sqlmap_logs", lambda *_args: [])
    monkeypatch.setattr("tools.sqlmap_detection_scan.os.makedirs", lambda *_args, **_kwargs: None)

    result = await tool.execute(
        {
            "target": "https://lab.example/filter?category=Accessories",
            "testForms": False,
            "crawlDepth": 0,
            "_job_id": "scope-test",
        }
    )

    assert result["success"] is True
    assert "--risk=1" in captured_command
    assert "--level=3" in captured_command
    assert "--banner" not in captured_command
    assert "--current-user" not in captured_command
    assert "--current-db" not in captured_command
    assert "--is-dba" not in captured_command


@pytest.mark.asyncio
async def test_detection_scan_fails_when_sqlmap_cannot_reach_target(monkeypatch):
    async def fake_exec(*_command, **_kwargs):
        return _CompletedProcess(
            [
                "[CRITICAL] unable to connect to the target URL (504 - Gateway Timeout)",
                "[ERROR] unable to connect to the target URL, skipping to the next target",
            ]
        )

    tool = SqlmapDetectionScanTool()
    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
    monkeypatch.setattr(tool, "_parse_sqlmap_logs", lambda *_args: [])
    monkeypatch.setattr("tools.sqlmap_detection_scan.os.makedirs", lambda *_args, **_kwargs: None)

    result = await tool.execute(
        {
            "target": "https://lab.example/filter?category=Accessories",
            "testForms": False,
            "crawlDepth": 0,
            "_job_id": "unreachable-test",
        }
    )

    assert result["success"] is False
    assert result["error"] == "SQLMap could not reach the target URL"
    assert result["output"]["vulnerabilities"] == []
    assert "504 - Gateway Timeout" in result["raw_output"]


@pytest.mark.asyncio
async def test_path_preflight_confirms_introduced_sql_error_with_request_response(monkeypatch):
    tool = SqlmapDetectionScanTool()
    requested_urls = []

    async def fake_fetch(_session, url, _headers):
        requested_urls.append(url)
        if "%27" in url:
            return {
                "status": 500,
                "reason": "Internal Server Error",
                "headers": {"Content-Type": "application/json"},
                "body": '{"error":"unterminated quoted string at or near SQL query"}',
                "truncated": False,
            }
        return {
            "status": 200,
            "reason": "OK",
            "headers": {"Content-Type": "application/json"},
            "body": '{"transactions":[]}',
            "truncated": False,
        }

    monkeypatch.setattr("tools.sqlmap_detection_scan.aiohttp.ClientSession", lambda **_kwargs: _ClientSession())
    monkeypatch.setattr(tool, "_fetch_path_preflight", fake_fetch)

    result = await tool.execute(
        {
            "targets": ["https://lab.example/transactions/1*"],
            "headers": {"Authorization": "Bearer private-test-token"},
            "cookie": "session=private-test-cookie",
            "_job_id": "path-positive",
        }
    )

    assert result["success"] is True
    assert result["output"]["preflight_requests"] == 2
    assert result["output"]["sqlmap_targets"] == []
    assert requested_urls == [
        "https://lab.example/transactions/1",
        "https://lab.example/transactions/1%27",
    ]
    vulnerability = result["output"]["vulnerabilities"][0]
    assert vulnerability["target"] == "https://lab.example/transactions/1"
    assert vulnerability["parameter"] == "path segment 2"
    assert "GET /transactions/1%27 HTTP/1.1" in vulnerability["request"]
    assert "HTTP/1.1 500 Internal Server Error" in vulnerability["response"]
    assert "private-test-token" not in str(vulnerability)
    assert "private-test-cookie" not in str(vulnerability)
    assert [
        step["carrierRole"]
        for step in vulnerability["http_evidence"]["steps"]
    ] == ["baseline", "mutation"]


@pytest.mark.asyncio
async def test_path_preflight_defers_unconfirmed_path_siblings_after_confirmation(monkeypatch):
    tool = SqlmapDetectionScanTool()

    async def fake_fetch(_session, url, _headers):
        is_confirmed_candidate = "/transactions/" in url
        is_mutated = "%27" in url
        return {
            "status": 500 if is_confirmed_candidate and is_mutated else 200,
            "reason": "Internal Server Error" if is_confirmed_candidate and is_mutated else "OK",
            "headers": {"Content-Type": "application/json"},
            "body": (
                '{"error":"syntax error at or near quote"}'
                if is_confirmed_candidate and is_mutated
                else '{"ok":true}'
            ),
            "truncated": False,
        }

    async def unexpected_sqlmap(*_command, **_kwargs):
        raise AssertionError("broad SQLMap must not run for marked path siblings")

    monkeypatch.setattr("tools.sqlmap_detection_scan.aiohttp.ClientSession", lambda **_kwargs: _ClientSession())
    monkeypatch.setattr(tool, "_fetch_path_preflight", fake_fetch)
    monkeypatch.setattr(asyncio, "create_subprocess_exec", unexpected_sqlmap)

    result = await tool.execute(
        {
            "targets": [
                "https://lab.example/transactions/1*",
                "https://lab.example/billers/1*",
            ],
            "_job_id": "path-defer",
        }
    )

    assert result["success"] is True
    assert result["output"]["preflight_requests"] == 4
    assert result["output"]["sqlmap_targets"] == []
    assert result["output"]["deferred_path_targets"] == [
        "https://lab.example/billers/1*"
    ]
    assert len(result["output"]["vulnerabilities"]) == 1
    assert "deferred for 1 unconfirmed marked path sibling" in result["raw_output"]


@pytest.mark.asyncio
async def test_path_preflight_keeps_query_targets_for_sqlmap_after_path_confirmation(monkeypatch):
    tool = SqlmapDetectionScanTool()
    captured_command = []

    async def fake_fetch(_session, url, _headers):
        is_mutated = "%27" in url
        return {
            "status": 500 if is_mutated else 200,
            "reason": "Internal Server Error" if is_mutated else "OK",
            "headers": {},
            "body": "SQL syntax error" if is_mutated else "normal response",
            "truncated": False,
        }

    async def fake_exec(*command, **_kwargs):
        captured_command.extend(command)
        return _CompletedProcess()

    monkeypatch.setattr("tools.sqlmap_detection_scan.aiohttp.ClientSession", lambda **_kwargs: _ClientSession())
    monkeypatch.setattr(tool, "_fetch_path_preflight", fake_fetch)
    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
    monkeypatch.setattr(tool, "_parse_sqlmap_logs", lambda *_args: [])

    query_target = "https://lab.example/filter?id=1*"
    result = await tool.execute(
        {
            "targets": ["https://lab.example/transactions/1*", query_target],
            "testForms": False,
            "_job_id": "path-and-query",
        }
    )

    assert result["success"] is True
    assert captured_command[0] == "sqlmap"
    assert result["output"]["sqlmap_targets"] == [query_target]
    assert result["output"]["deferred_path_targets"] == []
    assert len(result["output"]["vulnerabilities"]) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("baseline_body", "mutated_body"),
    [
        ("normal response", "internal server error"),
        ("SQL syntax error", "SQL syntax error"),
    ],
)
async def test_path_preflight_rejects_status_only_or_unchanged_sql_signal(
    monkeypatch,
    baseline_body,
    mutated_body,
):
    tool = SqlmapDetectionScanTool()

    async def fake_fetch(_session, url, _headers):
        mutated = "%27" in url
        return {
            "status": 500 if mutated else 200,
            "reason": "Internal Server Error" if mutated else "OK",
            "headers": {},
            "body": mutated_body if mutated else baseline_body,
            "truncated": False,
        }

    monkeypatch.setattr("tools.sqlmap_detection_scan.aiohttp.ClientSession", lambda **_kwargs: _ClientSession())
    monkeypatch.setattr(tool, "_fetch_path_preflight", fake_fetch)

    vulnerabilities, remaining, request_count = await tool._run_path_sqli_preflight(
        ["https://lab.example/accounts/1*"],
        {},
    )

    assert vulnerabilities == []
    assert remaining == ["https://lab.example/accounts/1*"]
    assert request_count == 2


def test_path_preflight_does_not_treat_query_markers_or_credentials_as_path_candidates():
    tool = SqlmapDetectionScanTool()

    assert tool._path_marker_urls("https://lab.example/filter?id=1*") is None
    assert tool._path_marker_urls("https://user:secret@lab.example/accounts/1*") is None
