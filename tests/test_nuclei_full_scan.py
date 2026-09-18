import asyncio
import json

import pytest

from tools.nuclei_full_scan import NucleiFullScanTool, TEMPLATE_CATEGORIES


class _Stream:
    def __init__(self, *chunks):
        self._chunks = list(chunks)

    async def read(self, _size=-1):
        if not self._chunks:
            return b""
        chunk = self._chunks.pop(0)
        if isinstance(chunk, BaseException):
            raise chunk
        return chunk


class _Process:
    def __init__(self, *, stdout=b"", stderr=b"", returncode=0, stdout_chunks=None):
        self.stdout = _Stream(*(stdout_chunks if stdout_chunks is not None else [stdout]))
        self.stderr = _Stream(stderr)
        self.returncode = returncode
        self.killed = False

    async def wait(self):
        return self.returncode

    def kill(self):
        self.killed = True
        self.returncode = -9


def _finding(template_id="partial-template"):
    return {
        "template-id": template_id,
        "matched-at": "https://example.test/proof",
        "info": {"name": "Partial evidence", "severity": "medium"},
    }


async def _execute(
    monkeypatch,
    process_or_error_by_category,
    *,
    parameters=None,
    captured_commands=None,
):
    queued = list(process_or_error_by_category)

    async def fake_exec(*command, **_kwargs):
        if captured_commands is not None:
            captured_commands.append(list(command))
        current = queued.pop(0)
        if isinstance(current, BaseException):
            raise current
        return current

    async def no_tls_findings(_self, _target, _targets, _parameters, _agent):
        return []

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
    monkeypatch.setattr(NucleiFullScanTool, "_inspect_tls_posture", no_tls_findings)

    execution_parameters = {
        "target": "https://example.test",
        "_job_id": "coverage-contract",
    }
    execution_parameters.update(parameters or {})
    result = await NucleiFullScanTool().execute(execution_parameters)
    assert queued == []
    return result


def _completed_processes():
    return [_Process() for _ in TEMPLATE_CATEGORIES]


def _flag_value(command, flag):
    return command[command.index(flag) + 1]


def _flag_values(command, flag):
    return [command[index + 1] for index, value in enumerate(command) if value == flag]


@pytest.mark.asyncio
async def test_default_argv_bounds_template_loading_and_uses_supported_exclusion_flag(
    monkeypatch,
):
    commands = []
    await _execute(
        monkeypatch,
        _completed_processes(),
        parameters={
            "exclusionPatterns": {
                "urlPatterns": ["private.example.test", "10.0.0.0/8"]
            },
        },
        captured_commands=commands,
    )

    assert len(commands) == len(TEMPLATE_CATEGORIES) == 7
    for command in commands:
        assert _flag_value(command, "-c") == "10"
        assert _flag_value(command, "-bs") == "10"
        assert _flag_value(command, "-rl") == "50"
        assert _flag_value(command, "-tlc") == "4"
        assert _flag_values(command, "-exclude-hosts") == [
            "private.example.test",
            "10.0.0.0/8",
        ]
        assert "-exclude-targets" not in command


@pytest.mark.asyncio
async def test_all_categories_complete_with_bounded_legacy_compatible_outcomes(monkeypatch):
    result = await _execute(monkeypatch, _completed_processes())

    assert result["success"] is True
    output = result["output"]
    assert output["coverageStatus"] == "COMPLETE_NO_FINDING"
    assert output["coverage"] == {
        "plannedCategories": 7,
        "completedCategories": 7,
        "incompleteCategories": 0,
        "retryable": False,
        "stopReason": "ALL_CATEGORIES_COMPLETED",
    }
    assert len(output["categoryOutcomes"]) == len(TEMPLATE_CATEGORIES) == 7
    assert list(output["category_results"]) == [
        category.rstrip("/").split("/")[-1] for category in TEMPLATE_CATEGORIES
    ]
    assert all(
        outcome["status"] == "COMPLETED"
        and outcome["diagnosticCode"] == "NONE"
        and outcome["exitCode"] == 0
        and 0 <= outcome["elapsedMs"] <= 900000
        for outcome in output["categoryOutcomes"]
    )


@pytest.mark.asyncio
async def test_timeout_keeps_partial_findings_and_reports_incomplete_coverage(monkeypatch):
    partial_line = json.dumps(_finding("timeout-partial")).encode() + b"\n"
    timed_out = _Process(stdout_chunks=[partial_line, asyncio.TimeoutError()])
    processes = [timed_out, *_completed_processes()[1:]]

    result = await _execute(monkeypatch, processes)

    assert result["success"] is True
    assert timed_out.killed is True
    output = result["output"]
    assert output["coverageStatus"] == "INCOMPLETE"
    assert output["total_findings"] == 1
    assert output["findings"][0]["template-id"] == "timeout-partial"
    assert output["category_results"]["technologies"] == 1
    assert output["categoryOutcomes"][0] == {
        "category": TEMPLATE_CATEGORIES[0],
        "status": "TIMED_OUT",
        "elapsedMs": output["categoryOutcomes"][0]["elapsedMs"],
        "findingCount": 1,
        "exitCode": None,
        "diagnosticCode": "CATEGORY_TIMEOUT",
    }


@pytest.mark.asyncio
async def test_newosproc_is_classified_without_persisting_stderr(monkeypatch, capsys):
    finding = json.dumps(_finding("thread-limit-partial")).encode() + b"\n"
    secret_stderr = b"secret-marker: runtime: failed to create new OS thread; fatal error: newosproc"
    processes = [
        _Process(stdout=finding, stderr=secret_stderr, returncode=2),
        *_completed_processes()[1:],
    ]

    result = await _execute(monkeypatch, processes)

    output = result["output"]
    assert result["success"] is True
    assert output["coverageStatus"] == "INCOMPLETE"
    assert output["findings"][0]["template-id"] == "thread-limit-partial"
    assert output["categoryOutcomes"][0]["status"] == "PROCESS_FAILED"
    assert output["categoryOutcomes"][0]["exitCode"] == 2
    assert output["categoryOutcomes"][0]["diagnosticCode"] == "NUCLEI_THREAD_LIMIT"
    assert "secret-marker" not in json.dumps(result)
    assert "secret-marker" not in capsys.readouterr().out


@pytest.mark.asyncio
async def test_nonzero_exit_code_is_classified_and_bounded(monkeypatch):
    processes = [_Process(returncode=999), *_completed_processes()[1:]]

    result = await _execute(monkeypatch, processes)

    first = result["output"]["categoryOutcomes"][0]
    assert result["success"] is True
    assert first["status"] == "PROCESS_FAILED"
    assert first["diagnosticCode"] == "NUCLEI_NONZERO_EXIT"
    assert first["exitCode"] == 255


@pytest.mark.asyncio
async def test_spawn_failure_is_bounded_and_does_not_abort_remaining_categories(monkeypatch):
    processes = [OSError("secret spawn detail"), *_completed_processes()[1:]]

    result = await _execute(monkeypatch, processes)

    output = result["output"]
    assert result["success"] is True
    assert len(output["categoryOutcomes"]) == 7
    assert output["categoryOutcomes"][0] == {
        "category": TEMPLATE_CATEGORIES[0],
        "status": "PROCESS_FAILED",
        "elapsedMs": output["categoryOutcomes"][0]["elapsedMs"],
        "findingCount": 0,
        "exitCode": None,
        "diagnosticCode": "NUCLEI_SPAWN_FAILED",
    }
    assert output["coverageStatus"] == "INCOMPLETE"
    assert output["coverage"]["completedCategories"] == 6
    assert output["coverage"]["retryable"] is False
    assert "secret spawn detail" not in json.dumps(result)
