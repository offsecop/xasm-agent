#!/usr/bin/env python3
"""Operational Nuclei PID-budget harness for issue #2168.

The harness executes Nuclei twice inside the agent image with Docker networking
disabled: once with one loopback target and once with 17 loopback targets. It
samples the container's cgroup-v2 PID counters while the process is alive.

Exit codes:
  0: both cases ran and stayed within the guardrail
  1: a case ran but failed its scan or PID assertions
  2: Docker, the image, Nuclei, templates, or cgroup-v2 metrics were unavailable
"""

from __future__ import annotations

import argparse
import json
import shlex
import shutil
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path


EXPECTED_NUCLEI_VERSION = "3.11.1"
PID_LIMIT = 512
PID_PEAK_GUARDRAIL = 384
TARGET_COUNTS = (1, 17)
TEMPLATE_CATEGORIES = (
    "http/technologies/",
    "http/exposed-panels/",
    "http/misconfiguration/",
    "http/vulnerabilities/",
    "http/cves/",
    "http/exposures/",
    "ssl/",
)
FIXTURE_TEMPLATE_ID = "pid-ceiling-loopback"


class NotRunnable(RuntimeError):
    """The harness did not execute because a required runtime was unavailable."""


def build_nuclei_args(
    target_file: str,
    template_file: str = "/work/pid-fixture.yaml",
) -> list[str]:
    return [
        "nuclei",
        "-l",
        target_file,
        "-t",
        template_file,
        "-jsonl",
        "-silent",
        "-no-color",
        "-no-mhe",
        "-disable-update-check",
        "-timeout",
        "1",
        "-retries",
        "0",
        "-c",
        "10",
        "-bs",
        "10",
        "-tlc",
        "4",
        "-rl",
        "50",
    ]


def build_validation_args() -> list[str]:
    arguments = [
        "nuclei",
        "-validate",
        "-silent",
        "-no-color",
        "-disable-update-check",
        "-tlc",
        "4",
    ]
    for category in TEMPLATE_CATEGORIES:
        arguments.extend(["-t", category])
    return arguments


def loopback_targets(target_count: int) -> list[str]:
    return [f"http://127.0.0.1:18080/probe-{index}" for index in range(target_count)]


def parse_metrics(path: Path) -> dict[str, object]:
    if not path.is_file():
        raise RuntimeError(f"metrics file was not produced: {path}")
    raw: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        key, separator, value = line.partition("=")
        if separator:
            raw[key] = value
    required = {
        "case",
        "targets",
        "scanExitCode",
        "pidsCurrentStart",
        "pidsCurrentEnd",
        "pidsPeak",
        "pidsMax",
        "pidsEventsBefore",
        "pidsEventsAfter",
        "sampleCount",
        "jsonlFindingCount",
    }
    missing = sorted(required.difference(raw))
    if missing:
        raise RuntimeError(f"metrics file is missing keys: {', '.join(missing)}")
    return {
        **raw,
        "targets": int(raw["targets"]),
        "scanExitCode": int(raw["scanExitCode"]),
        "pidsCurrentStart": int(raw["pidsCurrentStart"]),
        "pidsCurrentEnd": int(raw["pidsCurrentEnd"]),
        "pidsPeak": int(raw["pidsPeak"]),
        "pidsMax": int(raw["pidsMax"]),
        "sampleCount": int(raw["sampleCount"]),
        "jsonlFindingCount": int(raw["jsonlFindingCount"]),
    }


def parse_pid_events(value: str) -> dict[str, int]:
    events: dict[str, int] = {}
    for token in value.split(";"):
        key, separator, raw_count = token.partition(":")
        if separator and raw_count.isdigit():
            events[key] = int(raw_count)
    return events


def metric_failures(metrics: dict[str, object]) -> list[str]:
    failures: list[str] = []
    if metrics["scanExitCode"] != 0:
        failures.append(f"Nuclei exited {metrics['scanExitCode']}")
    if metrics["pidsMax"] != PID_LIMIT:
        failures.append(f"pids.max={metrics['pidsMax']} (expected {PID_LIMIT})")
    if metrics["pidsPeak"] > PID_PEAK_GUARDRAIL:
        failures.append(
            f"pids peak={metrics['pidsPeak']} exceeds guardrail {PID_PEAK_GUARDRAIL}"
        )
    before = parse_pid_events(str(metrics["pidsEventsBefore"]))
    after = parse_pid_events(str(metrics["pidsEventsAfter"]))
    if after.get("max", 0) > before.get("max", 0):
        failures.append("pids.events max counter increased during the scan")
    if metrics["sampleCount"] < 1:
        failures.append("no pids.current samples were recorded")
    if metrics["jsonlFindingCount"] != metrics["targets"]:
        failures.append(
            f"JSONL findings={metrics['jsonlFindingCount']} "
            f"(expected {metrics['targets']})"
        )
    return failures


def run(command: list[str], **kwargs) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, text=True, capture_output=True, **kwargs)


def require_runtime(image: str) -> None:
    if not shutil.which("docker"):
        raise NotRunnable("Docker CLI is not installed")
    docker_info = run(["docker", "info", "--format", "{{.ServerVersion}}"])
    if docker_info.returncode != 0:
        raise NotRunnable("Docker daemon is unavailable")
    inspect = run(["docker", "image", "inspect", image])
    if inspect.returncode != 0:
        raise NotRunnable(f"Docker image {image!r} is unavailable; rerun with --build")

    version = run(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--entrypoint",
            "nuclei",
            image,
            "-version",
        ]
    )
    version_text = f"{version.stdout}\n{version.stderr}"
    if version.returncode != 0:
        raise NotRunnable(f"Nuclei is unavailable in image {image!r}")
    if EXPECTED_NUCLEI_VERSION not in version_text:
        raise RuntimeError(
            f"image has an unexpected Nuclei version; expected {EXPECTED_NUCLEI_VERSION}"
        )

    preflight = run(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--pids-limit",
            str(PID_LIMIT),
            "--entrypoint",
            "/bin/sh",
            image,
            "-c",
            (
                "test -x /usr/local/bin/nuclei && "
                "test -d /root/nuclei-templates/http/cves && "
                "test -r /sys/fs/cgroup/pids.current && "
                "test -r /sys/fs/cgroup/pids.max && "
                "test -r /sys/fs/cgroup/pids.events && "
                "cat /sys/fs/cgroup/pids.max"
            ),
        ]
    )
    if preflight.returncode != 0:
        raise NotRunnable(
            "Nuclei templates or cgroup-v2 pids.current/max/events are unavailable"
        )
    if preflight.stdout.strip().splitlines()[-1] != str(PID_LIMIT):
        raise RuntimeError(
            f"Docker did not apply --pids-limit={PID_LIMIT}: {preflight.stdout.strip()}"
        )


def build_image(image: str, agent_dir: Path) -> None:
    build = subprocess.run(
        ["docker", "build", "--tag", image, str(agent_dir)],
        text=True,
    )
    if build.returncode != 0:
        raise RuntimeError(f"Docker build failed with exit code {build.returncode}")


def wrapper_script() -> str:
    nuclei_command = shlex.join(build_nuclei_args("/work/targets.txt"))
    validation_command = shlex.join(build_validation_args())
    return f"""
set -u
metrics="/work/${{CASE_NAME}}.metrics"
samples="/work/${{CASE_NAME}}.pids-current.tsv"
stdout_file="/work/${{CASE_NAME}}.stdout.jsonl"
stderr_file="/work/${{CASE_NAME}}.stderr.log"
validation_file="/work/${{CASE_NAME}}.validation.log"
server_log="/work/${{CASE_NAME}}.http-server.log"
: > "$samples"
python3 /work/pid-http-server.py > "$server_log" 2>&1 &
server_pid=$!
cleanup() {{
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
}}
trap cleanup EXIT INT TERM
server_ready=0
for _attempt in $(seq 1 100); do
    if wget -q -O /dev/null http://127.0.0.1:18080/probe-0; then
        server_ready=1
        break
    fi
    sleep 0.05
done
if [ "$server_ready" -ne 1 ]; then
    echo "loopback HTTP fixture did not become ready" >&2
    exit 70
fi
events_before="$(awk '{{printf "%s:%s;", $1, $2}}' /sys/fs/cgroup/pids.events)"
current_start="$(cat /sys/fs/cgroup/pids.current)"
peak="$current_start"
sample_count=0
(
    {validation_command} > "$validation_file" 2>&1 &&
    {nuclei_command} > "$stdout_file" 2> "$stderr_file"
) &
scan_pid=$!
while kill -0 "$scan_pid" 2>/dev/null; do
    current="$(cat /sys/fs/cgroup/pids.current)"
    sample_count=$((sample_count + 1))
    printf '%s\t%s\n' "$sample_count" "$current" >> "$samples"
    if [ "$current" -gt "$peak" ]; then peak="$current"; fi
    sleep 0.05
done
scan_rc=0
wait "$scan_pid" || scan_rc=$?
current_end="$(cat /sys/fs/cgroup/pids.current)"
if [ "$current_end" -gt "$peak" ]; then peak="$current_end"; fi
events_after="$(awk '{{printf "%s:%s;", $1, $2}}' /sys/fs/cgroup/pids.events)"
jsonl_finding_count="$(awk 'NF {{ count++ }} END {{ print count + 0 }}' "$stdout_file")"
{{
    printf 'case=%s\n' "$CASE_NAME"
    printf 'targets=%s\n' "$TARGET_COUNT"
    printf 'scanExitCode=%s\n' "$scan_rc"
    printf 'pidsCurrentStart=%s\n' "$current_start"
    printf 'pidsCurrentEnd=%s\n' "$current_end"
    printf 'pidsPeak=%s\n' "$peak"
    printf 'pidsMax=%s\n' "$(cat /sys/fs/cgroup/pids.max)"
    printf 'pidsEventsBefore=%s\n' "$events_before"
    printf 'pidsEventsAfter=%s\n' "$events_after"
    printf 'sampleCount=%s\n' "$sample_count"
    printf 'jsonlFindingCount=%s\n' "$jsonl_finding_count"
}} > "$metrics"
exit "$scan_rc"
""".strip()


def run_case(image: str, work_dir: Path, target_count: int, timeout: int) -> dict[str, object]:
    case_name = "single-target" if target_count == 1 else f"{target_count}-targets"
    targets = loopback_targets(target_count)
    for index in range(target_count):
        (work_dir / f"probe-{index}").write_text(
            f"bounded nuclei pid fixture {index}\n",
            encoding="utf-8",
        )
    (work_dir / "pid-fixture.yaml").write_text(
        """id: pid-ceiling-loopback
info:
  name: Bounded PID loopback fixture
  author: xasm
  severity: info
http:
  - method: GET
    path:
      - '{{BaseURL}}'
    matchers:
      - type: status
        status:
          - 200
""",
        encoding="utf-8",
    )
    (work_dir / "pid-http-server.py").write_text(
        """from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer


class FixtureServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 128


FixtureServer(
    ("127.0.0.1", 18080),
    partial(SimpleHTTPRequestHandler, directory="/work"),
).serve_forever()
""",
        encoding="utf-8",
    )
    (work_dir / "targets.txt").write_text("\n".join(targets) + "\n", encoding="utf-8")
    container_name = f"nuclei-pid-{target_count}-{uuid.uuid4().hex[:10]}"
    command = [
        "docker",
        "run",
        "--detach",
        "--name",
        container_name,
        "--network",
        "none",
        "--pids-limit",
        str(PID_LIMIT),
        "--env",
        f"CASE_NAME={case_name}",
        "--env",
        f"TARGET_COUNT={target_count}",
        "--volume",
        f"{work_dir}:/work",
        "--entrypoint",
        "/bin/sh",
        image,
        "-c",
        wrapper_script(),
    ]
    try:
        started = run(command)
        if started.returncode != 0:
            raise RuntimeError(f"failed to start {case_name}: {started.stderr.strip()}")
        try:
            waited = run(["docker", "wait", container_name], timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(f"{case_name} exceeded {timeout}s") from exc
        if waited.returncode != 0:
            raise RuntimeError(f"docker wait failed for {case_name}: {waited.stderr.strip()}")

        metrics = parse_metrics(work_dir / f"{case_name}.metrics")
        output_path = work_dir / f"{case_name}.stdout.jsonl"
        parsed_findings = []
        for line in output_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            finding = json.loads(line)
            if finding.get("template-id") != FIXTURE_TEMPLATE_ID:
                raise RuntimeError(f"{case_name} emitted an unexpected template id")
            parsed_findings.append(finding)
        if len(parsed_findings) != target_count:
            raise RuntimeError(
                f"{case_name} emitted {len(parsed_findings)} valid JSONL findings; "
                f"expected {target_count}"
            )
        failures = metric_failures(metrics)
        if failures:
            stderr_path = work_dir / f"{case_name}.stderr.log"
            stderr_tail = (
                stderr_path.read_text(encoding="utf-8", errors="replace")[-2000:]
                if stderr_path.is_file()
                else ""
            )
            detail = "; ".join(failures)
            if stderr_tail:
                detail = f"{detail}; stderr tail: {stderr_tail}"
            raise RuntimeError(f"{case_name} failed: {detail}")
        return metrics
    finally:
        run(["docker", "rm", "--force", container_name])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--image",
        default="asm-platform-agent:nuclei-pid-ceiling",
        help="Agent image to validate",
    )
    parser.add_argument(
        "--build",
        action="store_true",
        help="Build --image from agent/Dockerfile before validation",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=int,
        default=900,
        help="Maximum runtime for each target-count case",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Optional path for the JSON metrics report",
    )
    args = parser.parse_args()

    agent_dir = Path(__file__).resolve().parents[1]
    try:
        if args.build:
            if not shutil.which("docker"):
                raise NotRunnable("Docker CLI is not installed")
            build_image(args.image, agent_dir)
        require_runtime(args.image)
        with tempfile.TemporaryDirectory(prefix="nuclei-pid-ceiling-") as temp_dir:
            work_dir = Path(temp_dir)
            cases = [
                run_case(args.image, work_dir, target_count, args.timeout_seconds)
                for target_count in TARGET_COUNTS
            ]
        report = {
            "status": "PASS",
            "nucleiVersion": EXPECTED_NUCLEI_VERSION,
            "pidLimit": PID_LIMIT,
            "pidPeakGuardrail": PID_PEAK_GUARDRAIL,
            "network": "none",
            "cases": cases,
        }
        rendered = json.dumps(report, indent=2, sort_keys=True)
        print(rendered)
        if args.output:
            args.output.write_text(rendered + "\n", encoding="utf-8")
        return 0
    except NotRunnable as exc:
        print(f"NOT RUN: {exc}", file=sys.stderr)
        return 2
    except (RuntimeError, ValueError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
