from scripts.validate_nuclei_pid_ceiling import (
    PID_LIMIT,
    PID_PEAK_GUARDRAIL,
    TEMPLATE_CATEGORIES,
    build_nuclei_args,
    build_validation_args,
    loopback_targets,
    metric_failures,
    parse_pid_events,
    wrapper_script,
)


def _metrics(**overrides):
    metrics = {
        "scanExitCode": 0,
        "pidsMax": PID_LIMIT,
        "pidsPeak": PID_PEAK_GUARDRAIL,
        "pidsEventsBefore": "max:0;",
        "pidsEventsAfter": "max:0;",
        "sampleCount": 5,
        "targets": 1,
        "jsonlFindingCount": 1,
    }
    metrics.update(overrides)
    return metrics


def _flag_value(arguments, flag):
    return arguments[arguments.index(flag) + 1]


def test_harness_uses_production_concurrency_and_template_loading_limits():
    arguments = build_nuclei_args("/work/targets.txt")
    validation_arguments = build_validation_args()

    assert _flag_value(arguments, "-c") == "10"
    assert _flag_value(arguments, "-bs") == "10"
    assert _flag_value(arguments, "-rl") == "50"
    assert _flag_value(arguments, "-tlc") == "4"
    assert _flag_value(arguments, "-l") == "/work/targets.txt"
    assert _flag_value(validation_arguments, "-tlc") == "4"
    assert [
        validation_arguments[index + 1]
        for index, argument in enumerate(validation_arguments)
        if argument == "-t"
    ] == list(TEMPLATE_CATEGORIES)


def test_harness_uses_responsive_loopback_urls_without_external_network():
    targets = loopback_targets(17)

    assert len(targets) == 17
    assert len(set(targets)) == 17
    assert all(target.startswith("http://127.0.0.1:18080/probe-") for target in targets)
    assert "python3 /work/pid-http-server.py" in wrapper_script()


def test_harness_accepts_peak_at_guardrail_and_parses_cgroup_events():
    assert metric_failures(_metrics()) == []
    assert parse_pid_events("max:2;oom:0;") == {"max": 2, "oom": 0}


def test_harness_rejects_peak_above_guardrail_or_pid_limit_event():
    peak_failures = metric_failures(_metrics(pidsPeak=PID_PEAK_GUARDRAIL + 1))
    event_failures = metric_failures(_metrics(pidsEventsAfter="max:1;"))

    assert any("exceeds guardrail" in failure for failure in peak_failures)
    assert any("pids.events" in failure for failure in event_failures)
