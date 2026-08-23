#!/usr/bin/env python3
import os
import subprocess
import time

from ebpf_event_oracles import (
    parse_json_events,
    parse_lifecycle_events,
    parse_phase_events,
    parse_ready_events,
    parse_stats_events,
)
from ebpf_fixture_build import build_named_fixture
from ebpf_perf_model import PERF_WORKLOADS, PerfCapture, PerfWorkloadSpec
from ebpf_perf_reporting import print_go_pipeline_benchmarks, print_perf_capture
from ebpf_perf_validation import parse_go_benchmark_metrics, validate_perf_capture
from ebpf_suites import build_strace_go, run_strace_go_capture, run_strace_go_json


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
PERF_FIXTURE_SRC = os.path.join(SCRIPT_DIR, "fixtures", "ebpf_perf_fixture.c")


def run_go_pipeline_benchmarks():
    return subprocess.run(
        [
            "go",
            "test",
            "./cmd/strace-go",
            "-run",
            "^$",
            "-bench",
            "^Benchmark(TraceRecordDecoderPayload|TraceEventDecodeState|TraceStateDeferredPayload|TraceEventContextHandler|TraceEventHandlerPipeline|TraceEventTextPipeline|TraceEventJSONPipeline|JSONEventWriter|JSONDecodedEventWriter|JSONDecodedPayloadEventWriter)$",
            "-benchmem",
            "-count=1",
        ],
        cwd=PROJECT_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        errors="ignore",
        timeout=120,
    )


def capture_workload(fixture, spec):
    command_args = ["-f", "-e", f"trace={spec.trace}", fixture]
    command_args.extend(spec.fixture_args)
    start = time.monotonic()
    if spec.event_format == "json":
        result = run_strace_go_json(command_args, timeout=60, phases=True)
    elif spec.event_format == "reader":
        result = run_strace_go_capture(command_args, "reader", timeout=60)
    else:
        raise ValueError(f"unsupported perf event format: {spec.event_format}")
    return PerfCapture(
        name=spec.name,
        result=result,
        elapsed=time.monotonic() - start,
        events=parse_json_events(result.stderr),
        lifecycle_events=parse_lifecycle_events(result.stderr),
        stats_events=parse_stats_events(result.stderr),
        ready_events=parse_ready_events(result.stderr),
        phase_events=parse_phase_events(result.stderr),
    )


def _check_go_benchmarks(result, metrics):
    expected = {
        "BenchmarkTraceRecordDecoderPayload",
        "BenchmarkTraceEventDecodeState",
        "BenchmarkTraceStateDeferredPayload",
        "BenchmarkTraceEventContextHandler",
        "BenchmarkTraceEventHandlerPipeline",
        "BenchmarkTraceEventTextPipeline",
        "BenchmarkTraceEventJSONPipeline",
        "BenchmarkJSONEventWriter",
        "BenchmarkJSONDecodedEventWriter",
        "BenchmarkJSONDecodedPayloadEventWriter",
    }
    actual = {metric["name"].rsplit("-", 1)[0] for metric in metrics}
    if result.returncode != 0:
        return ["Go event-pipeline benchmark returned nonzero"]
    missing = expected - actual
    if missing:
        return [f"missing Go benchmark metrics: {sorted(missing)}"]
    return []


def _run_go_benchmarks():
    try:
        result = run_go_pipeline_benchmarks()
    except (OSError, subprocess.SubprocessError) as error:
        return None, [], [f"Go event-pipeline benchmark failed to run: {error}"]
    output = result.stdout + result.stderr
    metrics = parse_go_benchmark_metrics(output)
    print_go_pipeline_benchmarks(result, metrics)
    failures = _check_go_benchmarks(result, metrics)
    if failures and result.returncode != 0:
        failures.append("\n".join(output.splitlines()[-30:]))
    return result, metrics, failures


def run_ebpf_perf(args):
    if not args.skip_build:
        build_strace_go()
    fixture = build_named_fixture(
        "strace-go-ebpf-perf-fixture", (PERF_FIXTURE_SRC,), ["-pthread"]
    )
    _, _, benchmark_failures = _run_go_benchmarks()
    failed = bool(benchmark_failures)
    for spec in PERF_WORKLOADS:
        capture = capture_workload(fixture, spec)
        print_perf_capture(capture)
        failures = validate_perf_capture(capture, spec)
        if failures:
            failed = True
            for failure in failures:
                print(f"FAIL: {failure}")
            print("--- stderr tail ---")
            print("\n".join(capture.result.stderr.splitlines()[-30:]))
    for failure in benchmark_failures:
        print(f"FAIL: {failure}")
    if failed:
        return 1
    print("PASS: ebpf-perf")
    return 0
