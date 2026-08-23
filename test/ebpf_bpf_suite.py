#!/usr/bin/env python3
import os
import subprocess

from ebpf_bpf_lifecycle_oracle import check_bpf_lifecycle
from ebpf_bpf_semantic_checks import BPF_ZERO_STATS, check_bpf_semantic
from ebpf_check_support import valid_stats_event
from ebpf_event_oracles import parse_json_events, parse_stats_events
from ebpf_fixture_build import build_named_fixture


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BPF_FIXTURE_SOURCE = (
    os.path.join(SCRIPT_DIR, "fixtures", "ebpf_bpf_fixture.c"),
    os.path.join(SCRIPT_DIR, "fixtures", "ebpf_bpf_map_elem_fixture.c"),
    os.path.join(SCRIPT_DIR, "fixtures", "ebpf_bpf_query_fixture.c"),
)
BPF_PERCPU_FIXTURE_SOURCE = os.path.join(
    SCRIPT_DIR, "fixtures", "ebpf_bpf_percpu_fixture.c"
)
BPF_LIFECYCLE_FIXTURE_SOURCE = os.path.join(
    SCRIPT_DIR, "fixtures", "ebpf_bpf_lifecycle_fixture.c"
)


def _run_fixture(wrapper, root, fixture):
    return subprocess.run(
        [wrapper, "--event-format=json", "-e", "trace=bpf", fixture],
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        errors="ignore",
        timeout=30,
        env=os.environ.copy(),
    )


def _run_main_fixtures(wrapper, root):
    sources = (
        ("strace-go-ebpf-bpf-fixture", BPF_FIXTURE_SOURCE, ("-ldl",)),
        ("strace-go-ebpf-bpf-percpu-fixture", (BPF_PERCPU_FIXTURE_SOURCE,), ()),
    )
    runs = []
    for name, fixture_sources, extra_args in sources:
        fixture = build_named_fixture(name, fixture_sources, extra_args=extra_args)
        runs.append(_run_fixture(wrapper, root, fixture))
    return runs


def _check_percpu_stats(run):
    failures = []
    stats_events = parse_stats_events(run.stderr)
    if len(stats_events) != 1:
        return ["BPF per-CPU stats event missing"]
    stats = stats_events[0]
    if not valid_stats_event(stats):
        failures.append("BPF per-CPU stats event is malformed")
    for key in BPF_ZERO_STATS:
        if stats.get(key) != 0:
            failures.append(f"BPF per-CPU {key} is non-zero")
    return failures


def run_bpf_semantic(wrapper, root):
    runs = _run_main_fixtures(wrapper, root)
    lifecycle_fixture = build_named_fixture(
        "strace-go-ebpf-bpf-lifecycle-fixture", (BPF_LIFECYCLE_FIXTURE_SOURCE,)
    )
    lifecycle_run = _run_fixture(wrapper, root, lifecycle_fixture)
    combined_stdout = "\n".join(run.stdout for run in runs)
    combined_events = []
    for run in runs:
        combined_events.extend(parse_json_events(run.stderr))

    failures = check_bpf_semantic(
        0 if all(run.returncode == 0 for run in runs) else 1,
        combined_stdout,
        combined_events,
        parse_stats_events(runs[0].stderr),
    )
    failures.extend(
        check_bpf_lifecycle(
            lifecycle_run.returncode,
            lifecycle_run.stdout,
            parse_json_events(lifecycle_run.stderr),
            parse_stats_events(lifecycle_run.stderr),
        )
    )
    if "bpf-percpu-fixture-ok" not in combined_stdout:
        failures.append("BPF per-CPU fixture marker missing")
    failures.extend(_check_percpu_stats(runs[1]))
    if not failures:
        lifecycle_events = parse_json_events(lifecycle_run.stderr)
        print(
            f"=> eBPF bpf semantic events: "
            f"{len(combined_events) + len(lifecycle_events)}"
        )
    return failures
