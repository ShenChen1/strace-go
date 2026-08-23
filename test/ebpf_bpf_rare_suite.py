import os
import subprocess

from ebpf_bpf_capability_matrix import (
    check_capability_matrix,
    parse_capability_records,
)
from ebpf_bpf_rare_oracle import check_bpf_rare
from ebpf_event_oracles import parse_json_events, parse_stats_events
from ebpf_fixture_build import build_named_fixture


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
RARE_FIXTURE_SOURCE = os.path.join(
    SCRIPT_DIR, "fixtures", "ebpf_bpf_rare_fixture.c"
)


def _run_bpf_rare_fixture(wrapper, root):
    fixture = build_named_fixture(
        "strace-go-ebpf-bpf-rare-fixture", (RARE_FIXTURE_SOURCE,)
    )
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


def run_bpf_rare_semantic(wrapper, root):
    result = _run_bpf_rare_fixture(wrapper, root)
    events = parse_json_events(result.stderr)
    failures = check_bpf_rare(
        result.returncode,
        result.stdout,
        events,
        parse_stats_events(result.stderr),
    )
    failures.extend(check_capability_matrix(result.stdout))
    if not failures:
        print(f"=> eBPF bpf rare semantic events: {len(events)}")
    return failures


def run_bpf_capability_semantic(wrapper, root):
    result = _run_bpf_rare_fixture(wrapper, root)
    failures = []
    if result.returncode != 0:
        failures.append(f"BPF capability fixture rc={result.returncode}")
    if "bpf-rare-fixture-ok" not in result.stdout:
        failures.append("BPF capability fixture marker missing")
    failures.extend(check_capability_matrix(result.stdout))
    if failures:
        for failure in failures:
            print(f"FAIL: {failure}")
        return 1
    print(
        "=> eBPF capability matrix probes: "
        f"{len(parse_capability_records(result.stdout))}"
    )
    print("PASS: ebpf-capability")
    return 0
