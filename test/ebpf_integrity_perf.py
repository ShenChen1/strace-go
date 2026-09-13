#!/usr/bin/env python3
"""Compare isolated binaries; report trace-window and process-lifetime costs separately."""

import argparse
import json
import os
import subprocess
import time

from ebpf_event_oracles import parse_phase_events, parse_stats_events
from ebpf_fixture_build import build_named_fixture


def capture(binary, fixture, workload, event_format="reader"):
    name, trace, arguments, calls = workload
    command = [binary, "--debug-phases", f"--event-format={event_format}", "-f", "-e",
               f"trace={trace}", fixture, *arguments]
    start = time.monotonic()
    result = subprocess.run(command, capture_output=True, text=True, timeout=60,
                            check=False)
    elapsed = time.monotonic() - start
    stats_events = parse_stats_events(result.stderr)
    phases = {event["phase"]: event for event in parse_phase_events(result.stderr)}
    if result.returncode != 0 or not stats_events:
        raise RuntimeError(f"{name}: tracer failed: {result.stderr[-2000:]}")
    stats = stats_events[-1]
    trace_seconds = (phases["trace_end"]["time_ns"] -
                     phases["trace_start"]["time_ns"]) / 1e9
    samples = stats.get("service_records", 0)
    return {
        "workload": name,
        "event_format": event_format,
        "trace_seconds": trace_seconds,
        "end_to_end_seconds": elapsed,
        "workload_syscalls_per_second": calls / trace_seconds,
        "service_ns_per_sample": stats.get("service_time_ns", 0) / max(samples, 1),
        "ringbuf_reserve_fail": stats["ringbuf_reserve_fail"],
        "ringbuf_copy_fail": stats["ringbuf_copy_fail"],
        "records_read": stats["records_read"],
        "bytes_read": stats["bytes_read"],
        "integrity": stats.get("integrity"),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", required=True)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--iterations", type=int, default=3, choices=range(1, 11))
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("requires root to load BPF")
    binaries = [("baseline", os.path.abspath(args.baseline)),
                ("candidate", os.path.abspath(args.candidate))]
    for _, binary in binaries:
        if not os.path.isfile(binary) or not os.access(binary, os.X_OK):
            parser.error(f"not an executable file: {binary}")
    source = os.path.join(os.path.dirname(__file__), "fixtures", "ebpf_perf_fixture.c")
    fixture = build_named_fixture("strace-go-integrity-perf-fixture", (source,), ["-pthread"])
    workloads = (
        ("scalar", "getpid,clock_gettime", ("scalar", "100000"), 200000),
        ("io", "read,write", ("io", "100000"), 200000),
        ("threads", "getpid,clone,clone3", ("threads", "4", "50000"), 200000),
    )
    for iteration in range(args.iterations):
        for workload in workloads:
            order = binaries if iteration % 2 == 0 else list(reversed(binaries))
            for event_format in ("reader", "none"):
                for label, binary in order:
                    result = capture(binary, fixture, workload, event_format)
                    result.update(binary=label, iteration=iteration + 1)
                    print(json.dumps(result), flush=True)


if __name__ == "__main__":
    main()
