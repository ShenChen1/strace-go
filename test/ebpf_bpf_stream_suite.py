#!/usr/bin/env python3
import os
import subprocess

from ebpf_bpf_stream_oracle import check_bpf_stream
from ebpf_event_oracles import parse_json_events, parse_stats_events
from ebpf_fixture_build import build_bpf_object, build_named_fixture


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
STREAM_PROGRAM_SOURCE = os.path.join(
    SCRIPT_DIR, "fixtures", "ebpf_bpf_stream_prog.bpf.c"
)
STREAM_FIXTURE_SOURCE = os.path.join(
    SCRIPT_DIR, "fixtures", "ebpf_bpf_stream_fixture.c"
)


def run_bpf_stream_semantic(wrapper, root):
    object_path = build_bpf_object(
        "strace-go-ebpf-bpf-stream-prog.bpf.o", STREAM_PROGRAM_SOURCE
    )
    fixture = build_named_fixture(
        "strace-go-ebpf-bpf-stream-fixture",
        (STREAM_FIXTURE_SOURCE,),
        ["-Werror", "-Wl,--no-as-needed", "-lbpf"],
    )
    result = subprocess.run(
        [wrapper, "--event-format=json", "-e", "trace=bpf", fixture, object_path],
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        errors="ignore",
        timeout=30,
        env=os.environ.copy(),
    )
    failures = check_bpf_stream(
        result.returncode,
        result.stdout,
        parse_json_events(result.stderr),
        parse_stats_events(result.stderr),
    )
    if not failures:
        print("=> eBPF bpf stream semantic success/failure paths verified")
    return failures
