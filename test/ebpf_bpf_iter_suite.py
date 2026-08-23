import os
import subprocess

from ebpf_bpf_iter_oracle import check_bpf_iter
from ebpf_event_oracles import parse_json_events, parse_stats_events
from ebpf_fixture_build import build_named_fixture


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ITER_FIXTURE_SOURCE = os.path.join(
    SCRIPT_DIR, "fixtures", "ebpf_bpf_iter_fixture.c"
)


def run_bpf_iter_semantic(wrapper, root):
    fixture = build_named_fixture(
        "strace-go-ebpf-bpf-iter-fixture",
        (ITER_FIXTURE_SOURCE,),
        ["-Wl,--no-as-needed", "-lbpf"],
    )
    result = subprocess.run(
        [wrapper, "--event-format=json", "-e", "trace=bpf", fixture],
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        errors="ignore",
        timeout=30,
        env=os.environ.copy(),
    )
    failures = check_bpf_iter(
        result.returncode,
        result.stdout,
        parse_json_events(result.stderr),
        parse_stats_events(result.stderr),
    )
    if not failures:
        print("=> eBPF bpf iterator semantic success path verified")
    return failures
