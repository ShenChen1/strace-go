#!/usr/bin/env python3
import os
import subprocess
import tempfile

from ebpf_fixture_build import build_fixture


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
FIXTURE_SOURCE = os.path.join(
    SCRIPT_DIR, "fixtures", "ebpf_no_ptrace_fixture.c"
)


def parse_tracer_pid(status_text):
    for line in status_text.splitlines():
        if not line.startswith("TracerPid:"):
            continue
        try:
            value = int(line.split(":", 1)[1].strip())
        except (IndexError, ValueError):
            return None
        return value if value >= 0 else None
    return None


def check_no_ptrace_fixture(result):
    failures = []
    if result.returncode != 0:
        failures.append(f"no-ptrace fixture rc={result.returncode}")
    if "no-ptrace-fixture-ok" not in result.stdout:
        failures.append("no-ptrace fixture marker missing")
    tracer_pid = parse_tracer_pid(result.stdout)
    if tracer_pid is None:
        failures.append("no-ptrace fixture TracerPid observation missing")
    elif tracer_pid != 0:
        failures.append(f"no-ptrace fixture observed TracerPid={tracer_pid}")
    return failures


def run_no_ptrace_semantic(wrapper, root):
    fd, fixture = tempfile.mkstemp(prefix="strace-go-ebpf-no-ptrace-")
    os.close(fd)
    os.unlink(fixture)
    try:
        build_fixture((FIXTURE_SOURCE,), fixture)
        result = subprocess.run(
            [wrapper, "--event-format=json", "-e", "trace=openat,read,close", fixture],
            cwd=root,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="ignore",
            timeout=30,
            env=os.environ.copy(),
        )
    finally:
        try:
            os.unlink(fixture)
        except FileNotFoundError:
            pass
    failures = check_no_ptrace_fixture(result)
    if not failures:
        print("=> eBPF no-ptrace runtime invariant verified")
    return failures
