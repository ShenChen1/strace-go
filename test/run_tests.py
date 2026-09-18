#!/usr/bin/env python3
import argparse
import multiprocessing
import os
import platform
import shlex
import signal
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

from ebpf_perf_suite import run_ebpf_perf
from ebpf_capture_suite import run_ebpf_capture, run_ebpf_capture_long
from ebpf_bpf_rare_suite import run_bpf_capability_semantic
from ebpf_bpf_stream_suite import run_bpf_stream_semantic
from ebpf_bpf_struct_ops_suite import run_bpf_struct_ops_semantic
from ebpf_no_ptrace_suite import run_no_ptrace_semantic
from ebpf_suites import build_strace_go, run_ebpf_semantic
from upstream_suites import (
    MORE_EXPECTED_FAILURES,
    MORE_TOLERATED_XPASSES,
    MORE_TESTS,
    SMOKE_TESTS,
    UPSTREAM_REFERENCE_EXPECTED_FAILURES,
    UPSTREAM_REFERENCE_TESTS,
)


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
TESTS_DIR = os.path.join(PROJECT_ROOT, "strace-upstream", "tests")
UPSTREAM_DIR = os.path.join(PROJECT_ROOT, "strace-upstream")
UPSTREAM_CONFIGURE_ARGS = [
    "./configure",
    "--enable-mpers=no",
    "--enable-stacktrace=no",
    "--without-libiberty",
    "--without-libselinux",
    "CFLAGS=-g -O2 -Wno-error",
]
CONFIGURED_TESTS_MAKE_RULE = (
    ".PHONY: print-strace-go-tests\n"
    "print-strace-go-tests:\n"
    "\t@printf '%s\\n' $(TESTS)\n"
)
UPSTREAM_TEST_TIMEOUT_SECONDS = {
    "qual_signal.test": 180,
    "qual_syscall.test": 180,
    "filtering_syscall-syntax.test": 180,
    "readv.test": 60,
    "strace-S.test": 120,
    "trace_clock.gen.test": 180,
    "trace_fstat.gen.test": 600,
    "trace_fstatfs.gen.test": 180,
    "trace_personality_64.gen.test": 180,
    "trace_personality_32.gen.test": 180,
    "trace_personality_x32.gen.test": 180,
    "trace_personality_number_64.gen.test": 180,
    "trace_personality_regex_64.gen.test": 180,
    "trace_personality_statfs_64.gen.test": 180,
    "trace_personality_all_32.gen.test": 180,
    "trace_personality_all_x32.gen.test": 180,
    "trace_stat_like.gen.test": 600,
    "trace_statfs.gen.test": 180,
    "trace_statfs_like.gen.test": 180,
}


class UpstreamSetupError(RuntimeError):
    pass


@dataclass
class SuiteResults:
    counts: dict = field(
        default_factory=lambda: {
            "pass": 0,
            "fail": 0,
            "skip": 0,
            "xfail": 0,
            "xpass": 0,
            "xpass_allowed": 0,
        }
    )
    failed: list = field(default_factory=list)
    xfailed: list = field(default_factory=list)
    xpassed: list = field(default_factory=list)
    xpassed_allowed: list = field(default_factory=list)

    def record(self, result, expected_failures, tolerated_xpasses=None):
        outcome, reason = classify_test_result(
            result, expected_failures, tolerated_xpasses
        )
        self.counts[outcome] += 1
        if outcome == "fail":
            self.failed.append(result)
        elif outcome == "xfail":
            self.xfailed.append((result, reason))
        elif outcome == "xpass":
            self.xpassed.append((result, reason))
        elif outcome == "xpass_allowed":
            self.xpassed_allowed.append((result, reason))
        return outcome, reason


def parse_args():
    parser = argparse.ArgumentParser(description="Unified test framework for strace-go")
    parser.add_argument(
        "--suite",
        choices=[
            "small",
            "more",
            "all",
            "upstream-reference",
            "ebpf-semantic",
            "ebpf-capability",
            "ebpf-stream",
            "ebpf-struct-ops",
            "ebpf-no-ptrace",
            "ebpf-perf",
            "ebpf-capture",
            "ebpf-capture-long",
        ],
        default="small",
        help="Which test suite to run",
    )
    parser.add_argument("--limit", type=int, default=0, help="Limit tests (0 for unlimited)")
    parser.add_argument("--parallel", type=int, default=1, help="Parallel workers")
    parser.add_argument("--filter", type=str, default="", help="Filter by exact test name")
    parser.add_argument("--skip-build", action="store_true", help="Skip upstream build")
    parser.add_argument(
        "--arch",
        choices=("amd64", "arm64"),
        default="",
        help="native target architecture; must match the host; defaults to ARCH, GOARCH, or uname",
    )
    return parser.parse_args()


def native_linux_architecture(explicit="", goarch="", machine=""):
    requested = explicit or goarch or machine or platform.machine()
    aliases = {
        "amd64": "x86_64",
        "x86_64": "x86_64",
        "arm64": "aarch64",
        "aarch64": "aarch64",
    }
    try:
        return aliases[requested]
    except KeyError as exc:
        raise ValueError(
            f"unsupported architecture: {requested}; supported architectures: amd64, arm64"
        ) from exc


def setup_env(explicit_arch="", machine=""):
    linux_arch = native_linux_architecture(
        explicit_arch, os.environ.get("ARCH", "") or os.environ.get("GOARCH", "")
    )
    host_arch = native_linux_architecture("", "", machine or platform.machine())
    if linux_arch != host_arch:
        raise ValueError(
            f"native tests require a native Linux/{linux_arch} host; current host is {host_arch}"
        )
    os.environ["STRACE"] = os.path.join(SCRIPT_DIR, "strace-sudo.sh")
    os.environ["SIZEOF_LONG"] = "8"
    os.environ["STRACE_ARCH"] = linux_arch
    os.environ["STRACE_NATIVE_ARCH"] = linux_arch
    os.environ["MIPS_ABI"] = ""


def root_requirement_error(euid):
    if euid == 0:
        return ""
    return "test suites require root; rerun with sudo -n python3 test/run_tests.py"


def run_upstream_command(command, cwd, stage, input_text=None):
    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            input=input_text,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as exc:
        raise UpstreamSetupError(
            f"{stage} could not start: {shlex.join(command)}: {exc}"
        ) from exc
    if result.returncode == 0:
        return result.stdout

    output = "\n".join(
        part.strip() for part in (result.stdout, result.stderr) if part.strip()
    )
    message = (
        f"{stage} failed with exit code {result.returncode}: {shlex.join(command)}"
    )
    if output:
        message = f"{message}\n{output}"
    raise UpstreamSetupError(message)


def build_upstream():
    if not os.path.isfile(os.path.join(UPSTREAM_DIR, "Makefile")):
        print("=> Configuring upstream strace...")
        run_upstream_command(["./bootstrap"], UPSTREAM_DIR, "upstream bootstrap")
        run_upstream_command(
            UPSTREAM_CONFIGURE_ARGS,
            UPSTREAM_DIR,
            "upstream configure",
        )
    print("=> Building upstream strace (make -j)...")
    try:
        cpus = multiprocessing.cpu_count()
    except NotImplementedError:
        cpus = 4
    run_upstream_command(
        ["make", f"-j{cpus}"],
        UPSTREAM_DIR,
        "upstream build",
    )
    print("=> Building upstream test prerequisites...")
    run_upstream_command(
        [
            "make",
            "--no-print-directory",
            "-C",
            "tests",
            "check-prerequisites-local",
        ],
        UPSTREAM_DIR,
        "upstream test prerequisite build",
    )


def parse_configured_upstream_tests(output):
    entries = output.split()
    if not entries:
        raise UpstreamSetupError("configured upstream test inventory is empty")
    invalid = [
        entry
        for entry in entries
        if not entry.endswith(".test") or os.path.basename(entry) != entry
    ]
    if invalid:
        raise UpstreamSetupError(f"unexpected configured test entry: {invalid[0]}")
    return sorted(set(entries))


def configured_upstream_tests():
    output = run_upstream_command(
        [
            "make",
            "--no-print-directory",
            "-s",
            "-f",
            "Makefile",
            "-f",
            "-",
            "print-strace-go-tests",
        ],
        TESTS_DIR,
        "configured upstream test inventory",
        input_text=CONFIGURED_TESTS_MAKE_RULE,
    )
    return parse_configured_upstream_tests(output)


def get_tests(suite):
    if suite == "all":
        return configured_upstream_tests()
    if not os.path.exists(TESTS_DIR):
        print(f"Tests dir {TESTS_DIR} not found.")
        return []
    valid_tests = sorted(
        name
        for name in os.listdir(TESTS_DIR)
        if name.endswith(".test")
        and not name.endswith(".sh")
        and name != "strace-k.test"
    )
    if suite == "small":
        return [test for test in SMOKE_TESTS if test in valid_tests]
    if suite == "more":
        return [test for test in MORE_TESTS if test in valid_tests]
    if suite == "upstream-reference":
        return [test for test in UPSTREAM_REFERENCE_TESTS if test in valid_tests]
    return [test for test in valid_tests if suite in test]


def wait_for_upstream_test(process, test):
    try:
        return process.wait(timeout=UPSTREAM_TEST_TIMEOUT_SECONDS.get(test, 30))
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        process.wait(timeout=5)
        return 124


def run_test(test):
    out_fd, out_path = tempfile.mkstemp()
    err_fd, err_path = tempfile.mkstemp()
    try:
        with os.fdopen(out_fd, "w") as stdout, os.fdopen(err_fd, "w") as stderr:
            process = subprocess.Popen(
                [f"./{test}"],
                cwd=TESTS_DIR,
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                start_new_session=True,
            )
            returncode = wait_for_upstream_test(process, test)
        with open(out_path, "r", errors="ignore") as output:
            stdout_text = output.read()
        with open(err_path, "r", errors="ignore") as output:
            stderr_text = output.read()
        return {
            "test": test,
            "success": returncode == 0,
            "stdout": stdout_text,
            "stderr": stderr_text,
            "rc": returncode,
        }
    finally:
        os.remove(out_path)
        os.remove(err_path)


def expected_failures_for_suite(suite):
    if suite == "upstream-reference":
        return UPSTREAM_REFERENCE_EXPECTED_FAILURES
    if suite == "more":
        return MORE_EXPECTED_FAILURES
    return {}


def classify_test_result(result, expected_failures, tolerated_xpasses=None):
    reason = expected_failures.get(result["test"], "")
    tolerated = tolerated_xpasses or set()
    if result["rc"] == 77:
        return "skip", ""
    if result["success"]:
        if reason and result["test"] in tolerated:
            return "xpass_allowed", reason
        return ("xpass", reason) if reason else ("pass", "")
    return ("xfail", reason) if reason else ("fail", "")


def outcome_label(outcome, reason):
    labels = {
        "pass": "PASS",
        "skip": "SKIP",
        "fail": "FAIL",
        "xpass_allowed": f"XPASS-ALLOWED ({reason})",
    }
    if outcome == "xfail":
        return f"XFAIL ({reason})"
    if outcome == "xpass":
        return f"XPASS ({reason})"
    return labels[outcome]


def print_results(results):
    counts = results.counts
    print("\n=== SUMMARY ===")
    print(f"Passed:  {counts['pass']}")
    print(f"Failed:  {counts['fail']}")
    print(f"Skipped: {counts['skip']}")
    print(f"XFailed: {counts['xfail']}")
    print(f"XPassed: {counts['xpass']}")
    print(f"XPASS allowed: {counts['xpass_allowed']}")
    print(f"Total:   {sum(counts.values())}")
    print_expected_outcomes(results)
    print_failure_details(results.failed)


def print_expected_outcomes(results):
    if results.xfailed:
        print("\n=== EXPECTED FAILURES ===")
        for result, reason in results.xfailed:
            print(f"{result['test']}: {reason}")
    if results.xpassed:
        print("\n=== UNEXPECTED PASSES ===")
        for result, reason in results.xpassed:
            print(f"{result['test']}: {reason}")
    if results.xpassed_allowed:
        print("\n=== NON-CONTRACT PASSES ===")
        for result, reason in results.xpassed_allowed:
            print(f"{result['test']}: {reason}")


def print_failure_details(failed):
    if not failed:
        return
    print("\n=== FAIL DETAILS ===")
    for result in failed:
        print(f"\n--- {result['test']} ---")
        if result["stdout"]:
            print("STDOUT:")
            print("\n".join(result["stdout"].split("\n")[:15]))
        if result["stderr"]:
            print("STDERR:")
            print(result["stderr"])


def selected_tests(args):
    tests = get_tests(args.suite)
    if args.filter:
        tests = [test for test in tests if test == args.filter]
    return tests[: args.limit] if args.limit > 0 else tests


def record_and_print(
    result, expected_failures, results, tolerated_xpasses=None, include_name=True
):
    outcome, reason = results.record(result, expected_failures, tolerated_xpasses)
    label = outcome_label(outcome, reason)
    if include_name:
        print(f"{label}: {result['test']}")
    else:
        print(label)


def run_upstream_suite(args):
    try:
        if not args.skip_build:
            build_upstream()
        tests = selected_tests(args)
    except UpstreamSetupError as exc:
        print(f"=> Upstream setup failed: {exc}", file=sys.stderr)
        return 2
    print(f"=> Running {len(tests)} tests from '{args.suite}' suite...")
    results = SuiteResults()
    expected = expected_failures_for_suite(args.suite)
    tolerated_xpasses = MORE_TOLERATED_XPASSES if args.suite == "more" else set()
    if args.parallel > 1:
        print(f"=> Using {args.parallel} parallel workers.")
        with ThreadPoolExecutor(max_workers=args.parallel) as executor:
            futures = {executor.submit(run_test, test): test for test in tests}
            for future in as_completed(futures):
                record_and_print(
                    future.result(), expected, results, tolerated_xpasses
                )
    else:
        for test in tests:
            print(f"Running {test}... ", end="", flush=True)
            record_and_print(
                run_test(test), expected, results, tolerated_xpasses, include_name=False
            )
    print_results(results)
    return 1 if results.counts["fail"] > 0 or results.counts["xpass"] > 0 else 0


def main():
    args = parse_args()
    root_error = root_requirement_error(os.geteuid())
    if root_error:
        print(root_error, file=sys.stderr)
        return 2
    try:
        setup_env(args.arch)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    if args.suite == "ebpf-semantic":
        return run_ebpf_semantic(args)
    if args.suite == "ebpf-capability":
        if not args.skip_build:
            build_strace_go()
        return run_bpf_capability_semantic(
            os.path.join(SCRIPT_DIR, "strace-sudo.sh"), PROJECT_ROOT
        )
    if args.suite == "ebpf-stream":
        if not args.skip_build:
            build_strace_go()
        failures = run_bpf_stream_semantic(
            os.path.join(SCRIPT_DIR, "strace-sudo.sh"), PROJECT_ROOT
        )
        if failures:
            for failure in failures:
                print(f"FAIL: {failure}")
            return 1
        print("PASS: ebpf-stream")
        return 0
    if args.suite == "ebpf-struct-ops":
        if not args.skip_build:
            build_strace_go()
        failures = run_bpf_struct_ops_semantic(
            os.path.join(SCRIPT_DIR, "strace-sudo.sh"), PROJECT_ROOT
        )
        if failures:
            for failure in failures:
                print(f"FAIL: {failure}")
            return 1
        print("PASS: ebpf-struct-ops")
        return 0
    if args.suite == "ebpf-no-ptrace":
        if not args.skip_build:
            build_strace_go()
        failures = run_no_ptrace_semantic(
            os.path.join(SCRIPT_DIR, "strace-sudo.sh"), PROJECT_ROOT
        )
        if failures:
            for failure in failures:
                print(f"FAIL: {failure}")
            return 1
        print("PASS: ebpf-no-ptrace")
        return 0
    if args.suite == "ebpf-perf":
        return run_ebpf_perf(args)
    if args.suite == "ebpf-capture":
        return run_ebpf_capture(args)
    if args.suite == "ebpf-capture-long":
        return run_ebpf_capture_long(args)
    return run_upstream_suite(args)


if __name__ == "__main__":
    sys.exit(main())
