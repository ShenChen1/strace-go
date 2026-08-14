#!/usr/bin/env python3
import argparse
import multiprocessing
import os
import signal
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

from ebpf_perf_suite import run_ebpf_perf
from ebpf_suites import run_ebpf_semantic
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
UPSTREAM_TEST_TIMEOUT_SECONDS = {"readv.test": 60}


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
            "ebpf-perf",
        ],
        default="small",
        help="Which test suite to run",
    )
    parser.add_argument("--limit", type=int, default=0, help="Limit tests (0 for unlimited)")
    parser.add_argument("--parallel", type=int, default=1, help="Parallel workers")
    parser.add_argument("--filter", type=str, default="", help="Filter by exact test name")
    parser.add_argument("--skip-build", action="store_true", help="Skip upstream build")
    return parser.parse_args()


def setup_env():
    os.environ["STRACE"] = os.path.join(SCRIPT_DIR, "strace-sudo.sh")
    os.environ["SIZEOF_LONG"] = "8"
    os.environ["STRACE_ARCH"] = "x86_64"
    os.environ["STRACE_NATIVE_ARCH"] = "x86_64"


def root_requirement_error(euid):
    if euid == 0:
        return ""
    return "test suites require root; rerun with sudo -n python3 test/run_tests.py"


def build_upstream():
    if not os.path.isfile(os.path.join(UPSTREAM_DIR, "Makefile")):
        print("=> Configuring upstream strace...")
        subprocess.run(["./bootstrap"], cwd=UPSTREAM_DIR, check=True)
        subprocess.run(
            [
                "./configure",
                "--enable-mpers=no",
                "CFLAGS=-g -O2 -Wno-error",
                "--disable-werror",
            ],
            cwd=UPSTREAM_DIR,
            check=True,
        )
    print("=> Building upstream strace (make -j)...")
    try:
        cpus = multiprocessing.cpu_count()
    except NotImplementedError:
        cpus = 4
    subprocess.run(
        ["make", f"-j{cpus}"],
        cwd=UPSTREAM_DIR,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def get_tests(suite):
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
    if suite == "all":
        return valid_tests
    return [test for test in valid_tests if suite in test]


def build_upstream_test_helper(test):
    binary = test.replace(".test", "").replace(".gen", "")
    subprocess.run(
        ["make", binary],
        cwd=TESTS_DIR,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if binary != "sleep-timing":
        return
    subprocess.run(
        [
            "gcc",
            "-g",
            "-O2",
            "-Wno-error",
            "-I../src",
            "-I.",
            "-isystem",
            "./bundled/linux/arch/x86/include/uapi",
            "-isystem",
            "./bundled/linux/include/uapi",
            "sleep-timing.c",
            "libtests.a",
            "-o",
            "sleep-timing",
        ],
        cwd=TESTS_DIR,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


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
    build_upstream_test_helper(test)
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
    if not args.skip_build:
        build_upstream()
    tests = selected_tests(args)
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
    setup_env()
    if args.suite == "ebpf-semantic":
        return run_ebpf_semantic(args)
    if args.suite == "ebpf-perf":
        return run_ebpf_perf(args)
    return run_upstream_suite(args)


if __name__ == "__main__":
    sys.exit(main())
