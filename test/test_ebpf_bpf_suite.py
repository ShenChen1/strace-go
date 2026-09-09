#!/usr/bin/env python3
import base64
import unittest

from ebpf_bpf_suite import _fixture_diagnostic_lines, check_bpf_semantic
from ebpf_bpf_delete_oracle import has_delete_batch_keys
from ebpf_bpf_testdata_core import clean_stats, section
from ebpf_bpf_testdata_events import valid_events


class BpfSemanticOracleTests(unittest.TestCase):
    def test_extracts_fixture_stderr_without_json_trace_lines(self):
        stderr = '{"type":"syscall"}\nfixture: BPF_MAP_CREATE: Operation not permitted\n'

        self.assertEqual(
            _fixture_diagnostic_lines(stderr),
            ["fixture: BPF_MAP_CREATE: Operation not permitted"],
        )

    def test_accepts_delete_batch_keys_snapshot(self):
        events = valid_events()
        self.assertTrue(has_delete_batch_keys(events))

    def test_rejects_missing_delete_batch_keys_snapshot(self):
        events = [
            event
            for event in valid_events()
            if not (
                event.get("event_type") == "enter"
                and event.get("args", [None])[0] == 27
                and any(
                    section.get("arg_index") == 121
                    for section in event.get("payload_sections") or []
                )
            )
        ]
        failures = check_bpf_semantic(0, "bpf-fixture-ok\n", events, [clean_stats()])
        self.assertIn("BPF_MAP_DELETE_BATCH keys input snapshot missing", failures)

    def test_accepts_map_and_prog_load_input_snapshots(self):
        failures = check_bpf_semantic(
            0,
            "bpf-fixture-ok\n",
            valid_events(),
            [clean_stats()],
        )
        self.assertEqual(failures, [])

    def test_rejects_missing_map_lookup_output(self):
        events = valid_events()
        for event in events:
            if (
                event.get("event_type") == "exit"
                and event.get("args", [None])[0] == 1
                and event.get("ret") == 0
            ):
                event["payload_sections"] = []
        failures = check_bpf_semantic(0, "bpf-fixture-ok\n", events, [clean_stats()])
        self.assertIn("BPF_MAP_LOOKUP_ELEM value OUT snapshot missing", failures)

    def test_rejects_missing_map_batch_values_output(self):
        events = valid_events()
        for event in events:
            if (
                event.get("event_type") == "exit"
                and event.get("args", [None])[0] == 24
                and event.get("ret") == 0
            ):
                event["payload_sections"] = [
                    section
                    for section in event.get("payload_sections") or []
                    if section.get("arg_index") != 119
                ]
        failures = check_bpf_semantic(0, "bpf-fixture-ok\n", events, [clean_stats()])
        self.assertIn("BPF_MAP_LOOKUP_BATCH values OUT snapshot missing", failures)

    def test_rejects_missing_map_batch_input(self):
        events = valid_events()
        update_enter = next(
            event
            for event in events
            if event.get("event_type") == "enter"
            and event.get("args", [None])[0] == 26
        )
        update_enter["payload_sections"] = update_enter["payload_sections"][:1]
        failures = check_bpf_semantic(0, "bpf-fixture-ok\n", events, [clean_stats()])
        self.assertIn("BPF_MAP_UPDATE_BATCH input snapshot missing", failures)

    def test_rejects_missing_percpu_value_semantics(self):
        events = valid_events()
        events = [
            event
            for event in events
            if not (
                event.get("event_type") == "enter"
                and event.get("args", [None])[0] == 26
                and any(
                    section.get("arg_index") == 122
                    and b"percpu-no-flags" in base64.b64decode(
                        section.get("data_base64") or ""
                    )
                    for section in event.get("payload_sections") or []
                )
            )
        ]
        failures = check_bpf_semantic(0, "bpf-fixture-ok\n", events, [clean_stats()])
        self.assertIn("BPF per-CPU map value semantics missing", failures)

    def test_rejects_short_hash_batch_cursor(self):
        events = valid_events()
        cursor_exit = next(
            event
            for event in events
            if event.get("event_type") == "exit"
            and event.get("args", [None])[0] == 24
            and any(
                section.get("arg_index") == 119
                and b"cursor-value"
                in base64.b64decode(section.get("data_base64") or "")
                for section in event.get("payload_sections") or []
            )
        )
        cursor_section = next(
            section
            for section in cursor_exit["payload_sections"]
            if section.get("arg_index") == 120
        )
        cursor_section["user_len"] = 1
        failures = check_bpf_semantic(0, "bpf-fixture-ok\n", events, [clean_stats()])
        self.assertIn("BPF hash batch cursor minimum width missing", failures)

    def test_rejects_batch_partial_output_with_unrelated_errno(self):
        events = valid_events()
        partial_exit = next(
            event
            for event in events
            if event.get("event_type") == "exit"
            and event.get("args", [None])[0] == 24
            and event.get("ret") == -2
        )
        partial_exit["ret"] = -14
        failures = check_bpf_semantic(0, "bpf-fixture-ok\n", events, [clean_stats()])
        self.assertIn("BPF batch terminal ENOENT OUT snapshot missing", failures)

    def test_rejects_missing_nested_payload(self):
        events = valid_events()
        prog_enter = next(
            event
            for event in events
            if event.get("event_type") == "enter"
            and event.get("args", [None])[0] == 5
        )
        prog_enter["payload_sections"] = prog_enter["payload_sections"][:1]
        failures = check_bpf_semantic(0, "bpf-fixture-ok\n", events, [clean_stats()])
        self.assertIn("BPF_PROG_LOAD instruction payload missing", failures)

    def test_rejects_fabricated_output_on_failed_exit(self):
        events = valid_events()
        prog_exit = next(
            event
            for event in events
            if event.get("event_type") == "exit"
            and event.get("args", [None])[0] == 5
        )
        prog_exit["payload_sections"] = [section("bytes", "out", 1, b"bad")]
        failures = check_bpf_semantic(0, "bpf-fixture-ok\n", events, [clean_stats()])
        self.assertIn("failed BPF event fabricated OUT payload", failures)

    def test_rejects_missing_verifier_log_output(self):
        events = valid_events()
        prog_exit = next(
            event
            for event in events
            if event.get("event_type") == "exit"
            and event.get("args", [None])[0] == 5
        )
        prog_exit["payload_sections"] = []
        failures = check_bpf_semantic(0, "bpf-fixture-ok\n", events, [clean_stats()])
        self.assertIn("BPF_PROG_LOAD verifier log OUT snapshot missing", failures)

    def test_rejects_missing_btf_verifier_log_output(self):
        events = valid_events()
        btf_exit = next(
            event
            for event in events
            if event.get("event_type") == "exit"
            and event.get("args", [None])[0] == 18
        )
        btf_exit["payload_sections"] = []
        failures = check_bpf_semantic(0, "bpf-fixture-ok\n", events, [clean_stats()])
        self.assertIn("BPF_BTF_LOAD verifier log OUT snapshot missing", failures)

    def test_rejects_missing_test_run_context_output(self):
        events = valid_events()
        test_exit = next(
            event
            for event in events
            if event.get("event_type") == "exit"
            and event.get("args", [None])[0] == 10
        )
        test_exit["payload_sections"] = [
            section("bytes", "out", 115, b"data-out", user_len=8),
        ]
        failures = check_bpf_semantic(0, "bpf-fixture-ok\n", events, [clean_stats()])
        self.assertIn("BPF_PROG_TEST_RUN ctx_out snapshot missing", failures)

    def test_rejects_reversed_test_run_output_order(self):
        events = valid_events()
        test_exit = next(
            event
            for event in events
            if event.get("event_type") == "exit"
            and event.get("args", [None])[0] == 10
            and event.get("ret") == 0
        )
        test_exit["payload_sections"].reverse()
        failures = check_bpf_semantic(0, "bpf-fixture-ok\n", events, [clean_stats()])
        self.assertIn("BPF_PROG_TEST_RUN output order is unstable", failures)

    def test_rejects_runtime_counter_failure(self):
        failures = check_bpf_semantic(
            0,
            "bpf-fixture-ok\n",
            valid_events(),
            [clean_stats(ringbuf_copy_fail=1)],
        )
        self.assertIn("BPF ringbuf_copy_fail is non-zero", failures)


if __name__ == "__main__":
    unittest.main()
