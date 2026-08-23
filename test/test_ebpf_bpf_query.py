#!/usr/bin/env python3
import copy
import unittest

from ebpf_bpf_query_oracle import (
    failed_query_has_no_output,
    has_prog_attach_detach_lifecycle,
    has_prog_query_output_arrays,
)
from ebpf_bpf_query_testdata import query_events


class BpfProgQueryOracleTests(unittest.TestCase):
    def test_accepts_ordered_output_arrays(self):
        self.assertTrue(has_prog_query_output_arrays(query_events()))

    def test_rejects_missing_output_array(self):
        events = copy.deepcopy(query_events())
        events[1]["payload_sections"] = events[1]["payload_sections"][:-1]
        self.assertFalse(has_prog_query_output_arrays(events))

    def test_rejects_wrong_direction(self):
        events = copy.deepcopy(query_events())
        events[1]["payload_sections"][1]["direction"] = "in"
        self.assertFalse(has_prog_query_output_arrays(events))

    def test_rejects_failed_query_output(self):
        self.assertTrue(failed_query_has_no_output(query_events()))
        events = copy.deepcopy(query_events())
        events[2]["payload_sections"] = [events[1]["payload_sections"][1]]
        self.assertFalse(failed_query_has_no_output(events))

    def test_accepts_program_attach_and_detach_lifecycle(self):
        events = []
        for command in (8, 9):
            events.extend(
                [
                    {
                        "syscall": "bpf",
                        "event_type": "enter",
                        "args": [command, 0x1000],
                        "payload_sections": [
                            {
                                "direction": "in",
                                "arg_index": 1,
                                "probe_ret": 0,
                                "copied_len": 16,
                            }
                        ],
                    },
                    {
                        "syscall": "bpf",
                        "event_type": "exit",
                        "args": [command, 0x1000],
                        "ret": 0,
                        "paired_enter": True,
                    },
                ]
            )
        self.assertTrue(has_prog_attach_detach_lifecycle(events))

    def test_rejects_unpaired_program_detach(self):
        events = [
            {
                "syscall": "bpf",
                "event_type": "enter",
                "args": [8, 0x1000],
                "payload_sections": [
                    {"direction": "in", "arg_index": 1, "probe_ret": 0, "copied_len": 16}
                ],
            },
            {
                "syscall": "bpf",
                "event_type": "exit",
                "args": [8, 0x1000],
                "ret": 0,
                "paired_enter": True,
            },
        ]
        self.assertFalse(has_prog_attach_detach_lifecycle(events))


if __name__ == "__main__":
    unittest.main()
