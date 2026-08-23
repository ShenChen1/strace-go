#!/usr/bin/env python3
import copy
import unittest

from ebpf_bpf_next_id_oracle import has_get_next_id_output
from ebpf_bpf_next_id_testdata import next_id_events


class BpfGetNextIDOracleTests(unittest.TestCase):
    def test_accepts_exit_snapshot(self):
        self.assertTrue(has_get_next_id_output(next_id_events()))

    def test_rejects_missing_snapshot(self):
        events = copy.deepcopy(next_id_events())
        events[1]["payload_sections"] = []
        self.assertFalse(has_get_next_id_output(events))

    def test_rejects_wrong_direction(self):
        events = copy.deepcopy(next_id_events())
        events[1]["payload_sections"][0]["direction"] = "in"
        self.assertFalse(has_get_next_id_output(events))

    def test_rejects_wrong_width(self):
        events = copy.deepcopy(next_id_events())
        events[1]["payload_sections"][0]["user_len"] = 8
        self.assertFalse(has_get_next_id_output(events))


if __name__ == "__main__":
    unittest.main()
