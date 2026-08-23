#!/usr/bin/env python3
import copy
import unittest

from ebpf_bpf_update_oracle import has_large_update_elem_input, has_update_elem_inputs
from ebpf_bpf_update_testdata import update_elem_events


class BpfUpdateElemOracleTests(unittest.TestCase):
    def test_accepts_input_snapshots_and_failure_pair(self):
        self.assertTrue(has_update_elem_inputs(update_elem_events()))

    def test_rejects_missing_value_snapshot(self):
        events = copy.deepcopy(update_elem_events())
        events[0]["payload_sections"] = events[0]["payload_sections"][:2]
        self.assertFalse(has_update_elem_inputs(events))

    def test_requires_large_value_snapshot(self):
        self.assertTrue(has_large_update_elem_input(update_elem_events()))
        events = copy.deepcopy(update_elem_events())
        events[2]["payload_sections"][2]["copied_len"] = 20
        events[2]["payload_sections"][2]["data_base64"] = "bGFyZ2U="
        self.assertFalse(has_large_update_elem_input(events))


if __name__ == "__main__":
    unittest.main()
