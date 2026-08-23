#!/usr/bin/env python3
import copy
import unittest

from ebpf_bpf_uprobe_oracle import (
    has_uprobe_multi_failed_event,
    has_uprobe_multi_input_sections,
)
from ebpf_bpf_uprobe_testdata import uprobe_events


class BpfUprobeOracleTests(unittest.TestCase):
    def test_accepts_path_and_arrays(self):
        self.assertTrue(has_uprobe_multi_input_sections(uprobe_events()))

    def test_rejects_missing_cookies(self):
        events = copy.deepcopy(uprobe_events())
        events[0]["payload_sections"] = events[0]["payload_sections"][:-1]
        self.assertFalse(has_uprobe_multi_input_sections(events))

    def test_accepts_paired_failure(self):
        self.assertTrue(has_uprobe_multi_failed_event(uprobe_events()))

    def test_rejects_unpaired_failure(self):
        events = copy.deepcopy(uprobe_events())
        events[1]["paired_enter"] = False
        self.assertFalse(has_uprobe_multi_failed_event(events))


if __name__ == "__main__":
    unittest.main()
