#!/usr/bin/env python3
import copy
import unittest

from ebpf_bpf_next_key_oracle import has_get_next_key
from ebpf_bpf_next_key_testdata import next_key_events


class BpfGetNextKeyOracleTests(unittest.TestCase):
    def test_accepts_directional_snapshots(self):
        self.assertTrue(has_get_next_key(next_key_events()))

    def test_rejects_missing_next_key_output(self):
        events = copy.deepcopy(next_key_events())
        for event in events:
            if event.get("event_type") == "exit" and event.get("ret") == 0:
                event["payload_sections"] = []
        self.assertFalse(has_get_next_key(events))
