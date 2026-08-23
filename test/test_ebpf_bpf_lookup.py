#!/usr/bin/env python3
import copy
import unittest

from ebpf_bpf_lookup_oracle import (
    has_failed_lookup_key_probe_failure,
    has_lookup_key_inputs,
)
from ebpf_bpf_lookup_testdata import lookup_events


class BpfMapLookupOracleTests(unittest.TestCase):
    def test_accepts_both_lookup_key_snapshots(self):
        self.assertTrue(has_lookup_key_inputs(lookup_events()))

    def test_rejects_missing_lookup_key_snapshot(self):
        events = copy.deepcopy(lookup_events())
        events[0]["payload_sections"] = events[0]["payload_sections"][:1]
        self.assertFalse(has_lookup_key_inputs(events))

    def test_rejects_wrong_direction(self):
        events = copy.deepcopy(lookup_events())
        events[0]["payload_sections"][1]["direction"] = "out"
        self.assertFalse(has_lookup_key_inputs(events))

    def test_accepts_failed_lookup_key_probe_failure(self):
        events = lookup_events()
        self.assertTrue(has_failed_lookup_key_probe_failure(events))

    def test_rejects_failed_lookup_without_key_probe_failure(self):
        events = lookup_events()[:4]
        events[1]["ret"] = -14
        self.assertFalse(has_failed_lookup_key_probe_failure(events))


if __name__ == "__main__":
    unittest.main()
