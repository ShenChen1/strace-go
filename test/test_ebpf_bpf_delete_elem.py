#!/usr/bin/env python3
import unittest

from ebpf_bpf_delete_oracle import has_delete_elem_key
from ebpf_bpf_delete_testdata import delete_elem_events


class BpfDeleteElemOracleTests(unittest.TestCase):
    def test_accepts_key_snapshot_and_failure_pair(self):
        self.assertTrue(has_delete_elem_key(delete_elem_events()))

    def test_rejects_missing_key_snapshot(self):
        events = delete_elem_events()
        events[0]["payload_sections"] = events[0]["payload_sections"][:1]
        self.assertFalse(has_delete_elem_key(events))


if __name__ == "__main__":
    unittest.main()
