#!/usr/bin/env python3
import copy
import unittest

from ebpf_bpf_task_fd_query_oracle import (
    failed_task_fd_query_has_no_output,
    has_task_fd_query_output,
)
from ebpf_bpf_task_fd_query_testdata import task_fd_query_events


class BpfTaskFdQueryOracleTests(unittest.TestCase):
    def test_accepts_exit_string_snapshot(self):
        self.assertTrue(has_task_fd_query_output(task_fd_query_events()))

    def test_rejects_missing_snapshot(self):
        events = copy.deepcopy(task_fd_query_events())
        events[1]["payload_sections"] = []
        self.assertFalse(has_task_fd_query_output(events))

    def test_rejects_wrong_direction(self):
        events = copy.deepcopy(task_fd_query_events())
        events[1]["payload_sections"][0]["direction"] = "in"
        self.assertFalse(has_task_fd_query_output(events))

    def test_rejects_failed_output(self):
        self.assertTrue(failed_task_fd_query_has_no_output(task_fd_query_events()))
        events = copy.deepcopy(task_fd_query_events())
        events[2]["payload_sections"] = [events[1]["payload_sections"][0]]
        self.assertFalse(failed_task_fd_query_has_no_output(events))


if __name__ == "__main__":
    unittest.main()
