#!/usr/bin/env python3
import unittest

from ebpf_bpf_prog_load_oracle import (
	 has_failed_prog_load_core_relos_probe,
	 has_failed_prog_load_fd_array_probe,
	 has_failed_prog_load_func_info_probe,
	 has_failed_prog_load_line_info_probe,
	 has_prog_load_core_relos_input,
	 has_prog_load_fd_array_input,
	 has_prog_load_func_info_input,
	 has_prog_load_line_info_input,
)
from ebpf_bpf_prog_load_testdata import (
	prog_load_core_relos_events,
	prog_load_fd_array_events,
	prog_load_func_info_events,
	prog_load_line_info_events,
)


class BpfProgLoadOracleTests(unittest.TestCase):
    def test_accepts_fd_array_input_and_failed_probe(self):
        events = prog_load_fd_array_events()
        self.assertTrue(has_prog_load_fd_array_input(events))
        self.assertTrue(has_failed_prog_load_fd_array_probe(events))

    def test_rejects_missing_fd_array_section(self):
        events = prog_load_fd_array_events()
        events[0]["payload_sections"] = events[0]["payload_sections"][:1]
        self.assertFalse(has_prog_load_fd_array_input(events))

    def test_accepts_fragment_merged_into_paired_exit(self):
        events = prog_load_fd_array_events()
        attr = events[0]["payload_sections"].pop(0)
        fragment = events[0]["payload_sections"].pop()
        events[1]["paired_enter"] = True
        events[1]["payload_sections"] = [attr, fragment]
        self.assertTrue(has_prog_load_fd_array_input(events))

    def test_rejects_wrong_direction(self):
        events = prog_load_fd_array_events()
        events[0]["payload_sections"][1]["direction"] = "out"
        self.assertFalse(has_prog_load_fd_array_input(events))

    def test_rejects_wrong_logical_width(self):
        events = prog_load_fd_array_events()
        events[0]["payload_sections"][1]["user_len"] = 4
        self.assertFalse(has_prog_load_fd_array_input(events))

    def test_accepts_func_info_input_and_failed_probe(self):
        events = prog_load_func_info_events()
        self.assertTrue(has_prog_load_func_info_input(events))
        self.assertTrue(has_failed_prog_load_func_info_probe(events))

    def test_rejects_missing_func_info_section(self):
        events = prog_load_func_info_events()
        events[0]["payload_sections"] = events[0]["payload_sections"][:1]
        self.assertFalse(has_prog_load_func_info_input(events))

    def test_rejects_wrong_func_info_direction(self):
        events = prog_load_func_info_events()
        events[0]["payload_sections"][1]["direction"] = "out"
        self.assertFalse(has_prog_load_func_info_input(events))

    def test_rejects_wrong_func_info_width(self):
        events = prog_load_func_info_events()
        events[0]["payload_sections"][1]["user_len"] = 8
        self.assertFalse(has_prog_load_func_info_input(events))

    def test_accepts_line_info_input_and_failed_probe(self):
        events = prog_load_line_info_events()
        self.assertTrue(has_prog_load_line_info_input(events))
        self.assertTrue(has_failed_prog_load_line_info_probe(events))

    def test_rejects_missing_line_info_section(self):
        events = prog_load_line_info_events()
        events[0]["payload_sections"] = events[0]["payload_sections"][:1]
        self.assertFalse(has_prog_load_line_info_input(events))

    def test_accepts_core_relos_input_and_failed_probe(self):
        events = prog_load_core_relos_events()
        self.assertTrue(has_prog_load_core_relos_input(events))
        self.assertTrue(has_failed_prog_load_core_relos_probe(events))

    def test_rejects_missing_core_relos_section(self):
        events = prog_load_core_relos_events()
        events[0]["payload_sections"] = events[0]["payload_sections"][:1]
        self.assertFalse(has_prog_load_core_relos_input(events))


if __name__ == "__main__":
    unittest.main()
