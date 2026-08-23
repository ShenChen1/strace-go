#!/usr/bin/env python3

from ebpf_bpf_delete_oracle import has_delete_batch_keys, has_delete_elem_key
from ebpf_bpf_event_queries import (
    bpf_events,
    failed_events_have_no_output,
    has_failed_exit,
    has_hash_batch_cursor_width,
    has_map_batch_input_order,
    has_map_batch_output_order,
    has_map_batch_partial_output,
    has_output_section,
    has_paired_exit,
    has_section,
    has_test_run_output_order,
)
from ebpf_bpf_lookup_oracle import (
    has_failed_lookup_key_probe_failure,
    has_lookup_key_inputs,
)
from ebpf_bpf_next_id_oracle import has_get_next_id_output
from ebpf_bpf_next_key_oracle import has_get_next_key
from ebpf_bpf_percpu_oracle import has_percpu_map_semantics
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
from ebpf_bpf_query_oracle import (
    has_prog_attach_detach_lifecycle,
    has_prog_query_output_arrays,
)
from ebpf_bpf_task_fd_query_oracle import (
    failed_task_fd_query_has_no_output,
    has_task_fd_query_output,
)
from ebpf_bpf_uprobe_oracle import (
    has_uprobe_multi_failed_event,
    has_uprobe_multi_input_sections,
)
from ebpf_bpf_update_oracle import has_large_update_elem_input, has_update_elem_inputs
from ebpf_check_support import require, valid_stats_event


BPF_ZERO_STATS = (
    "ringbuf_reserve_fail",
    "ringbuf_copy_fail",
    "pending_update_fail",
    "orphan_exit",
    "pending_mismatch",
    "lifecycle_map_update_fail",
    "pending_stale",
)


def _check_runtime(returncode, stdout, events, stats_events):
    failures = []
    require(returncode == 0, failures, f"BPF fixture rc={returncode}")
    require("bpf-fixture-ok" in stdout, failures, "BPF fixture marker missing")
    require(events, failures, "BPF fixture produced no syscall events")
    require(len(stats_events) == 1, failures, "BPF stats event missing")
    if stats_events:
        stats = stats_events[0]
        require(valid_stats_event(stats), failures, "BPF stats event is malformed")
        for key in BPF_ZERO_STATS:
            require(stats.get(key) == 0, failures, f"BPF {key} is non-zero")
    return failures


def _check_map_lookup(events):
    failures = []
    require(
        has_section(events, 0, "bytes", "in", 1, b"strace_go_map"),
        failures,
        "BPF_MAP_CREATE attr snapshot missing",
    )
    require(has_paired_exit(events, 0), failures, "BPF_MAP_CREATE exit was not paired")
    require(
        has_section(events, 1, "bytes", "in", 1),
        failures,
        "BPF_MAP_LOOKUP_ELEM attr snapshot missing",
    )
    require(
        has_output_section(events, 1, "bytes", 117, b"map-value", ret=0),
        failures,
        "BPF_MAP_LOOKUP_ELEM value OUT snapshot missing",
    )
    require(has_lookup_key_inputs(events), failures, "BPF_MAP_LOOKUP_ELEM key IN snapshots missing")
    require(has_paired_exit(events, 1), failures, "BPF_MAP_LOOKUP_ELEM exit was not paired")
    require(has_failed_exit(events, 1), failures, "BPF_MAP_LOOKUP_ELEM failure path missing")
    require(
        has_failed_lookup_key_probe_failure(events),
        failures,
        "BPF_MAP_LOOKUP_ELEM bad-key probe failure missing",
    )
    require(
        has_section(events, 21, "bytes", "in", 1),
        failures,
        "BPF_MAP_LOOKUP_AND_DELETE_ELEM attr snapshot missing",
    )
    require(
        has_output_section(events, 21, "bytes", 117, b"map-value", ret=0),
        failures,
        "BPF_MAP_LOOKUP_AND_DELETE_ELEM value OUT snapshot missing",
    )
    require(
        has_paired_exit(events, 21),
        failures,
        "BPF_MAP_LOOKUP_AND_DELETE_ELEM exit was not paired",
    )
    return failures


def _check_map_batch_outputs(events):
    failures = []
    require(
        has_section(events, 24, "bytes", "in", 1),
        failures,
        "BPF_MAP_LOOKUP_BATCH attr snapshot missing",
    )
    require(
        has_output_section(events, 24, "bytes", 118, ret=0),
        failures,
        "BPF_MAP_LOOKUP_BATCH keys OUT snapshot missing",
    )
    require(
        has_output_section(events, 24, "bytes", 119, b"value-one", ret=0),
        failures,
        "BPF_MAP_LOOKUP_BATCH values OUT snapshot missing",
    )
    require(has_paired_exit(events, 24), failures, "BPF_MAP_LOOKUP_BATCH exit was not paired")
    require(has_failed_exit(events, 24), failures, "BPF_MAP_LOOKUP_BATCH failure path missing")
    require(
        has_section(events, 25, "bytes", "in", 1),
        failures,
        "BPF_MAP_LOOKUP_AND_DELETE_BATCH attr snapshot missing",
    )
    require(
        has_output_section(events, 25, "bytes", 118, ret=0),
        failures,
        "BPF_MAP_LOOKUP_AND_DELETE_BATCH keys OUT snapshot missing",
    )
    require(
        has_output_section(events, 25, "bytes", 119, b"value-one", ret=0),
        failures,
        "BPF_MAP_LOOKUP_AND_DELETE_BATCH values OUT snapshot missing",
    )
    require(
        has_paired_exit(events, 25),
        failures,
        "BPF_MAP_LOOKUP_AND_DELETE_BATCH exit was not paired",
    )
    require(has_map_batch_output_order(events), failures, "BPF map batch output order is unstable")
    require(
        has_hash_batch_cursor_width(events),
        failures,
        "BPF hash batch cursor minimum width missing",
    )
    require(
        has_map_batch_partial_output(events),
        failures,
        "BPF batch terminal ENOENT OUT snapshot missing",
    )
    return failures


def _check_map_inputs(events):
    failures = []
    require(has_map_batch_input_order(events), failures, "BPF_MAP_UPDATE_BATCH input snapshot missing")
    require(has_percpu_map_semantics(events), failures, "BPF per-CPU map value semantics missing")
    require(has_delete_batch_keys(events), failures, "BPF_MAP_DELETE_BATCH keys input snapshot missing")
    require(has_paired_exit(events, 27), failures, "BPF_MAP_DELETE_BATCH exit was not paired")
    require(has_failed_exit(events, 27), failures, "BPF_MAP_DELETE_BATCH failure path missing")
    require(has_delete_elem_key(events), failures, "BPF_MAP_DELETE_ELEM key input snapshot missing")
    require(has_get_next_key(events), failures, "BPF_MAP_GET_NEXT_KEY snapshots missing")
    require(has_update_elem_inputs(events), failures, "BPF_MAP_UPDATE_ELEM input snapshots missing")
    require(
        has_large_update_elem_input(events),
        failures,
        "BPF_MAP_UPDATE_ELEM large value snapshot missing",
    )
    require(has_paired_exit(events, 26), failures, "BPF_MAP_UPDATE_BATCH exit was not paired")
    require(has_failed_exit(events, 26), failures, "BPF_MAP_UPDATE_BATCH failure path missing")
    return failures


def _check_object_queries(events):
    failures = []
    require(
        has_prog_query_output_arrays(events),
        failures,
        "BPF_PROG_QUERY output array snapshots missing",
    )
    require(
        has_prog_attach_detach_lifecycle(events),
        failures,
        "BPF_PROG_ATTACH/DETACH lifecycle events missing",
    )
    require(
        has_task_fd_query_output(events),
        failures,
        "BPF_TASK_FD_QUERY output string snapshot missing",
    )
    require(
        has_get_next_id_output(events),
        failures,
        "BPF *_GET_NEXT_ID exit scalar snapshot missing",
    )
    require(
        failed_task_fd_query_has_no_output(events),
        failures,
        "failed BPF_TASK_FD_QUERY fabricated OUT payload",
    )
    require(
        has_uprobe_multi_input_sections(events),
        failures,
        "BPF_TRACE_UPROBE_MULTI input snapshots missing",
    )
    require(
        has_uprobe_multi_failed_event(events),
        failures,
        "BPF_TRACE_UPROBE_MULTI failure/pairing path missing",
    )
    return failures


def _check_object_info(events):
    failures = []
    require(
        has_section(events, 15, "bytes", "in", 1),
        failures,
        "BPF_OBJ_GET_INFO_BY_FD attr snapshot missing",
    )
    require(
        has_output_section(events, 15, "bytes", 113, b"strace_go_map", ret=0),
        failures,
        "BPF_OBJ_GET_INFO_BY_FD OUT info snapshot missing",
    )
    require(has_paired_exit(events, 15), failures, "BPF_OBJ_GET_INFO_BY_FD exit was not paired")
    require(
        has_failed_exit(events, 15),
        failures,
        "BPF_OBJ_GET_INFO_BY_FD bad-pointer failure path missing",
    )
    return failures


def _check_prog_load(events):
    failures = []
    require(has_section(events, 5, "bytes", "in", 1), failures, "BPF_PROG_LOAD attr snapshot missing")
    require(has_prog_load_fd_array_input(events), failures, "BPF_PROG_LOAD fd_array input snapshot missing")
    require(
        has_failed_prog_load_fd_array_probe(events),
        failures,
        "BPF_PROG_LOAD fd_array probe failure missing",
    )
    require(has_prog_load_func_info_input(events), failures, "BPF_PROG_LOAD func_info input snapshot missing")
    require(
        has_failed_prog_load_func_info_probe(events),
        failures,
        "BPF_PROG_LOAD func_info probe failure missing",
    )
    require(has_prog_load_line_info_input(events), failures, "BPF_PROG_LOAD line_info input snapshot missing")
    require(
        has_failed_prog_load_line_info_probe(events),
        failures,
        "BPF_PROG_LOAD line_info probe failure missing",
    )
    require(has_prog_load_core_relos_input(events), failures, "BPF_PROG_LOAD core_relos input snapshot missing")
    require(
        has_failed_prog_load_core_relos_probe(events),
        failures,
        "BPF_PROG_LOAD core_relos probe failure missing",
    )
    require(
        has_section(events, 5, "bytes", "in", 112, b"\xff"),
        failures,
        "BPF_PROG_LOAD instruction payload missing",
    )
    require(
        has_section(events, 5, "string", "in", 101, b"GPL\x00"),
        failures,
        "BPF_PROG_LOAD license payload missing",
    )
    require(
        has_section(events, 5, "bytes", "in", 102, b"bpf-verifier-log"),
        failures,
        "BPF_PROG_LOAD log payload missing",
    )
    require(has_output_section(events, 5, "bytes", 102), failures, "BPF_PROG_LOAD verifier log OUT snapshot missing")
    require(has_paired_exit(events, 5), failures, "BPF_PROG_LOAD exit was not paired")
    return failures


def _check_btf_and_test_run(events):
    failures = []
    require(has_section(events, 18, "bytes", "in", 1), failures, "BPF_BTF_LOAD attr snapshot missing")
    require(
        has_section(events, 18, "bytes", "in", 106, b"bPf\x00daTum"),
        failures,
        "BPF_BTF_LOAD BTF payload missing",
    )
    require(has_failed_exit(events, 18), failures, "BPF_BTF_LOAD failure path missing")
    require(has_paired_exit(events, 18), failures, "BPF_BTF_LOAD exit was not paired")
    require(
        has_output_section(events, 18, "bytes", 114),
        failures,
        "BPF_BTF_LOAD verifier log OUT snapshot missing",
    )
    require(has_section(events, 10, "bytes", "in", 1), failures, "BPF_PROG_TEST_RUN attr snapshot missing")
    require(has_paired_exit(events, 10), failures, "BPF_PROG_TEST_RUN exit was not paired")
    require(
        any(event.get("ret", 0) == 0 for event in bpf_events(events, "exit", 10)),
        failures,
        "BPF_PROG_TEST_RUN success path missing",
    )
    require(has_failed_exit(events, 10), failures, "BPF_PROG_TEST_RUN failure path missing")
    require(
        has_output_section(events, 10, "bytes", 115, ret=0),
        failures,
        "BPF_PROG_TEST_RUN data_out snapshot missing",
    )
    require(
        has_output_section(events, 10, "bytes", 116, ret=0),
        failures,
        "BPF_PROG_TEST_RUN ctx_out snapshot missing",
    )
    require(has_test_run_output_order(events), failures, "BPF_PROG_TEST_RUN output order is unstable")
    return failures


def _check_invalid_paths(events):
    failures = []
    require(
        any(event.get("ret", 0) < 0 for event in bpf_events(events, "exit", 0)),
        failures,
        "invalid BPF_MAP_CREATE failure path missing",
    )
    require(
        failed_events_have_no_output(events),
        failures,
        "failed BPF event fabricated OUT payload",
    )
    return failures


def check_bpf_semantic(returncode, stdout, events, stats_events):
    failures = _check_runtime(returncode, stdout, events, stats_events)
    failures.extend(_check_map_lookup(events))
    failures.extend(_check_map_batch_outputs(events))
    failures.extend(_check_map_inputs(events))
    failures.extend(_check_object_queries(events))
    failures.extend(_check_object_info(events))
    failures.extend(_check_prog_load(events))
    failures.extend(_check_btf_and_test_run(events))
    failures.extend(_check_invalid_paths(events))
    return failures
