#!/usr/bin/env python3
from dataclasses import dataclass, field


RUNTIME_DIAGNOSTIC_FIELDS = (
    "ringbuf_reserve_fail",
    "ringbuf_copy_fail",
    "pending_update_fail",
    "orphan_exit",
    "pending_mismatch",
    "lifecycle_map_update_fail",
    "pending_stale",
)
REQUIRED_PERF_PHASES = (
    "trace_start",
    "trace_end",
    "finalize_start",
    "cleanup_start",
)
REQUIRED_BPF_SETUP_PHASES = (
    "bpf_memlock",
    "bpf_spec",
    "bpf_route_plan",
    "bpf_object_prepare",
    "bpf_core_collection_load",
    "bpf_handler_collections_load",
    "bpf_enter_generic_collection_load",
    "bpf_enter_payload_collection_load",
    "bpf_enter_path_collection_load",
    "bpf_enter_memory_collection_load",
    "bpf_enter_control_collection_load",
    "bpf_enter_structured_collection_load",
    "bpf_exit_collection_load",
    "bpf_recvmsg_collection_load",
    "bpf_resource_bind",
    "bpf_route_maps",
    "bpf_prog_arrays",
    "bpf_tracepoints",
    "bpf_recvmsg_kretprobe",
)


@dataclass(frozen=True)
class PerfWorkloadSpec:
    name: str
    minimum_exit_counts: tuple
    fixture_args: tuple = ()
    trace: str = ""
    event_format: str = "json"
    payload_requirements: tuple = ()
    max_bytes_read: int = 0
    minimum_records_read: int = 0
    minimum_producer_attempts_lower_bound: int = 0
    lifecycle_actions: tuple = ()
    lifecycle_minimum_counts: tuple = ()
    lifecycle_stat_minimums: tuple = ()
    lifecycle_stat_zeroes: tuple = ()
    require_non_leader_tid: bool = False


@dataclass
class PerfCapture:
    name: str
    result: object
    elapsed: float
    events: list
    lifecycle_events: list
    stats_events: list
    ready_events: list = field(default_factory=list)
    phase_events: list = field(default_factory=list)

    @property
    def exit_events(self):
        return [event for event in self.events if event.get("event_type") == "exit"]


PERF_WORKLOADS = (
    PerfWorkloadSpec(
        name="scalar",
        fixture_args=("scalar", "1500"),
        trace="getpid,clock_gettime",
        minimum_exit_counts=(("getpid", 1500), ("clock_gettime", 1500)),
    ),
    PerfWorkloadSpec(
        name="io",
        fixture_args=("io", "1000"),
        trace="read,write",
        minimum_exit_counts=(("read", 1000), ("write", 1000)),
        payload_requirements=(("read", "out", 1), ("write", "in", 1)),
        max_bytes_read=900000,
    ),
    PerfWorkloadSpec(
        name="io-long-reader",
        minimum_exit_counts=(),
        fixture_args=("io", "100000"),
        trace="read,write",
        event_format="reader",
        max_bytes_read=65000000,
        minimum_records_read=400000,
        minimum_producer_attempts_lower_bound=400000,
    ),
    PerfWorkloadSpec(
        name="lifecycle",
        fixture_args=("lifecycle", "8"),
        trace="fork,vfork,clone,clone3,execve",
        minimum_exit_counts=(("execve", 1),),
        lifecycle_actions=("fork", "exec", "exit"),
    ),
    PerfWorkloadSpec(
        name="lifecycle-storm",
        minimum_exit_counts=(),
        fixture_args=("lifecycle", "1000"),
        trace="fork,vfork,clone,clone3,execve,exit,exit_group",
        lifecycle_minimum_counts=(
            ("fork", 1000),
            ("exec", 1001),
            ("exit", 1000),
        ),
        lifecycle_stat_minimums=(
            ("lifecycle_fork_seen", 1000),
            ("lifecycle_fork_parent_tracked", 1000),
            ("lifecycle_fork_child_filter_installed", 1000),
        ),
        lifecycle_stat_zeroes=("lifecycle_fork_child_filter_failed",),
    ),
    PerfWorkloadSpec(
        name="threads",
        fixture_args=("threads", "4", "400"),
        trace="getpid,clone,clone3",
        minimum_exit_counts=(("getpid", 1000),),
        require_non_leader_tid=True,
    ),
)
