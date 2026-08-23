from ebpf_check_support import require, valid_stats_event


ZERO_STATS = (
    "ringbuf_reserve_fail",
    "ringbuf_copy_fail",
    "pending_update_fail",
    "orphan_exit",
    "pending_mismatch",
    "lifecycle_map_update_fail",
    "pending_stale",
)


def _events(events, event_type, command):
    return [
        event
        for event in events
        if event.get("syscall") == "bpf"
        and event.get("event_type") == event_type
        and (event.get("args") or [None])[0] == command
    ]


def _has_attr(events, command):
    return any(
        section.get("kind") == "bytes"
        and section.get("direction") == "in"
        and section.get("arg_index") == 1
        and section.get("probe_ret") == 0
        and section.get("copied_len", 0) > 0
        for event in _events(events, "enter", command)
        for section in event.get("payload_sections") or []
    )


def _has_exit(events, command, want_success):
    return any(
        event.get("paired_enter") is True
        and ((event.get("ret", -1) >= 0) == want_success)
        for event in _events(events, "exit", command)
    )


def check_bpf_iter(returncode, stdout, events, stats_events):
    failures = []
    require(returncode == 0, failures, f"BPF iterator fixture rc={returncode}")
    require("bpf-iter-fixture-ok" in stdout, failures, "BPF iterator fixture marker missing")
    require(events, failures, "BPF iterator fixture produced no syscall events")
    require(len(stats_events) == 1, failures, "BPF iterator stats event missing")
    if stats_events:
        stats = stats_events[0]
        require(valid_stats_event(stats), failures, "BPF iterator stats malformed")
        for key in ZERO_STATS:
            require(stats.get(key) == 0, failures, f"BPF iterator {key} is non-zero")

    for command, name in ((5, "BPF_PROG_LOAD"), (28, "BPF_LINK_CREATE")):
        require(_has_attr(events, command), failures, f"{name} attr snapshot missing")
        require(_has_exit(events, command, True), failures, f"{name} success missing")
    require(_has_attr(events, 33), failures, "BPF_ITER_CREATE attr snapshot missing")
    require(_has_exit(events, 33, True), failures, "BPF_ITER_CREATE success missing")
    require(_has_exit(events, 33, False), failures, "BPF_ITER_CREATE failure missing")
    return failures
