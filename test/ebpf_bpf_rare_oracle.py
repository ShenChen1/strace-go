import base64

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


def _has_failed_exit(events, command):
    return any(
        event.get("paired_enter") is True and event.get("ret", 0) < 0
        for event in _events(events, "exit", command)
    )


def _has_stream_snapshot(events):
    for event in _events(events, "exit", 37):
        if event.get("ret", 0) >= 0:
            continue
        for section in event.get("payload_sections") or []:
            if (
                section.get("kind") == "bytes"
                and section.get("direction") == "out"
                and section.get("arg_index") == 111
                and section.get("probe_ret") == 0
                and section.get("copied_len", 0) > 0
                and b"stream-data" in _section_bytes(section)
            ):
                return True
    return False


def _section_bytes(section):
    try:
        return base64.b64decode(section.get("data_base64") or "")
    except (TypeError, ValueError):
        return b""


def check_bpf_rare(returncode, stdout, events, stats_events):
    failures = []
    require(returncode == 0, failures, f"BPF rare fixture rc={returncode}")
    require("bpf-rare-fixture-ok" in stdout, failures, "BPF rare fixture marker missing")
    require(events, failures, "BPF rare fixture produced no syscall events")
    require(len(stats_events) == 1, failures, "BPF rare stats event missing")
    if stats_events:
        stats = stats_events[0]
        require(valid_stats_event(stats), failures, "BPF rare stats malformed")
        for key in ZERO_STATS:
            require(stats.get(key) == 0, failures, f"BPF rare {key} is non-zero")

    for command, name in (
        (33, "BPF_ITER_CREATE"),
        (36, "BPF_TOKEN_CREATE"),
        (37, "BPF_PROG_STREAM_READ_BY_FD"),
        (38, "BPF_PROG_ASSOC_STRUCT_OPS"),
    ):
        require(_has_attr(events, command), failures, f"{name} attr snapshot missing")
        require(_has_failed_exit(events, command), failures, f"{name} failure missing")
    require(_has_stream_snapshot(events), failures, "BPF stream OUT snapshot missing")
    return failures
