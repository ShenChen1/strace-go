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


def _section_bytes(section):
    try:
        return base64.b64decode(section.get("data_base64") or "")
    except (TypeError, ValueError):
        return b""


def _events(events, event_type, command):
    return [
        event
        for event in events
        if event.get("syscall") == "bpf"
        and event.get("event_type") == event_type
        and (event.get("args") or [None])[0] == command
    ]


def _has_attr_snapshot(events, command):
    return any(
        section.get("kind") == "bytes"
        and section.get("direction") == "in"
        and section.get("arg_index") == 1
        and section.get("probe_ret") == 0
        and section.get("copied_len", 0) > 0
        for event in _events(events, "enter", command)
        for section in event.get("payload_sections") or []
    )


def _has_string_snapshot(events, command, arg_index, marker):
    return any(
        section.get("kind") == "string"
        and section.get("direction") == "in"
        and section.get("arg_index") == arg_index
        and section.get("probe_ret") == 0
        and section.get("copied_len", 0) > 0
        and marker in _section_bytes(section)
        for event in _events(events, "enter", command)
        for section in event.get("payload_sections") or []
    )


def _has_paired_exit(events, command, success=None):
    for event in _events(events, "exit", command):
        if event.get("paired_enter") is not True:
            continue
        if success is None or (event.get("ret", -1) >= 0) == success:
            return True
    return False


def check_bpf_lifecycle(returncode, stdout, events, stats_events):
    failures = []
    require(returncode == 0, failures, f"BPF lifecycle fixture rc={returncode}")
    require(
        "bpf-lifecycle-fixture-ok" in stdout,
        failures,
        "BPF lifecycle fixture marker missing",
    )
    require(events, failures, "BPF lifecycle fixture produced no syscall events")
    require(len(stats_events) == 1, failures, "BPF lifecycle stats event missing")
    if stats_events:
        stats = stats_events[0]
        require(valid_stats_event(stats), failures, "BPF lifecycle stats malformed")
        for key in ZERO_STATS:
            require(stats.get(key) == 0, failures, f"BPF lifecycle {key} is non-zero")

    for command, name in ((13, "BPF_PROG_GET_FD_BY_ID"), (14, "BPF_MAP_GET_FD_BY_ID")):
        require(_has_attr_snapshot(events, command), failures, f"{name} attr snapshot missing")
        require(_has_paired_exit(events, command, True), failures, f"{name} success missing")
        require(_has_paired_exit(events, command, False), failures, f"{name} failure missing")

    for command, name in ((6, "BPF_OBJ_PIN"), (7, "BPF_OBJ_GET")):
        require(_has_attr_snapshot(events, command), failures, f"{name} attr snapshot missing")
        require(
            _has_string_snapshot(events, command, 104, b"strace-go-bpf-no-object"),
            failures,
            f"{name} pathname snapshot missing",
        )
        require(_has_paired_exit(events, command, False), failures, f"{name} failure missing")

    require(_has_attr_snapshot(events, 22), failures, "BPF_MAP_FREEZE attr snapshot missing")
    require(_has_paired_exit(events, 22, True), failures, "BPF_MAP_FREEZE success missing")
    require(_has_paired_exit(events, 2, False), failures, "frozen map update failure missing")
    require(_has_attr_snapshot(events, 35), failures, "BPF_PROG_BIND_MAP attr snapshot missing")
    require(_has_paired_exit(events, 35, True), failures, "BPF_PROG_BIND_MAP success missing")
    require(_has_attr_snapshot(events, 28), failures, "BPF_LINK_CREATE attr snapshot missing")
    require(_has_paired_exit(events, 28, True), failures, "BPF_LINK_CREATE success missing")
    require(_has_attr_snapshot(events, 29), failures, "BPF_LINK_UPDATE attr snapshot missing")
    require(_has_paired_exit(events, 29, True), failures, "BPF_LINK_UPDATE success missing")
    require(_has_paired_exit(events, 29, False), failures, "BPF_LINK_UPDATE failure missing")
    require(_has_attr_snapshot(events, 34), failures, "BPF_LINK_DETACH attr snapshot missing")
    require(_has_paired_exit(events, 34, True), failures, "BPF_LINK_DETACH success missing")
    require(_has_paired_exit(events, 34, False), failures, "BPF_LINK_DETACH failure missing")
    require(_has_attr_snapshot(events, 30), failures, "BPF_LINK_GET_FD_BY_ID attr snapshot missing")
    require(_has_paired_exit(events, 30, True), failures, "BPF_LINK_GET_FD_BY_ID success missing")
    require(_has_paired_exit(events, 30, False), failures, "BPF_LINK_GET_FD_BY_ID failure missing")
    require(_has_attr_snapshot(events, 31), failures, "BPF_LINK_GET_NEXT_ID attr snapshot missing")
    require(_has_paired_exit(events, 31, True), failures, "BPF_LINK_GET_NEXT_ID success missing")
    for command, name in ((11, "BPF_PROG_GET_NEXT_ID"), (23, "BPF_BTF_GET_NEXT_ID")):
        require(_has_attr_snapshot(events, command), failures, f"{name} attr snapshot missing")
        require(_has_paired_exit(events, command, True), failures, f"{name} success missing")
    require(_has_attr_snapshot(events, 19), failures, "BPF_BTF_GET_FD_BY_ID attr snapshot missing")
    require(_has_paired_exit(events, 19, True), failures, "BPF_BTF_GET_FD_BY_ID success missing")
    require(_has_paired_exit(events, 19, False), failures, "BPF_BTF_GET_FD_BY_ID failure missing")
    require(_has_attr_snapshot(events, 17), failures, "BPF_RAW_TRACEPOINT_OPEN attr snapshot missing")
    require(
        _has_string_snapshot(events, 17, 105, b"sys_enter"),
        failures,
        "BPF_RAW_TRACEPOINT_OPEN name snapshot missing",
    )
    require(_has_paired_exit(events, 17, True), failures, "BPF_RAW_TRACEPOINT_OPEN success missing")
    require(_has_paired_exit(events, 17, False), failures, "BPF_RAW_TRACEPOINT_OPEN failure missing")
    require(_has_attr_snapshot(events, 32), failures, "BPF_ENABLE_STATS attr snapshot missing")
    require(_has_paired_exit(events, 32), failures, "BPF_ENABLE_STATS exit missing")
    return failures
