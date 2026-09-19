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


def _events(events, event_type):
	return [
		event
		for event in events
		if event.get("syscall") == "bpf"
		and event.get("event_type") == event_type
		and (event.get("args") or [None])[0] == 38
	]


def _has_attr_snapshot(event):
	return any(
		section.get("kind") == "bytes"
		and section.get("direction") == "in"
		and section.get("arg_index") == 1
		and section.get("probe_ret") == 0
		and section.get("copied_len", 0) > 0
		for section in event.get("payload_sections") or []
	)


def has_struct_ops_contract(events):
	enters = _events(events, "enter")
	exits = _events(events, "exit")
	if len(enters) != 2 or len(exits) != 2:
		return False
	if not all(_has_attr_snapshot(event) for event in enters):
		return False
	if not all(event.get("paired_enter") is True for event in exits):
		return False
	return (
		sum(event.get("ret", -1) == 0 for event in exits) == 1
		and sum(event.get("ret", 0) < 0 for event in exits) == 1
	)


def check_bpf_struct_ops(returncode, stdout, events, stats_events):
	failures = []
	require(returncode == 0, failures, f"BPF struct-ops fixture rc={returncode}")
	require(
		"bpf-struct-ops-fixture-ok" in stdout,
		failures,
		"BPF struct-ops fixture marker missing",
	)
	require(events, failures, "BPF struct-ops fixture produced no syscall events")
	require(
		has_struct_ops_contract(events),
		failures,
		"BPF struct-ops success/failure contract missing",
	)
	require(len(stats_events) == 1, failures, "BPF struct-ops stats event missing")
	if stats_events:
		stats = stats_events[0]
		require(valid_stats_event(stats), failures, "BPF struct-ops stats malformed")
		for key in ZERO_STATS:
			require(stats.get(key) == 0, failures, f"BPF struct-ops {key} is non-zero")
	return failures
