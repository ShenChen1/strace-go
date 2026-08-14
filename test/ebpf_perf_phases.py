REQUIRED_CLEANUP_PHASES = (
    "cleanup_output",
    "cleanup_target_handoff",
    "cleanup_target_bootstrap",
    "cleanup_ringbuf_reader",
    "cleanup_bpf_runtime",
)


def validate_cleanup_phases(phases, capture_name):
    failures = []
    cleanup_start = phases["cleanup_start"].get("time_ns", 0)
    cleanup_times = []
    for phase in REQUIRED_CLEANUP_PHASES:
        event = phases.get(phase)
        if event is None:
            failures.append(f"{capture_name} missing cleanup phase: {phase}")
            continue
        start_time_ns = event.get("start_time_ns", 0)
        end_time_ns = event.get("time_ns", 0)
        if start_time_ns <= 0 or end_time_ns < start_time_ns:
            failures.append(f"{capture_name} {phase} timing is invalid")
        if start_time_ns < cleanup_start:
            failures.append(f"{capture_name} {phase} starts before cleanup_start")
        cleanup_times.append((start_time_ns, end_time_ns))
    for previous, current in zip(cleanup_times, cleanup_times[1:]):
        if current[0] < previous[1]:
            failures.append(f"{capture_name} cleanup steps overlap")
    return failures


def cleanup_phase_durations(phases):
    durations = {
        f"{phase}_sec": (
            phases[phase]["time_ns"] - phases[phase]["start_time_ns"]
        )
        / 1_000_000_000
        for phase in REQUIRED_CLEANUP_PHASES
    }
    durations["cleanup_owner_sec"] = sum(durations.values())
    return durations
