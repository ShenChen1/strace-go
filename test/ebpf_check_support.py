def require(condition, failures, message):
    if not condition:
        failures.append(message)


def valid_stats_event(event):
    keys = (
        "ringbuf_reserve_fail",
        "ringbuf_copy_fail",
        "payload_truncated_events",
        "pending_update_fail",
        "orphan_exit",
        "pending_mismatch",
        "lifecycle_map_update_fail",
        "pending_stale",
    )
    return event.get("available") is True and all(
        isinstance(event.get(key), int) and event.get(key) >= 0 for key in keys
    )
