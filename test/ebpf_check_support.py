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
    ) and isinstance(event.get("service_enabled"), bool) and all(
        isinstance(event.get(key), int) and event.get(key) >= 0
        for key in (
            "service_sample_rate",
            "bytes_read",
            "max_record_bytes",
            "read_time_ns",
            "decode_time_ns",
            "sink_time_ns",
            "min_remaining_bytes",
            "service_time_ns",
            "service_records",
            "max_service_time_ns",
            "records_read",
            "records_decoded",
            "records_invalid",
            "records_routed",
            "max_remaining_bytes",
        )
    )


def service_measurement_failures(stats, label):
    failures = []
    if stats.get("service_enabled") is not True:
        failures.append(f"{label} service measurement is disabled")
        return failures
    service_records = stats.get("service_records", 0)
    records_read = stats.get("records_read", 0)
    sample_rate = stats.get("service_sample_rate", 0)
    if sample_rate < 1:
        failures.append(f"{label} service_sample_rate={sample_rate}")
    if service_records > records_read:
        failures.append(
            f"{label} service_records={service_records} exceeds records_read={records_read}"
        )
    if records_read > 0 and service_records == 0:
        failures.append(f"{label} service_records is zero")
    if records_read > 0 and stats.get("service_time_ns", 0) <= 0:
        failures.append(f"{label} service_time_ns is zero")
    if records_read > 0 and stats.get("max_service_time_ns", 0) <= 0:
        failures.append(f"{label} max_service_time_ns is zero")
    stage_time = stats.get("decode_time_ns", 0) + stats.get("sink_time_ns", 0)
    if stage_time > stats.get("service_time_ns", 0):
        failures.append(f"{label} stage times exceed service_time_ns")
    if stats.get("min_remaining_bytes", 0) > stats.get("max_remaining_bytes", 0):
        failures.append(f"{label} remaining-bytes watermarks are inverted")
    return failures
