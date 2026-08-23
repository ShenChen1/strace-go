import base64
import struct


def _bytes(section):
    try:
        return base64.b64decode(section.get("data_base64") or "")
    except (TypeError, ValueError):
        return b""


def _u64(data, offset):
    if len(data) < offset + 8:
        return 0
    return struct.unpack_from("<Q", data, offset)[0]


def _u32(data, offset):
    if len(data) < offset + 4:
        return 0
    return struct.unpack_from("<I", data, offset)[0]


def _prog_load_observations(events):
    return [
        event
        for event in events
        if event.get("syscall") == "bpf"
        and (event.get("args") or [None])[0] == 5
        and (
            event.get("event_type") == "enter"
            or (event.get("event_type") == "exit" and event.get("paired_enter") is True)
        )
    ]


def has_prog_load_fd_array_input(events):
    for event in _prog_load_observations(events):
        attr = next(
            (
                section
                for section in event.get("payload_sections") or []
                if section.get("arg_index") == 1
                and section.get("direction") == "in"
                and section.get("probe_ret") == 0
            ),
            None,
        )
        fd_array = next(
            (
                section
                for section in event.get("payload_sections") or []
                if section.get("arg_index") == 141
                and section.get("kind") == "bytes"
                and section.get("direction") == "in"
                and section.get("probe_ret") == 0
            ),
            None,
        )
        if attr is None or fd_array is None:
            continue
        attr_data = _bytes(attr)
        data = _bytes(fd_array)
        count = _u32(attr_data, 148)
        ptr = _u64(attr_data, 120)
        expected_len = count * 4
        if (
            ptr == fd_array.get("user_ptr")
            and count == 2
            and expected_len == fd_array.get("user_len")
            and fd_array.get("copied_len") == expected_len
            and struct.unpack("<2I", data) == (17, 23)
        ):
            return True
    return False


def has_failed_prog_load_fd_array_probe(events):
    return any(
        any(
            section.get("arg_index") == 141
            and section.get("direction") == "in"
            and section.get("probe_ret", 0) < 0
            and section.get("copied_len") == 0
            for section in event.get("payload_sections") or []
        )
        for event in _prog_load_observations(events)
    )


def has_prog_load_func_info_input(events):
    for event in _prog_load_observations(events):
        attr = next(
            (
                section
                for section in event.get("payload_sections") or []
                if section.get("arg_index") == 1
                and section.get("direction") == "in"
                and section.get("probe_ret") == 0
            ),
            None,
        )
        func_info = next(
            (
                section
                for section in event.get("payload_sections") or []
                if section.get("arg_index") == 142
                and section.get("kind") == "bytes"
                and section.get("direction") == "in"
                and section.get("probe_ret") == 0
            ),
            None,
        )
        if attr is None or func_info is None:
            continue
        attr_data = _bytes(attr)
        data = _bytes(func_info)
        rec_size = _u32(attr_data, 76)
        ptr = _u64(attr_data, 80)
        count = _u32(attr_data, 88)
        expected_len = rec_size * count
        if (
            ptr == func_info.get("user_ptr")
            and rec_size == 8
            and count == 2
            and expected_len == func_info.get("user_len")
            and func_info.get("copied_len") == expected_len
            and struct.unpack("<4I", data) == (0, 0x1234, 8, 0x5678)
        ):
            return True
    return False


def has_failed_prog_load_func_info_probe(events):
    return any(
        any(
            section.get("arg_index") == 142
            and section.get("direction") == "in"
            and section.get("probe_ret", 0) < 0
            and section.get("copied_len") == 0
            for section in event.get("payload_sections") or []
        )
        for event in _prog_load_observations(events)
    )


def _has_prog_load_record_input(events, spec):
    arg_index = spec["arg_index"]
    attr_offset = spec["attr_offset"]
    rec_size_offset = spec["rec_size_offset"]
    count_offset = spec["count_offset"]
    rec_size = spec["rec_size"]
    records = spec["records"]
    for event in _prog_load_observations(events):
        attr = next(
            (
                section
                for section in event.get("payload_sections") or []
                if section.get("arg_index") == 1
                and section.get("direction") == "in"
                and section.get("probe_ret") == 0
            ),
            None,
        )
        payload = next(
            (
                section
                for section in event.get("payload_sections") or []
                if section.get("arg_index") == arg_index
                and section.get("kind") == "bytes"
                and section.get("direction") == "in"
                and section.get("probe_ret") == 0
            ),
            None,
        )
        if attr is None or payload is None:
            continue
        attr_data = _bytes(attr)
        data = _bytes(payload)
        actual_rec_size = _u32(attr_data, rec_size_offset)
        count = _u32(attr_data, count_offset)
        if (
            _u64(attr_data, attr_offset) == payload.get("user_ptr")
            and actual_rec_size == rec_size
            and count == len(records) // rec_size
            and payload.get("user_len") == actual_rec_size * count
            and payload.get("copied_len") == actual_rec_size * count
            and data == records
        ):
            return True
    return False


def has_prog_load_line_info_input(events):
    return _has_prog_load_record_input(events, {
        "arg_index": 143,
        "attr_offset": 96,
        "rec_size_offset": 92,
        "count_offset": 104,
        "pointer": 0x8000,
        "rec_size": 16,
        "records": struct.pack(
            "<8I", 0, 4, 8, 0x10001, 16, 20, 24, 0x20002
        ),
    })


def has_failed_prog_load_line_info_probe(events):
    return any(
        any(
            section.get("arg_index") == 143
            and section.get("direction") == "in"
            and section.get("probe_ret", 0) < 0
            and section.get("copied_len") == 0
            for section in event.get("payload_sections") or []
        )
        for event in _prog_load_observations(events)
    )


def has_prog_load_core_relos_input(events):
    return _has_prog_load_record_input(events, {
        "arg_index": 144,
        "attr_offset": 128,
        "rec_size_offset": 136,
        "count_offset": 116,
        "pointer": 0x9000,
        "rec_size": 16,
        "records": struct.pack(
            "<8I", 0, 0x1234, 4, 1, 16, 0x5678, 8, 2
        ),
    })


def has_failed_prog_load_core_relos_probe(events):
    return any(
        any(
            section.get("arg_index") == 144
            and section.get("direction") == "in"
            and section.get("probe_ret", 0) < 0
            and section.get("copied_len") == 0
            for section in event.get("payload_sections") or []
        )
        for event in _prog_load_observations(events)
    )
