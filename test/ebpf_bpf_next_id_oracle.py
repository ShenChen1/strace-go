#!/usr/bin/env python3
import base64


def _bytes(section):
    try:
        return base64.b64decode(section.get("data_base64") or "")
    except (TypeError, ValueError):
        return b""


def _u32(data):
    if len(data) < 4:
        return None
    return int.from_bytes(data[:4], "little")


def has_get_next_id_output(events):
    commands = {11, 12, 23, 31}
    for event in events:
        if (
            event.get("syscall") != "bpf"
            or event.get("event_type") != "exit"
            or (event.get("args") or [None])[0] not in commands
            or event.get("ret") != 0
            or event.get("paired_enter") is not True
        ):
            continue
        for section in event.get("payload_sections") or []:
            data = _bytes(section)
            attr_ptr = (event.get("args") or [None, None])[1]
            if (
                section.get("kind") == "bytes"
                and section.get("direction") == "out"
                and section.get("arg_index") == 140
                and section.get("probe_ret") == 0
                and section.get("user_len") == 4
                and section.get("copied_len") == 4
                and _u32(data) not in (None, 0)
                and (
                    section.get("user_ptr") is None
                    or attr_ptr is None
                    or section.get("user_ptr") == attr_ptr + 4
                )
            ):
                for enter in events:
                    if (
                        enter.get("syscall") == "bpf"
                        and enter.get("event_type") == "enter"
                        and enter.get("args") == event.get("args")
                    ):
                        attr_sections = [
                            candidate
                            for candidate in enter.get("payload_sections") or []
                            if candidate.get("arg_index") == 1
                            and candidate.get("direction") == "in"
                        ]
                        if attr_sections and _u32(_bytes(attr_sections[0])[4:8]) != _u32(data):
                            return True
    return False
