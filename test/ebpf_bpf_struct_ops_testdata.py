import base64


def _attr_section(data):
	raw = bytes(data)
	return {
		"kind": "bytes",
		"direction": "in",
		"arg_index": 1,
		"user_len": len(raw),
		"copied_len": len(raw),
		"probe_ret": 0,
		"data_base64": base64.b64encode(raw).decode(),
	}


def struct_ops_events():
	attr = bytes(range(16))
	return [
		{
			"syscall": "bpf",
			"event_type": "enter",
			"args": [38, 0x1000, 0, 0, 0, 0],
			"payload_sections": [_attr_section(attr)],
		},
		{
			"syscall": "bpf",
			"event_type": "exit",
			"args": [38, 0x1000, 0, 0, 0, 0],
			"ret": 0,
			"paired_enter": True,
			"payload_sections": [_attr_section(attr)],
		},
		{
			"syscall": "bpf",
			"event_type": "enter",
			"args": [38, 0x1000, 0, 0, 0, 0],
			"payload_sections": [_attr_section(attr)],
		},
		{
			"syscall": "bpf",
			"event_type": "exit",
			"args": [38, 0x1000, 0, 0, 0, 0],
			"ret": -9,
			"paired_enter": True,
			"payload_sections": [_attr_section(attr)],
		},
	]
