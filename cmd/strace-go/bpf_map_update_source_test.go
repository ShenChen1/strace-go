package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFBpfMapUpdateElemUsesDedicatedInputProvider(t *testing.T) {
	root := repoRootForTest(t)
	nested := readTextFile(t, filepath.Join(root, "bpf/syscall_bpf_nested_direct_event_v2.h"))
	provider := readTextFile(t, filepath.Join(root, "bpf/syscall_bpf_map_input_direct_event_v2.h"))
	common := readTextFile(t, filepath.Join(root, "bpf/syscall_bpf_map_common_direct_event_v2.h"))
	capture := readTextFile(t, filepath.Join(root, "bpf/syscall_bpf_nested_capture_direct_event_v2.h"))

	for _, snippet := range []string{
		"BPF_DIRECT_MAP_UPDATE_ELEM 2",
		"BPF_DIRECT_MAP_UPDATE_KEY_IN_ARG 126",
		"BPF_DIRECT_MAP_UPDATE_VALUE_IN_ARG 127",
		"BPF_DIRECT_MAP_KEY_OFF 8",
		"BPF_DIRECT_MAP_VALUE_OFF 16",
		"BPF_DIRECT_MAP_FD_OFF 0",
		"read_bpf_map_update_elem_input_requests_direct(",
		"capture_bpf_map_update_elem_inputs_tlv_direct(",
		"BPF_CORE_READ(map, key_size)",
		"BPF_CORE_READ(map, value_size)",
		"bpf_map_effective_value_size_direct(",
		"capture_bpf_bytes_tlv_direct(",
		"PAYLOAD_TLV_KIND_BYTES",
	} {
		if !strings.Contains(nested+provider+common+capture, snippet) {
			t.Fatalf("BPF map update provider missing %q", snippet)
		}
	}
	if !strings.Contains(nested, "cmd == BPF_DIRECT_MAP_UPDATE_ELEM") {
		t.Fatal("nested BPF dispatcher must route BPF_MAP_UPDATE_ELEM")
	}
	if strings.Contains(nested, "struct bpf_map_batch_input_requests") {
		t.Fatal("nested dispatcher must not own map input request layout")
	}
}
