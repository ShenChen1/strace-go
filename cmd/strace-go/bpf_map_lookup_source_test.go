package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFBpfMapLookupCapturesKeyAtEnter(t *testing.T) {
	root := repoRootForTest(t)
	nested := readTextFile(t, filepath.Join(root, "bpf/syscall_bpf_nested_direct_event_v2.h"))
	provider := readTextFile(t, filepath.Join(root, "bpf/syscall_bpf_map_lookup_direct_event_v2.h"))
	keyProvider := readTextFile(t, filepath.Join(root, "bpf/syscall_bpf_map_key_direct_event_v2.h"))
	common := readTextFile(t, filepath.Join(root, "bpf/syscall_bpf_map_common_direct_event_v2.h"))
	capture := readTextFile(t, filepath.Join(root, "bpf/syscall_bpf_nested_capture_direct_event_v2.h"))
	for _, snippet := range []string{
		"BPF_DIRECT_MAP_LOOKUP_ELEM 1",
		"BPF_DIRECT_MAP_LOOKUP_AND_DELETE_ELEM 21",
		"BPF_DIRECT_MAP_LOOKUP_KEY_IN_ARG 139",
		"read_bpf_map_lookup_key_input_request_direct(",
		"capture_bpf_map_lookup_key_input_tlv_direct(",
		"BPF_DIRECT_MAP_FD_OFF 0",
		"BPF_DIRECT_MAP_KEY_OFF 8",
		"BPF_CORE_READ(map, key_size)",
		"capture_bpf_bytes_tlv_direct(",
	} {
		if !strings.Contains(nested+provider+keyProvider+common+capture, snippet) {
			t.Fatalf("BPF map lookup key provider missing %q", snippet)
		}
	}
	if !strings.Contains(nested, "cmd == BPF_DIRECT_MAP_LOOKUP_ELEM") {
		t.Fatal("nested BPF dispatcher must route BPF_MAP_LOOKUP_ELEM")
	}
	if !strings.Contains(nested, "cmd == BPF_DIRECT_MAP_LOOKUP_AND_DELETE_ELEM") {
		t.Fatal("nested BPF dispatcher must route BPF_MAP_LOOKUP_AND_DELETE_ELEM")
	}
}
