package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFBpfMapDeleteBatchUsesKeysOnlyEnterSnapshot(t *testing.T) {
	root := repoRootForTest(t)
	nested := readTextFile(t, filepath.Join(root, "bpf/syscall_bpf_nested_direct_event_v2.h"))
	common := readTextFile(t, filepath.Join(root, "bpf/syscall_bpf_map_common_direct_event_v2.h"))
	capture := readTextFile(t, filepath.Join(root, "bpf/syscall_bpf_nested_capture_direct_event_v2.h"))
	keyProvider := readTextFile(t, filepath.Join(root, "bpf/syscall_bpf_map_key_direct_event_v2.h"))
	deleteProvider := readTextFile(t, filepath.Join(root, "bpf/syscall_bpf_delete_direct_event_v2.h"))

	for _, snippet := range []string{
		"BPF_DIRECT_MAP_DELETE_BATCH 27",
		"BPF_DIRECT_MAP_BATCH_KEYS_IN_ARG 121",
		"read_bpf_map_delete_batch_input_request_direct(",
		"capture_bpf_map_delete_batch_input_tlv_direct(",
		"BPF_DIRECT_MAP_BATCH_KEYS_OFF 16",
		"BPF_DIRECT_MAP_BATCH_COUNT_OFF 32",
		"BPF_DIRECT_MAP_BATCH_FD_OFF 36",
		"BPF_CORE_READ(map, key_size)",
		"bpf_map_batch_buffer_len_direct(",
		"capture_bpf_bytes_tlv_direct(",
		".event_flags = event_flags",
		"BPF_DIRECT_MAP_DELETE_BATCH",
	} {
		if !strings.Contains(nested+common+capture+keyProvider+deleteProvider, snippet) {
			t.Fatalf("BPF delete batch provider missing %q", snippet)
		}
	}
	if strings.Contains(nested, "BPF_DIRECT_MAP_DELETE_BATCH_IN_VALUES") {
		t.Fatal("delete batch provider must not introduce a values payload")
	}
}

func TestBPFBpfMapDeleteElemUsesKeyOnlyEnterSnapshot(t *testing.T) {
	root := repoRootForTest(t)
	nested := readTextFile(t, filepath.Join(root, "bpf/syscall_bpf_nested_direct_event_v2.h"))
	deleteProvider := readTextFile(t, filepath.Join(root, "bpf/syscall_bpf_delete_direct_event_v2.h"))
	keyProvider := readTextFile(t, filepath.Join(root, "bpf/syscall_bpf_map_key_direct_event_v2.h"))
	common := readTextFile(t, filepath.Join(root, "bpf/syscall_bpf_map_common_direct_event_v2.h"))
	capture := readTextFile(t, filepath.Join(root, "bpf/syscall_bpf_nested_capture_direct_event_v2.h"))
	provider := nested + deleteProvider + keyProvider + common + capture
	for _, snippet := range []string{
		"BPF_DIRECT_MAP_DELETE_ELEM 3",
		"BPF_DIRECT_MAP_DELETE_KEY_IN_ARG 123",
		"read_bpf_map_delete_elem_input_request_direct(",
		"capture_bpf_map_delete_elem_input_tlv_direct(",
		"BPF_DIRECT_MAP_FD_OFF 0",
		"BPF_DIRECT_MAP_KEY_OFF 8",
		"BPF_CORE_READ(map, key_size)",
		"capture_bpf_bytes_tlv_direct(",
		"PAYLOAD_TLV_KIND_BYTES",
	} {
		if !strings.Contains(provider, snippet) {
			t.Fatalf("BPF delete elem provider missing %q", snippet)
		}
	}
}
