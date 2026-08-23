package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFBpfBytesRequestsDeclareStorageBucket(t *testing.T) {
	root := repoRootForTest(t)
	capture := readTextFile(t, filepath.Join(root, "bpf/syscall_bpf_nested_capture_direct_event_v2.h"))
	nested := readTextFile(t, filepath.Join(root, "bpf/syscall_bpf_nested_direct_event_v2.h"))
	mapInput := readTextFile(t, filepath.Join(root, "bpf/syscall_bpf_map_input_direct_event_v2.h"))
	exit := readTextFile(t, filepath.Join(root, "bpf/syscall_bpf_exit_direct_event_v2.h"))
	mapExit := readTextFile(t, filepath.Join(root, "bpf/syscall_bpf_map_exit_direct_event_v2.h"))

	if !strings.Contains(capture, "u32 storage_len;") {
		t.Fatal("nested bytes request must declare storage_len")
	}
	if !strings.Contains(capture, "storage_len < max_len") {
		t.Fatal("nested bytes capture must reject an undersized storage bucket")
	}
	for _, snippet := range []string{
		"bpf_nested_bytes_storage_direct(",
		"storage_len == BPF_DIRECT_BYTES_BUCKET_20",
		"storage_len == BPF_DIRECT_BYTES_BUCKET_512",
		"bpf_dynptr_data(ptr, data_offset, BPF_DIRECT_BYTES_BUCKET_512)",
	} {
		if !strings.Contains(capture, snippet) {
			t.Fatalf("nested bytes capture missing storage bucket contract %q", snippet)
		}
	}
	if !strings.Contains(exit, "u32 storage_len;") {
		t.Fatal("exit bytes request must declare storage_len")
	}
	if !strings.Contains(exit, "request->storage_len < max_len") {
		t.Fatal("exit bytes capture must reject an undersized storage bucket")
	}
	for _, source := range []string{nested, mapInput, mapExit, exit} {
		if !strings.Contains(source, ".storage_len =") &&
			!strings.Contains(source, "->storage_len =") {
			t.Fatal("every BPF bytes provider must initialize storage_len")
		}
	}
	if !strings.Contains(mapInput, "->storage_len = BPF_DIRECT_BYTES_BUCKET_512") {
		t.Fatal("map input provider must use the 512-byte map bucket")
	}
}
