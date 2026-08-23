package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFProgLoadFDArrayUsesBoundedEnterSnapshot(t *testing.T) {
	root := repoRootForTest(t)
	nested := readTextFile(t, filepath.Join(root, "bpf/syscall_bpf_nested_direct_event_v2.h"))
	progLoad := readTextFile(t, filepath.Join(root, "bpf/syscall_bpf_prog_load_direct_event_v2.h"))
	for _, snippet := range []string{
		"BPF_DIRECT_PROG_LOAD_FD_ARRAY_ARG 141",
		"BPF_DIRECT_PROG_LOAD_FD_ARRAY_OFF 120",
		"BPF_DIRECT_PROG_LOAD_FD_ARRAY_CNT_OFF 148",
		"BPF_DIRECT_PROG_LOAD_FD_ARRAY_MAX 512",
	} {
		if !strings.Contains(nested, snippet) {
			t.Fatalf("BPF prog-load constants missing %q", snippet)
		}
	}
	for _, snippet := range []string{
		"BPF_DIRECT_PROG_LOAD_FUNC_INFO_ARG 142",
		"BPF_DIRECT_PROG_LOAD_FUNC_INFO_REC_SIZE_OFF 76",
		"BPF_DIRECT_PROG_LOAD_FUNC_INFO_OFF 80",
		"BPF_DIRECT_PROG_LOAD_FUNC_INFO_CNT_OFF 88",
		"BPF_DIRECT_PROG_LOAD_FUNC_INFO_MAX 512",
	} {
		if !strings.Contains(nested, snippet) {
			t.Fatalf("BPF prog-load constants missing %q", snippet)
		}
	}
	for _, snippet := range []string{
		"capture_bpf_prog_load_fd_array_tlv_direct(",
		"capture_bpf_prog_load_func_info_tlv_direct(",
		"capture_bpf_bytes_tlv_direct(",
		"BPF_DIRECT_BYTES_BUCKET_512",
	} {
		if !strings.Contains(progLoad, snippet) {
			t.Fatalf("BPF prog-load provider missing %q", snippet)
		}
	}
	if !strings.Contains(nested, "syscall_bpf_prog_load_direct_event_v2.h") {
		t.Fatal("BPF prog-load dispatcher does not include dedicated provider")
	}
	if !strings.Contains(progLoad, "payload_size += capture_bpf_prog_load_fd_array_tlv_direct(") ||
		!strings.Contains(progLoad, "payload_size += capture_bpf_prog_load_func_info_tlv_direct(") ||
		strings.Contains(nested, "payload_size += capture_bpf_prog_load_fd_array_tlv_direct(") ||
		strings.Contains(nested, "payload_size += capture_bpf_prog_load_func_info_tlv_direct(") {
		t.Fatal("BPF prog-load provider ownership for fd_array/func_info is invalid")
	}
}
