package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFBpfProgStreamReadUsesExitOutputProvider(t *testing.T) {
	root := repoRootForTest(t)
	nested := readTextFile(t, filepath.Join(root, "bpf/syscall_bpf_nested_direct_event_v2.h"))
	exit := readTextFile(t, filepath.Join(root, "bpf/syscall_bpf_exit_direct_event_v2.h"))
	dispatch := readTextFile(t, filepath.Join(root, "bpf/exit_dispatch.h"))

	if strings.Contains(nested, "capture_bpf_prog_stream_read_tlv_direct(") {
		t.Fatal("BPF stream buffer must not be captured during enter")
	}
	for _, snippet := range []string{
		"BPF_DIRECT_PROG_STREAM_READ_BY_FD 37",
		"BPF_DIRECT_PROG_STREAM_BUF_ARG 111",
		"BPF_DIRECT_PROG_STREAM_BUF_OFF 0",
		"BPF_DIRECT_PROG_STREAM_BUF_LEN_OFF 8",
		"BPF_DIRECT_STREAM_BUF_MAX 512",
		"emit_bpf_prog_stream_read_exit_event_v2_direct(",
		"bpf_attr_read_u64_direct(",
		"bpf_attr_read_u32_direct(",
		"PAYLOAD_TLV_FLAG_DIRECTION_OUT",
		"emit_bpf_exit_bytes_event_v2_direct(",
	} {
		if !strings.Contains(nested+exit, snippet) {
			t.Fatalf("BPF stream exit provider missing %q", snippet)
		}
	}
	if !strings.Contains(dispatch, "emit_bpf_exit_event_v2_direct(p, ret_value, duration)") {
		t.Fatal("exit dispatch must route BPF stream output")
	}
}
