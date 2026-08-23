package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFProgQueryExitProviderOwnsOutputArrays(t *testing.T) {
	root := repoRootForTest(t)
	nested := readTextFile(t, filepath.Join(root, "bpf/syscall_bpf_nested_direct_event_v2.h"))
	exit := readTextFile(t, filepath.Join(root, "bpf/syscall_bpf_exit_direct_event_v2.h"))
	provider := readTextFile(t, filepath.Join(root, "bpf/syscall_bpf_prog_query_exit_direct_event_v2.h"))
	dispatch := readTextFile(t, filepath.Join(root, "bpf/exit_dispatch.h"))

	for _, snippet := range []string{
		"BPF_DIRECT_PROG_QUERY 16",
		"BPF_DIRECT_PROG_QUERY_PROG_IDS_ARG 128",
		"BPF_DIRECT_PROG_QUERY_PROG_ATTACH_FLAGS_ARG 129",
		"BPF_DIRECT_PROG_QUERY_LINK_IDS_ARG 130",
		"BPF_DIRECT_PROG_QUERY_LINK_ATTACH_FLAGS_ARG 131",
		"BPF_DIRECT_PROG_QUERY_PROG_CNT_OUT_ARG 132",
		"BPF_DIRECT_PROG_QUERY_PROG_IDS_OFF 16",
		"BPF_DIRECT_PROG_QUERY_PROG_CNT_OFF 24",
		"BPF_DIRECT_PROG_QUERY_ARRAY_MAX 512",
	} {
		if !strings.Contains(nested+provider, snippet) {
			t.Fatalf("BPF prog-query provider missing %q", snippet)
		}
	}
	for _, snippet := range []string{
		"struct bpf_exit_bytes_request requests[BPF_DIRECT_PROG_QUERY_OUTPUT_SECTIONS]",
		"emit_bpf_prog_query_exit_event_v2_direct(",
		"init_syscall_exit_event_v2_from_pending(",
	} {
		if !strings.Contains(provider, snippet) {
			t.Fatalf("BPF prog-query exit provider missing %q", snippet)
		}
	}
	for _, snippet := range []string{
		"BPF_DIRECT_BYTES_BUCKET_512",
		"bpf_probe_read_user(",
		"PAYLOAD_TLV_FLAG_DIRECTION_OUT",
	} {
		if !strings.Contains(provider+exit, snippet) {
			t.Fatalf("BPF prog-query payload path missing %q", snippet)
		}
	}
	if !strings.Contains(exit, `#include "syscall_bpf_prog_query_exit_direct_event_v2.h"`) {
		t.Fatal("BPF exit facade must include the prog-query provider")
	}
	if !strings.Contains(dispatch, "emit_bpf_exit_event_v2_direct(p, ret_value, duration)") {
		t.Fatal("exit IO family must dispatch BPF prog-query output")
	}
}
