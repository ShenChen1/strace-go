package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFGetNextIDUsesExitScalarProvider(t *testing.T) {
	root := repoRootForTest(t)
	exit := readTextFile(t, filepath.Join(root, "bpf/syscall_bpf_exit_direct_event_v2.h"))
	provider := readTextFile(t, filepath.Join(root, "bpf/syscall_bpf_next_id_exit_direct_event_v2.h"))
	for _, snippet := range []string{
		`#include "syscall_bpf_next_id_exit_direct_event_v2.h"`,
		"BPF_DIRECT_PROG_GET_NEXT_ID 11",
		"BPF_DIRECT_MAP_GET_NEXT_ID 12",
		"BPF_DIRECT_BTF_GET_NEXT_ID 23",
		"BPF_DIRECT_LINK_GET_NEXT_ID 31",
		"BPF_DIRECT_GET_NEXT_ID_OUTPUT_ARG 140",
		"BPF_DIRECT_GET_NEXT_ID_NEXT_ID_OFF 4",
		"ret_value != 0",
		"p->args[1] + BPF_DIRECT_GET_NEXT_ID_NEXT_ID_OFF",
		"emit_bpf_exit_bytes_event_v2_direct(",
		"PAYLOAD_TLV_FLAG_DIRECTION_OUT",
	} {
		if !strings.Contains(exit+provider, snippet) {
			t.Fatalf("BPF GET_NEXT_ID provider missing %q", snippet)
		}
	}
}
