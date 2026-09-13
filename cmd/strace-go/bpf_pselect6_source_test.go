package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFPselect6UsesEventTimeWrapperCapture(t *testing.T) {
	root := repoRootForTest(t)
	read := func(name string) string {
		return readTextFile(t, filepath.Join(root, name))
	}

	sources := strings.Join([]string{
		read("bpf/capture_manifest_generated.h"),
		read("bpf/syscall_numbers_amd64_generated.h"),
		read("bpf/syscall_select_direct_event_v2.h"),
		read("bpf/syscall_select_capture_direct_event_v2.h"),
		read("bpf/syscall_select_emit_direct_event_v2.h"),
		read("bpf/enter_dispatch.h"),
		read("cmd/strace-go/bpf_routes.go"),
		read("cmd/strace-go/bpf_capture_manifest_generated.go"),
	}, "\n")

	for _, snippet := range []string{
		"#define SYS_PSELECT6 270",
		"SELECT_DIRECT_PSELECT6_WRAPPER_SIZE 16",
		"SELECT_DIRECT_PSELECT6_SIGMASK_SIZE 8",
		"SELECT_DIRECT_PSELECT6_SIGMASK_ARG_INDEX 6",
		"SELECT_DIRECT_CAPTURE_SIGMASK",
		"is_pselect6_direct_syscall(",
		"capture_pselect6_sigmask_wrapper_tlv_direct(",
		"capture_pselect6_sigmask_tlv_direct(",
		"args[5]",
		"request.arg_index = SELECT_DIRECT_PSELECT6_SIGMASK_ARG_INDEX",
		`"pselect6":          {enterSlot: enterProgSelect, exitSlot: exitProgIO, standaloneExitElision: false}`,
	} {
		if !strings.Contains(sources, snippet) {
			t.Fatalf("pselect6 event-time capture contract missing %q", snippet)
		}
	}
}
