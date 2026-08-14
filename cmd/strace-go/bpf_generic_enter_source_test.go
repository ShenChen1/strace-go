package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFGenericEnterHandlerExcludesFDPathCapture(t *testing.T) {
	root := repoRootForTest(t)
	dispatch := readTextFile(t, filepath.Join(root, "bpf/enter_dispatch.h"))
	runtime := readTextFile(t, filepath.Join(root, "bpf/enter_runtime.h"))
	abi := readTextFile(t, filepath.Join(root, "bpf/runtime_abi.h"))

	start := strings.Index(dispatch, "int enter_no_payload_generic(")
	if start < 0 {
		t.Fatal("enter dispatch is missing generic no-payload handler")
	}
	end := strings.Index(dispatch[start:], "SEC(\"tracepoint/raw_syscalls/sys_enter\")")
	if end < 0 {
		t.Fatal("generic no-payload handler has no bounded source region")
	}
	generic := dispatch[start : start+end]
	if !strings.Contains(generic, "emit_no_payload_enter_event_v2_direct(") {
		t.Fatal("generic no-payload handler does not use the ordinary enter emitter")
	}
	if strings.Contains(generic, "emit_fd_path_or_no_payload_enter_event_v2_direct(") {
		t.Fatal("generic no-payload handler still references FD/path capture")
	}
	for _, snippet := range []string{
		"ENTER_PROG_NO_PAYLOAD_GENERIC = 46",
		"__uint(max_entries, 47)",
	} {
		if !strings.Contains(runtime+abi, snippet) {
			t.Fatalf("generic enter ABI is missing %q", snippet)
		}
	}
}
