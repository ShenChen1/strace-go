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
	manifest := readTextFile(t, filepath.Join(root, "bpf/capture_manifest_generated.h"))
	abi := readTextFile(t, filepath.Join(root, "bpf/runtime_abi.h"))
	eventABI := readTextFile(t, filepath.Join(root, "bpf/event_abi_generated.h"))

	start := strings.Index(dispatch, "int enter_no_payload_generic(")
	if start < 0 {
		t.Fatal("enter dispatch is missing generic no-payload handler")
	}
	end := strings.Index(dispatch[start:], "SEC(\"tracepoint/raw_syscalls/sys_enter\")")
	if end < 0 {
		t.Fatal("generic no-payload handler has no bounded source region")
	}
	generic := dispatch[start : start+end]
	if !strings.Contains(generic, "emit_plain_no_payload_enter_event_v2_direct(") {
		t.Fatal("generic no-payload handler does not use the ordinary enter emitter")
	}
	if strings.Contains(generic, "emit_fd_path_or_no_payload_enter_event_v2_direct(") {
		t.Fatal("generic no-payload handler still references FD/path capture")
	}
	for _, snippet := range []string{
		"ENTER_PROG_NO_PAYLOAD_GENERIC = 46",
		"STRACE_GO_ENTER_PROG_ARRAY_MAX_ENTRIES 55",
		"CONFIG_ELIDE_PLAIN_ENTER 128",
		"plain_enter_elide_map",
	} {
		if !strings.Contains(runtime+abi+eventABI+manifest, snippet) {
			t.Fatalf("generic enter ABI is missing %q", snippet)
		}
	}
}
