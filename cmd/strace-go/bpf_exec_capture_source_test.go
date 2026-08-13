package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFExecCaptureHasDedicatedOwnership(t *testing.T) {
	root := repoRootForTest(t)
	execHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_exec_capture_direct_event_v2.h"))
	payloadHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_payload_capture_direct_event_v2.h"))

	for _, snippet := range []string{
		"struct exec_records_capture_request",
		"struct exec_capture_request",
		"capture_exec_path_tlv_direct(",
		"capture_exec_argv_records_direct(",
		"capture_exec_env_records_direct(",
		"capture_exec_snapshot_direct(",
		"capture_exec_tlv_direct(",
		"EXEC_ARG_MAX",
		"EXEC_ENV_MAX",
		"bpf_probe_read_user_str(",
	} {
		if !strings.Contains(execHeader, snippet) {
			t.Fatalf("exec capture header missing snippet %q", snippet)
		}
	}

	if !strings.Contains(payloadHeader, `#include "syscall_exec_capture_direct_event_v2.h"`) {
		t.Fatal("payload capture facade should include the dedicated exec capture header")
	}
	for _, definition := range []string{
		"static __always_inline u32 capture_exec_path_tlv_direct(",
		"static __always_inline void capture_exec_argv_records_direct(",
		"static __always_inline void capture_exec_env_records_direct(",
		"static __always_inline int capture_exec_snapshot_direct(",
		"static __always_inline u32 capture_exec_tlv_direct(",
	} {
		if strings.Contains(payloadHeader, definition) {
			t.Fatalf("payload capture facade still owns exec definition %q", definition)
		}
	}
	for _, forbidden := range []string{
		"capture_openat_path_tlv_direct(",
		"capture_write_bytes_tlv_direct(",
		"capture_read_bytes_tlv_direct(",
	} {
		if strings.Contains(execHeader, forbidden) {
			t.Fatalf("exec capture header must not own generic payload helper %q", forbidden)
		}
	}
	emitHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_payload_emit_direct_event_v2.h"))
	for _, snippet := range []string{
		"struct exec_capture_request request = {}",
		"request.path_ptr = p->args[0]",
		"request.path_ptr = p->args[1]",
		"payload_size = capture_exec_tlv_direct(&request);",
	} {
		if !strings.Contains(emitHeader, snippet) {
			t.Fatalf("payload emitter missing request-based exec exit call %q", snippet)
		}
	}

	if strings.Count(payloadHeader, "\n") > 500 || strings.Count(execHeader, "\n") > 500 {
		t.Fatal("payload capture modules exceed the 500-line source limit")
	}
}
