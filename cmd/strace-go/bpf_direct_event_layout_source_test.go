package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFDirectEventModulesOwnResponsibilities(t *testing.T) {
	root := repoRootForTest(t)
	read := func(name string) string {
		return readTextFile(t, filepath.Join(root, "bpf", name))
	}

	facade := read("syscall_direct_event_v2.h")
	core := read("syscall_event_core_v2.h")
	capture := read("syscall_payload_capture_direct_event_v2.h")
	execCapture := read("syscall_exec_capture_direct_event_v2.h")
	emit := read("syscall_payload_emit_direct_event_v2.h")

	for name, source := range map[string]string{
		"syscall_direct_event_v2.h":                 facade,
		"syscall_event_core_v2.h":                   core,
		"syscall_payload_capture_direct_event_v2.h": capture,
		"syscall_exec_capture_direct_event_v2.h":    execCapture,
		"syscall_payload_emit_direct_event_v2.h":    emit,
	} {
		if !strings.Contains(source, "#ifndef STRACE_GO_") || !strings.Contains(source, "#endif") {
			t.Fatalf("%s must have an include guard", name)
		}
	}

	for _, include := range []string{
		`#include "syscall_event_core_v2.h"`,
		`#include "syscall_payload_capture_direct_event_v2.h"`,
		`#include "syscall_payload_emit_direct_event_v2.h"`,
	} {
		if !strings.Contains(facade, include) {
			t.Fatalf("direct event facade missing %q", include)
		}
	}
	for _, snippet := range []string{
		"save_pending_syscall_args(",
		"init_syscall_event_v2_header_direct(",
		"emit_terminating_exit_event_v2_direct(",
	} {
		if !strings.Contains(core, snippet) {
			t.Fatalf("core module missing %q", snippet)
		}
	}
	for _, snippet := range []string{
		"capture_openat_path_tlv_direct(",
		"capture_read_bytes_tlv_direct(",
	} {
		if !strings.Contains(capture, snippet) {
			t.Fatalf("payload capture module missing %q", snippet)
		}
	}
	for _, snippet := range []string{
		"capture_exec_path_tlv_direct(",
		"capture_exec_snapshot_direct(",
		"capture_exec_tlv_direct(",
	} {
		if !strings.Contains(execCapture, snippet) {
			t.Fatalf("exec capture module missing %q", snippet)
		}
	}
	for _, snippet := range []string{
		"emit_payload_enter_event_v2_direct(",
		"emit_payload_exit_event_v2_direct(",
		"emit_exec_exit_event_v2_direct(",
	} {
		if !strings.Contains(emit, snippet) {
			t.Fatalf("payload emit module missing %q", snippet)
		}
	}
	for _, forbidden := range []string{
		"static __always_inline void save_pending_syscall_args(",
		"static __always_inline u32 capture_openat_path_tlv_direct(",
		"static __always_inline void emit_payload_enter_event_v2_direct(",
	} {
		if strings.Contains(facade, forbidden) {
			t.Fatalf("facade must not own implementation %q", forbidden)
		}
	}
}

func TestBPFDirectEventModulesStayWithinFileLimit(t *testing.T) {
	root := repoRootForTest(t)
	for _, name := range []string{
		"syscall_direct_event_v2.h",
		"syscall_event_core_v2.h",
		"syscall_payload_capture_direct_event_v2.h",
		"syscall_exec_capture_direct_event_v2.h",
		"syscall_payload_emit_direct_event_v2.h",
	} {
		source := readTextFile(t, filepath.Join(root, "bpf", name))
		if lines := strings.Count(source, "\n") + 1; lines > 500 {
			t.Fatalf("bpf/%s lines = %d, want <= 500", name, lines)
		}
	}
}
