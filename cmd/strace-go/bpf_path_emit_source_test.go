package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFPathEmitHasDedicatedOwnership(t *testing.T) {
	root := repoRootForTest(t)
	facade := readTextFile(t, filepath.Join(root, "bpf/syscall_path_direct_event_v2.h"))
	emit := readTextFile(t, filepath.Join(root, "bpf/syscall_path_emit_direct_event_v2.h"))
	capture := readTextFile(t, filepath.Join(root, "bpf/syscall_path_capture_direct_event_v2.h"))

	for _, snippet := range []string{
		`#include "syscall_path_capture_direct_event_v2.h"`,
		`#include "syscall_path_emit_direct_event_v2.h"`,
	} {
		if !strings.Contains(facade, snippet) {
			t.Fatalf("path facade missing provider include %q", snippet)
		}
	}

	for _, definition := range []string{
		"static __always_inline void emit_path_only_enter_event_v2_direct_with_path(",
		"static __always_inline void emit_path_only_enter_event_v2_direct(",
		"static __always_inline void emit_path_only_exit_event_v2_direct(",
		"static __always_inline void emit_dual_path_exit_event_v2_direct(",
		"static __always_inline void emit_dual_path_enter_event_v2_direct_with_paths(",
		"static __always_inline void emit_dual_path_enter_event_v2_direct(",
	} {
		if !strings.Contains(emit, definition) {
			t.Fatalf("path emit provider missing definition %q", definition)
		}
		if strings.Contains(facade, definition) {
			t.Fatalf("path facade still owns emitter %q", definition)
		}
	}

	for _, snippet := range []string{
		"bpf_ringbuf_reserve_dynptr(",
		"bpf_ringbuf_submit_dynptr(",
		"capture_path_only_tlv_direct(",
		"capture_dual_path_tlv_direct(",
	} {
		if !strings.Contains(emit, snippet) {
			t.Fatalf("path emit provider missing snippet %q", snippet)
		}
	}

	if strings.Contains(emit, "bpf_probe_read_user(") ||
		strings.Contains(emit, "bpf_probe_read_user_str(") {
		t.Fatal("path emit provider must not own user-memory capture")
	}
	if strings.Contains(capture, "emit_path_only_enter_event_v2_direct(") ||
		strings.Contains(capture, "emit_dual_path_enter_event_v2_direct(") {
		t.Fatal("path capture provider must not own event emitters")
	}

	if strings.Count(facade, "\n") > 500 || strings.Count(emit, "\n") > 500 ||
		strings.Count(capture, "\n") > 500 {
		t.Fatal("path provider modules exceed the 500-line source limit")
	}
}
