package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFFSHasDedicatedCaptureAndEmitOwnership(t *testing.T) {
	root := repoRootForTest(t)
	facade := readTextFile(t, filepath.Join(root, "bpf/syscall_fs_direct_event_v2.h"))
	capture := readTextFile(t, filepath.Join(root, "bpf/syscall_fs_capture_direct_event_v2.h"))
	emit := readTextFile(t, filepath.Join(root, "bpf/syscall_fs_emit_direct_event_v2.h"))

	for _, include := range []string{
		`#include "syscall_fs_capture_direct_event_v2.h"`,
		`#include "syscall_fs_emit_direct_event_v2.h"`,
	} {
		if !strings.Contains(facade, include) {
			t.Fatalf("filesystem facade missing %q", include)
		}
	}
	for _, snippet := range []string{
		"capture_fs_string_tlv_direct(",
		"capture_fs_bytes_tlv_direct(",
		"capture_fs_enter_payload_tlv_direct(",
		"capture_getdents_bytes_tlv_direct(",
		"bpf_probe_read_user_str(payload_data, max_len",
		"bpf_probe_read_user(payload_data, copied_len",
	} {
		if !strings.Contains(capture, snippet) {
			t.Fatalf("filesystem capture module missing %q", snippet)
		}
	}
	for _, snippet := range []string{
		"emit_fs_enter_event_v2_direct(",
		"emit_getdents_exit_event_v2_direct(",
		"bpf_ringbuf_reserve_dynptr(&events",
		"init_syscall_enter_event_v2_from_ctx(",
		"init_syscall_exit_event_v2_from_pending(",
	} {
		if !strings.Contains(emit, snippet) {
			t.Fatalf("filesystem emit module missing %q", snippet)
		}
	}
	for _, snippet := range []string{
		"static __always_inline u32 capture_fs_string_tlv_direct(",
		"static __always_inline u32 capture_getdents_bytes_tlv_direct(",
	} {
		if strings.Contains(facade, snippet) || strings.Contains(emit, snippet) {
			t.Fatalf("filesystem capture implementation has the wrong owner %q", snippet)
		}
	}
	if strings.Contains(facade, "static __always_inline void emit_fs_enter_event_v2_direct(") ||
		strings.Contains(capture, "static __always_inline void emit_fs_enter_event_v2_direct(") {
		t.Fatal("filesystem enter emitter has the wrong owner")
	}

	for name, source := range map[string]string{
		"syscall_fs_direct_event_v2.h":         facade,
		"syscall_fs_capture_direct_event_v2.h": capture,
		"syscall_fs_emit_direct_event_v2.h":    emit,
	} {
		if lines := strings.Count(source, "\n") + 1; lines > 500 {
			t.Fatalf("bpf/%s lines = %d, want <= 500", name, lines)
		}
	}
}
