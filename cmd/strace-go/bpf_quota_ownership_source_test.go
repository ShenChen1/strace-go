package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFQuotaHasDedicatedCaptureAndEmitOwnership(t *testing.T) {
	root := repoRootForTest(t)
	read := func(name string) string {
		return readTextFile(t, filepath.Join(root, "bpf", name))
	}

	facade := read("syscall_quota_direct_event_v2.h")
	capture := read("syscall_quota_capture_direct_event_v2.h")
	emit := read("syscall_quota_emit_direct_event_v2.h")

	for _, include := range []string{
		`#include "syscall_quota_capture_direct_event_v2.h"`,
		`#include "syscall_quota_emit_direct_event_v2.h"`,
	} {
		if !strings.Contains(facade, include) {
			t.Fatalf("quota facade missing %q", include)
		}
	}
	if strings.Index(facade, "syscall_quota_capture_direct_event_v2.h") >
		strings.Index(facade, "syscall_quota_emit_direct_event_v2.h") {
		t.Fatal("quota facade must include capture before emit")
	}

	for _, snippet := range []string{
		"is_quota_direct_syscall(",
		"quota_direct_command(",
		"quota_direct_enter_command(",
		"quota_direct_pending_command(",
		"quota_direct_has_exit_payload(",
		"quota_direct_struct_size(",
	} {
		if !strings.Contains(facade, snippet) {
			t.Fatalf("quota facade missing policy %q", snippet)
		}
	}

	for _, snippet := range []string{
		"#include \"syscall_path_capture_direct_event_v2.h\"",
		"#include \"syscall_quota_xfs_direct_event_v2.h\"",
		"quota_direct_dynptr_data(",
		"capture_quota_struct_tlv_direct(",
		"quota_direct_enter_capacity(",
		"capture_quota_enter_tlvs(",
		"bpf_probe_read_user(",
	} {
		if !strings.Contains(capture, snippet) {
			t.Fatalf("quota capture provider missing %q", snippet)
		}
	}

	for _, snippet := range []string{
		"emit_quota_enter_event_v2_direct(",
		"emit_quota_exit_event_v2_direct(",
		"bpf_ringbuf_reserve_dynptr(",
		"bpf_ringbuf_submit_dynptr(",
		"capture_quota_enter_tlvs(",
	} {
		if !strings.Contains(emit, snippet) {
			t.Fatalf("quota emit provider missing %q", snippet)
		}
	}

	for _, definition := range []string{
		"static __always_inline u32 capture_quota_struct_tlv_direct(",
		"static __always_inline u32 quota_direct_enter_capacity(",
		"static __always_inline u32 capture_quota_enter_tlvs(",
	} {
		if strings.Contains(facade, definition) || strings.Contains(emit, definition) {
			t.Fatalf("quota capture definition leaked into another provider %q", definition)
		}
	}
	if strings.Contains(capture, "emit_quota_enter_event_v2_direct(") ||
		strings.Contains(capture, "emit_quota_exit_event_v2_direct(") {
		t.Fatal("quota capture provider must not own event emitters")
	}
	if strings.Contains(capture, "bpf_ringbuf_reserve_dynptr(") ||
		strings.Contains(capture, "bpf_ringbuf_submit_dynptr(") {
		t.Fatal("quota capture provider must not own ringbuf lifecycle")
	}
	if strings.Contains(emit, "bpf_probe_read_user(") {
		t.Fatal("quota emit provider must not own user memory reads")
	}

	for name, source := range map[string]string{
		"facade": facade, "capture": capture, "emit": emit,
	} {
		if lines := strings.Count(source, "\n") + 1; lines > 500 {
			t.Fatalf("quota %s provider lines = %d, want <= 500", name, lines)
		}
	}
}
