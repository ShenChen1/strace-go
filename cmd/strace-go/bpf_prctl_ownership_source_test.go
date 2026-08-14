package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFPrctlHasDedicatedCaptureAndEmitOwnership(t *testing.T) {
	root := repoRootForTest(t)
	read := func(name string) string {
		return readTextFile(t, filepath.Join(root, "bpf", name))
	}

	facade := read("syscall_prctl_direct_event_v2.h")
	capture := read("syscall_prctl_capture_direct_event_v2.h")
	emit := read("syscall_prctl_emit_direct_event_v2.h")

	for _, include := range []string{
		`#include "syscall_prctl_capture_direct_event_v2.h"`,
		`#include "syscall_prctl_emit_direct_event_v2.h"`,
	} {
		if !strings.Contains(facade, include) {
			t.Fatalf("prctl facade missing %q", include)
		}
	}
	if strings.Index(facade, "syscall_prctl_capture_direct_event_v2.h") >
		strings.Index(facade, "syscall_prctl_emit_direct_event_v2.h") {
		t.Fatal("prctl facade must include capture before emit")
	}

	for _, snippet := range []string{
		"PRCTL_DIRECT_NAME_SIZE 16",
		"PRCTL_DIRECT_UINT32_SIZE 4",
		"is_prctl_direct_syscall(",
		"is_prctl_set_name_option(",
		"is_prctl_get_name_option(",
		"is_prctl_uint32_out_option(",
	} {
		if !strings.Contains(facade, snippet) {
			t.Fatalf("prctl facade missing policy %q", snippet)
		}
	}
	for _, snippet := range []string{
		"capture_prctl_name_tlv_direct(",
		"capture_prctl_uint32_tlv_direct(",
		"bpf_probe_read_user_str(",
		"bpf_probe_read_user(",
		"payload_tlv_write_header_direct(",
	} {
		if !strings.Contains(capture, snippet) {
			t.Fatalf("prctl capture provider missing %q", snippet)
		}
	}
	for _, snippet := range []string{
		"emit_prctl_enter_event_v2_direct(",
		"emit_prctl_exit_event_v2_direct(",
		"bpf_ringbuf_reserve_dynptr(",
		"bpf_ringbuf_submit_dynptr(",
		"capture_prctl_name_tlv_direct(",
		"capture_prctl_uint32_tlv_direct(",
	} {
		if !strings.Contains(emit, snippet) {
			t.Fatalf("prctl emit provider missing %q", snippet)
		}
	}

	for _, definition := range []string{
		"static __always_inline u32 capture_prctl_name_tlv_direct(",
		"static __always_inline u32 capture_prctl_uint32_tlv_direct(",
		"static __always_inline void emit_prctl_enter_event_v2_direct(",
		"static __always_inline void emit_prctl_exit_event_v2_direct(",
	} {
		if strings.Contains(facade, definition) {
			t.Fatalf("prctl facade still owns implementation %q", definition)
		}
	}
	if strings.Contains(capture, "emit_prctl_enter_event_v2_direct(") ||
		strings.Contains(capture, "emit_prctl_exit_event_v2_direct(") ||
		strings.Contains(capture, "bpf_ringbuf_reserve_dynptr(") ||
		strings.Contains(capture, "bpf_ringbuf_submit_dynptr(") {
		t.Fatal("prctl capture provider must not own emitter or ringbuf lifecycle")
	}
	if strings.Contains(emit, "bpf_probe_read_user(") ||
		strings.Contains(emit, "bpf_probe_read_user_str(") {
		t.Fatal("prctl emit provider must not own user memory reads")
	}

	for name, source := range map[string]string{
		"facade": facade, "capture": capture, "emit": emit,
	} {
		if lines := strings.Count(source, "\n") + 1; lines > 500 {
			t.Fatalf("prctl %s provider lines = %d, want <= 500", name, lines)
		}
	}
}
