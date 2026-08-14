package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFSmallStructHasDedicatedCaptureAndEmitOwnership(t *testing.T) {
	root := repoRootForTest(t)
	read := func(name string) string {
		return readTextFile(t, filepath.Join(root, "bpf", name))
	}

	facade := read("syscall_small_struct_direct_event_v2.h")
	capture := read("syscall_small_struct_capture_direct_event_v2.h")
	emit := read("syscall_small_struct_emit_direct_event_v2.h")

	for _, include := range []string{
		`#include "syscall_small_struct_capture_direct_event_v2.h"`,
		`#include "syscall_small_struct_emit_direct_event_v2.h"`,
	} {
		if !strings.Contains(facade, include) {
			t.Fatalf("small struct facade missing %q", include)
		}
	}
	if strings.Index(facade, "syscall_small_struct_capture_direct_event_v2.h") >
		strings.Index(facade, "syscall_small_struct_emit_direct_event_v2.h") {
		t.Fatal("small struct facade must include capture before emit")
	}

	for _, snippet := range []string{
		"SMALL_STRUCT_DIRECT_WORD_SIZE 8",
		"is_arch_prctl_get_direct_option(",
		"is_small_struct_direct_syscall(",
		"is_small_struct_enter_direct_syscall(",
		"is_small_struct_exit_direct_syscall(",
	} {
		if !strings.Contains(facade, snippet) {
			t.Fatalf("small struct facade missing policy %q", snippet)
		}
	}
	for _, snippet := range []string{
		"capture_small_struct_word_tlv_direct(",
		"bpf_probe_read_user(",
		"payload_tlv_write_header_direct(",
		"PAYLOAD_TLV_KIND_STRUCT",
	} {
		if !strings.Contains(capture, snippet) {
			t.Fatalf("small struct capture provider missing %q", snippet)
		}
	}
	for _, snippet := range []string{
		"emit_small_struct_enter_event_v2_direct(",
		"emit_copy_file_range_enter_event_v2_direct(",
		"emit_small_struct_exit_event_v2_direct(",
		"bpf_ringbuf_reserve_dynptr(",
		"bpf_ringbuf_submit_dynptr(",
		"capture_small_struct_word_tlv_direct(",
	} {
		if !strings.Contains(emit, snippet) {
			t.Fatalf("small struct emit provider missing %q", snippet)
		}
	}

	for _, definition := range []string{
		"static __always_inline u32 capture_small_struct_word_tlv_direct(",
		"static __always_inline void emit_small_struct_enter_event_v2_direct(",
		"static __always_inline void emit_small_struct_exit_event_v2_direct(",
	} {
		if strings.Contains(facade, definition) {
			t.Fatalf("small struct facade still owns implementation %q", definition)
		}
	}
	if strings.Contains(capture, "bpf_ringbuf_reserve_dynptr(") ||
		strings.Contains(capture, "bpf_ringbuf_submit_dynptr(") {
		t.Fatal("small struct capture provider must not own ringbuf lifecycle")
	}
	if strings.Contains(emit, "bpf_probe_read_user(") {
		t.Fatal("small struct emit provider must not own user memory reads")
	}
	if strings.Contains(emit, "emit_small_struct_enter_event_v2_direct_with_arg(") {
		t.Fatal("small struct emit provider must not keep the oversized helper")
	}

	for name, source := range map[string]string{
		"facade": facade, "capture": capture, "emit": emit,
	} {
		if lines := strings.Count(source, "\n") + 1; lines > 500 {
			t.Fatalf("small struct %s provider lines = %d, want <= 500", name, lines)
		}
	}
}
