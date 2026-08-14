package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFKeyHasDedicatedCaptureAndEmitOwnership(t *testing.T) {
	root := repoRootForTest(t)
	read := func(name string) string {
		return readTextFile(t, filepath.Join(root, "bpf", name))
	}

	facade := read("syscall_key_direct_event_v2.h")
	capture := read("syscall_key_capture_direct_event_v2.h")
	emit := read("syscall_key_emit_direct_event_v2.h")

	for _, include := range []string{
		`#include "syscall_key_capture_direct_event_v2.h"`,
		`#include "syscall_key_emit_direct_event_v2.h"`,
	} {
		if !strings.Contains(facade, include) {
			t.Fatalf("key facade missing %q", include)
		}
	}
	if strings.Index(facade, "syscall_key_capture_direct_event_v2.h") >
		strings.Index(facade, "syscall_key_emit_direct_event_v2.h") {
		t.Fatal("key facade must include capture before emit")
	}
	for _, snippet := range []string{
		"KEY_DIRECT_TYPE_MAX 64",
		"KEY_DIRECT_DESCRIPTION_MAX 128",
		"KEY_DIRECT_PAYLOAD_MAX 256",
		"is_key_direct_syscall(",
		"KEY_DIRECT_PAYLOAD_CAPACITY",
	} {
		if !strings.Contains(facade, snippet) {
			t.Fatalf("key facade missing policy %q", snippet)
		}
	}
	for _, snippet := range []string{
		"capture_key_string_tlv_direct(",
		"capture_key_bytes_tlv_direct(",
		"capture_key_payload_tlv_direct(",
		"bpf_probe_read_user_str(",
		"bpf_probe_read_user(",
		"payload_tlv_write_header_direct(",
	} {
		if !strings.Contains(capture, snippet) {
			t.Fatalf("key capture provider missing %q", snippet)
		}
	}
	for _, snippet := range []string{
		"emit_key_enter_event_v2_direct(",
		"init_syscall_enter_event_v2_from_ctx(",
		"bpf_ringbuf_reserve_dynptr(",
		"bpf_ringbuf_submit_dynptr(",
		"capture_key_payload_tlv_direct(",
	} {
		if !strings.Contains(emit, snippet) {
			t.Fatalf("key emit provider missing %q", snippet)
		}
	}
	for _, definition := range []string{
		"static __always_inline u32 capture_key_string_tlv_direct(",
		"static __always_inline u32 capture_key_bytes_tlv_direct(",
		"static __always_inline u32 capture_key_payload_tlv_direct(",
		"static __always_inline void emit_key_enter_event_v2_direct(",
	} {
		if strings.Contains(facade, definition) {
			t.Fatalf("key facade still owns implementation %q", definition)
		}
	}
	if strings.Contains(capture, "emit_key_enter_event_v2_direct(") ||
		strings.Contains(capture, "bpf_ringbuf_reserve_dynptr(") ||
		strings.Contains(capture, "bpf_ringbuf_submit_dynptr(") {
		t.Fatal("key capture provider must not own emitter or ringbuf lifecycle")
	}
	if strings.Contains(emit, "bpf_probe_read_user(") ||
		strings.Contains(emit, "bpf_probe_read_user_str(") {
		t.Fatal("key emit provider must not own user memory reads")
	}

	for name, source := range map[string]string{
		"facade": facade, "capture": capture, "emit": emit,
	} {
		if lines := strings.Count(source, "\n") + 1; lines > 500 {
			t.Fatalf("key %s provider lines = %d, want <= 500", name, lines)
		}
	}
}
