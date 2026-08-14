package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFReadlinkHasDedicatedCaptureAndEmitOwnership(t *testing.T) {
	root := repoRootForTest(t)
	read := func(name string) string {
		return readTextFile(t, filepath.Join(root, "bpf", name))
	}

	facade := read("syscall_readlink_direct_event_v2.h")
	capture := read("syscall_readlink_capture_direct_event_v2.h")
	emit := read("syscall_readlink_emit_direct_event_v2.h")

	for _, include := range []string{
		`#include "syscall_readlink_capture_direct_event_v2.h"`,
		`#include "syscall_readlink_emit_direct_event_v2.h"`,
	} {
		if !strings.Contains(facade, include) {
			t.Fatalf("readlink facade missing %q", include)
		}
	}
	if strings.Index(facade, "syscall_readlink_capture_direct_event_v2.h") >
		strings.Index(facade, "syscall_readlink_emit_direct_event_v2.h") {
		t.Fatal("readlink facade must include capture before emit")
	}

	for _, snippet := range []string{
		"READLINK_DIRECT_PATH_MAX 512",
		"READLINK_DIRECT_BYTES_MAX 512",
		"is_readlink_direct_syscall(",
		"readlink_direct_buf_arg_index(",
		"readlink_direct_buf_user_ptr(",
	} {
		if !strings.Contains(facade, snippet) {
			t.Fatalf("readlink facade missing policy %q", snippet)
		}
	}
	for _, snippet := range []string{
		"capture_readlink_path_tlv_direct(",
		"capture_readlink_bytes_tlv_direct(",
		"bpf_probe_read_user_str(",
		"bpf_probe_read_user(",
		"payload_tlv_write_header_direct(",
	} {
		if !strings.Contains(capture, snippet) {
			t.Fatalf("readlink capture provider missing %q", snippet)
		}
	}
	for _, snippet := range []string{
		"emit_readlink_enter_event_v2_direct(",
		"emit_readlink_exit_event_v2_direct(",
		"request.args[0] = ctx->args[0];",
		"request.args[5] = ctx->args[5];",
		"request.user_ptr = request.args[0];",
		"request.user_ptr = request.args[1];",
		"bpf_ringbuf_reserve_dynptr(",
		"bpf_ringbuf_submit_dynptr(",
		"capture_readlink_path_tlv_direct(",
		"capture_readlink_bytes_tlv_direct(",
	} {
		if !strings.Contains(emit, snippet) {
			t.Fatalf("readlink emit provider missing %q", snippet)
		}
	}

	for _, definition := range []string{
		"static __always_inline u32 capture_readlink_path_tlv_direct(",
		"static __always_inline u32 capture_readlink_bytes_tlv_direct(",
		"static __always_inline void emit_readlink_enter_event_v2_direct(",
		"static __always_inline void emit_readlink_exit_event_v2_direct(",
	} {
		if strings.Contains(facade, definition) {
			t.Fatalf("readlink facade still owns implementation %q", definition)
		}
	}
	if strings.Contains(capture, "emit_readlink_enter_event_v2_direct(") ||
		strings.Contains(capture, "emit_readlink_exit_event_v2_direct(") ||
		strings.Contains(capture, "bpf_ringbuf_reserve_dynptr(") ||
		strings.Contains(capture, "bpf_ringbuf_submit_dynptr(") {
		t.Fatal("readlink capture provider must not own emitter or ringbuf lifecycle")
	}
	if strings.Contains(emit, "bpf_probe_read_user(") ||
		strings.Contains(emit, "bpf_probe_read_user_str(") {
		t.Fatal("readlink emit provider must not own user memory reads")
	}

	for name, source := range map[string]string{
		"facade": facade, "capture": capture, "emit": emit,
	} {
		if lines := strings.Count(source, "\n") + 1; lines > 500 {
			t.Fatalf("readlink %s provider lines = %d, want <= 500", name, lines)
		}
	}
}
