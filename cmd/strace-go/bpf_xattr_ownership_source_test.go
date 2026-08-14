package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFXattrSplitsCaptureAndEmitOwnership(t *testing.T) {
	root := repoRootForTest(t)
	read := func(name string) string {
		return readTextFile(t, filepath.Join(root, "bpf", name))
	}

	facade := read("syscall_xattr_direct_event_v2.h")
	capture := read("syscall_xattr_capture_direct_event_v2.h")
	emit := read("syscall_xattr_emit_direct_event_v2.h")

	for _, include := range []string{
		`#include "syscall_xattr_capture_direct_event_v2.h"`,
		`#include "syscall_xattr_emit_direct_event_v2.h"`,
	} {
		if !strings.Contains(facade, include) {
			t.Fatalf("xattr facade missing %q", include)
		}
	}
	if strings.Index(facade, "syscall_xattr_capture_direct_event_v2.h") >
		strings.Index(facade, "syscall_xattr_emit_direct_event_v2.h") {
		t.Fatal("xattr facade must include capture before emit")
	}
	for _, snippet := range []string{
		"XATTR_DIRECT_PATH_MAX",
		"XATTR_DIRECT_NAME_MAX",
		"XATTR_DIRECT_VALUE_MAX",
		"is_xattr_direct_syscall(",
		"xattr_direct_has_path(",
		"xattr_direct_has_name(",
	} {
		if !strings.Contains(facade, snippet) {
			t.Fatalf("xattr facade missing policy %q", snippet)
		}
	}
	for _, snippet := range []string{
		"struct xattr_bytes_capture_request",
		"capture_xattr_string_tlv_direct(",
		"capture_xattr_bytes_tlv_direct(",
		"capture_xattr_enter_payload_tlv_direct(",
		"bpf_probe_read_user_str(",
		"bpf_probe_read_user(",
	} {
		if !strings.Contains(capture, snippet) {
			t.Fatalf("xattr capture provider missing %q", snippet)
		}
	}
	for _, snippet := range []string{
		"emit_xattr_enter_event_v2_direct(",
		"emit_xattr_bytes_exit_event_v2_direct(",
		"emit_xattr_get_exit_event_v2_direct(",
		"emit_xattr_list_exit_event_v2_direct(",
		"bpf_ringbuf_reserve_dynptr(",
		"bpf_ringbuf_submit_dynptr(",
	} {
		if !strings.Contains(emit, snippet) {
			t.Fatalf("xattr emit provider missing %q", snippet)
		}
	}
	for _, forbidden := range []string{
		"capture_xattr_string_tlv_direct(",
		"capture_xattr_bytes_tlv_direct(",
		"capture_xattr_enter_payload_tlv_direct(",
	} {
		if strings.Contains(facade, forbidden) {
			t.Fatalf("xattr facade must not own capture implementation %q", forbidden)
		}
	}
	if strings.Contains(capture, "emit_xattr_enter_event_v2_direct(") ||
		strings.Contains(capture, "emit_xattr_bytes_exit_event_v2_direct(") {
		t.Fatal("xattr capture provider must not own event emitters")
	}
	if strings.Contains(capture, "bpf_ringbuf_reserve_dynptr(") ||
		strings.Contains(capture, "bpf_ringbuf_submit_dynptr(") {
		t.Fatal("xattr capture provider must not own ringbuf lifecycle")
	}
	if strings.Contains(emit, "bpf_probe_read_user(") || strings.Contains(emit, "bpf_probe_read_user_str(") {
		t.Fatal("xattr emit provider must not own user memory reads")
	}
	body, ok := bpfFunctionBody(capture, "capture_xattr_bytes_tlv_direct")
	if !ok {
		t.Fatal("xattr capture provider missing bytes helper")
	}
	signature := strings.SplitN(body, "{", 2)[0]
	if strings.Count(signature, ",")+1 > 5 {
		t.Fatalf("xattr bytes helper has more than five parameters: %s", signature)
	}

	for name, source := range map[string]string{
		"facade": facade, "capture": capture, "emit": emit,
	} {
		if lines := strings.Count(source, "\n") + 1; lines > 500 {
			t.Fatalf("xattr %s provider lines = %d, want <= 500", name, lines)
		}
	}
}
