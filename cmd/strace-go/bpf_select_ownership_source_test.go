package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFSelectSplitsCaptureAndEmitOwnership(t *testing.T) {
	root := repoRootForTest(t)
	read := func(name string) string {
		return readTextFile(t, filepath.Join(root, "bpf", name))
	}

	facade := read("syscall_select_direct_event_v2.h")
	capture := read("syscall_select_capture_direct_event_v2.h")
	emit := read("syscall_select_emit_direct_event_v2.h")

	for _, include := range []string{
		`#include "syscall_select_capture_direct_event_v2.h"`,
		`#include "syscall_select_emit_direct_event_v2.h"`,
	} {
		if !strings.Contains(facade, include) {
			t.Fatalf("select facade missing %q", include)
		}
	}
	if strings.Index(facade, "syscall_select_capture_direct_event_v2.h") >
		strings.Index(facade, "syscall_select_emit_direct_event_v2.h") {
		t.Fatal("select facade must include capture before emit")
	}
	for _, snippet := range []string{
		"is_select_direct_syscall(",
		"select_direct_fdset_user_len(",
		"SELECT_DIRECT_CAPTURE_FDSETS",
		"SELECT_DIRECT_CAPTURE_TIMEOUT",
	} {
		if !strings.Contains(facade, snippet) {
			t.Fatalf("select facade missing policy %q", snippet)
		}
	}

	for _, snippet := range []string{
		"select_direct_fdset_user_len(",
		"capture_select_fdset_tlv_direct(",
		"capture_select_timeout_tlv_direct(",
		"capture_select_payloads_tlv_direct(",
		"collect_select_fdset_candidates_direct(",
		"collect_select_fd_path_candidates_direct(",
	} {
		if !strings.Contains(capture, snippet) {
			t.Fatalf("select capture provider missing %q", snippet)
		}
	}
	for _, snippet := range []string{
		"emit_select_enter_event_v2_direct(",
		"emit_select_fd_path_fragment_event_v2_direct(",
		"emit_select_exit_event_v2_direct(",
		"bpf_ringbuf_reserve_dynptr(",
		"bpf_ringbuf_submit_dynptr(",
	} {
		if !strings.Contains(emit, snippet) {
			t.Fatalf("select emit provider missing %q", snippet)
		}
	}
	for _, forbidden := range []string{
		"capture_select_fdset_tlv_direct(",
		"capture_select_timeout_tlv_direct(",
		"capture_select_payloads_tlv_direct(",
	} {
		if strings.Contains(facade, forbidden) {
			t.Fatalf("select facade must not own capture implementation %q", forbidden)
		}
	}
	if strings.Contains(capture, "emit_select_enter_event_v2_direct(") ||
		strings.Contains(capture, "emit_select_exit_event_v2_direct(") {
		t.Fatal("select capture provider must not own event emitters")
	}
	if strings.Contains(emit, "bpf_probe_read_user(") {
		t.Fatal("select emit provider must not own user memory reads")
	}
	scanStart := strings.Index(capture, "static __always_inline void collect_select_fdset_candidates_direct(")
	collectorStart := strings.Index(capture, "static __always_inline u32 collect_select_fd_path_candidates_direct(")
	if scanStart < 0 || collectorStart <= scanStart {
		t.Fatal("select capture provider missing bounded fd_set scanner")
	}
	scanBody := capture[scanStart:collectorStart]
	if strings.Contains(scanBody, "capture_fd_path_tlv_direct(") {
		t.Fatal("select fd_set scanner must not perform dentry path capture inside its bounded loop")
	}
	for _, snippet := range []string{
		"struct select_fd_scan_context",
		"select_fd_scan_callback(",
		"bpf_loop(FD_PATH_NESTED_SCAN_BYTES * 8",
	} {
		if !strings.Contains(capture, snippet) {
			t.Fatalf("select fd_set scanner missing bounded helper loop %q", snippet)
		}
	}
	if strings.Contains(scanBody, "for (u32 fd = 0;") {
		t.Fatal("select fd_set scanner must not expand 1024 branches in enter_select")
	}
	body, ok := bpfFunctionBody(capture, "capture_select_payloads_tlv_direct")
	if !ok {
		t.Fatal("select capture provider missing payload composer")
	}
	signature := strings.SplitN(body, "{", 2)[0]
	if strings.Count(signature, ",")+1 > 5 {
		t.Fatalf("select payload composer has more than five parameters: %s", signature)
	}

	for name, source := range map[string]string{
		"facade": facade, "capture": capture, "emit": emit,
	} {
		if lines := strings.Count(source, "\n") + 1; lines > 500 {
			t.Fatalf("select %s provider lines = %d, want <= 500", name, lines)
		}
	}
}
