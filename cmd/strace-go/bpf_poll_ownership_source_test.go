package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFPollSplitsCaptureAndEmitOwnership(t *testing.T) {
	root := repoRootForTest(t)
	read := func(name string) string {
		return readTextFile(t, filepath.Join(root, "bpf", name))
	}

	facade := read("syscall_poll_direct_event_v2.h")
	capture := read("syscall_poll_capture_direct_event_v2.h")
	emit := read("syscall_poll_emit_direct_event_v2.h")

	for _, include := range []string{
		`#include "syscall_poll_capture_direct_event_v2.h"`,
		`#include "syscall_poll_emit_direct_event_v2.h"`,
	} {
		if !strings.Contains(facade, include) {
			t.Fatalf("poll facade missing %q", include)
		}
	}
	if strings.Index(facade, "syscall_poll_capture_direct_event_v2.h") >
		strings.Index(facade, "syscall_poll_emit_direct_event_v2.h") {
		t.Fatal("poll facade must include capture before emit")
	}
	for _, snippet := range []string{
		"is_poll_direct_syscall(",
		"is_ppoll_direct_syscall(",
		"poll_direct_count(",
		"poll_fds_user_len(",
		"poll_fds_copy_len(",
	} {
		if !strings.Contains(facade, snippet) {
			t.Fatalf("poll facade missing policy %q", snippet)
		}
	}
	for _, snippet := range []string{
		"capture_poll_fds_tlv_direct(",
		"capture_poll_timeout_tlv_direct(",
		"capture_poll_sigmask_tlv_direct(",
		"bpf_probe_read_user(",
	} {
		if !strings.Contains(capture, snippet) {
			t.Fatalf("poll capture provider missing %q", snippet)
		}
	}
	for _, snippet := range []string{
		"emit_poll_enter_event_v2_direct(",
		"emit_poll_exit_event_v2_direct(",
		"bpf_ringbuf_reserve_dynptr(",
		"bpf_ringbuf_submit_dynptr(",
	} {
		if !strings.Contains(emit, snippet) {
			t.Fatalf("poll emit provider missing %q", snippet)
		}
	}
	for _, forbidden := range []string{
		"capture_poll_fds_tlv_direct(",
		"capture_poll_timeout_tlv_direct(",
		"capture_poll_sigmask_tlv_direct(",
	} {
		if strings.Contains(facade, forbidden) {
			t.Fatalf("poll facade must not own capture implementation %q", forbidden)
		}
	}
	if strings.Contains(capture, "emit_poll_enter_event_v2_direct(") ||
		strings.Contains(capture, "emit_poll_exit_event_v2_direct(") {
		t.Fatal("poll capture provider must not own event emitters")
	}
	if strings.Contains(emit, "bpf_probe_read_user(") {
		t.Fatal("poll emit provider must not own user memory reads")
	}
	body, ok := bpfFunctionBody(capture, "capture_poll_fds_tlv_direct")
	if !ok {
		t.Fatal("poll capture provider missing fd composer")
	}
	signature := strings.SplitN(body, "{", 2)[0]
	if strings.Count(signature, ",")+1 > 5 {
		t.Fatalf("poll fd composer has more than five parameters: %s", signature)
	}

	for name, source := range map[string]string{
		"facade": facade, "capture": capture, "emit": emit,
	} {
		if lines := strings.Count(source, "\n") + 1; lines > 500 {
			t.Fatalf("poll %s provider lines = %d, want <= 500", name, lines)
		}
	}
}
