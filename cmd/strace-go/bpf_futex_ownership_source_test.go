package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFFutexSplitsCaptureAndEmitOwnership(t *testing.T) {
	root := repoRootForTest(t)
	read := func(name string) string {
		return readTextFile(t, filepath.Join(root, "bpf", name))
	}

	facade := read("syscall_futex_direct_event_v2.h")
	capture := read("syscall_futex_capture_direct_event_v2.h")
	emit := read("syscall_futex_emit_direct_event_v2.h")

	for _, include := range []string{
		`#include "syscall_futex_capture_direct_event_v2.h"`,
		`#include "syscall_futex_emit_direct_event_v2.h"`,
	} {
		if !strings.Contains(facade, include) {
			t.Fatalf("futex facade missing %q", include)
		}
	}
	if strings.Index(facade, "syscall_futex_capture_direct_event_v2.h") >
		strings.Index(facade, "syscall_futex_emit_direct_event_v2.h") {
		t.Fatal("futex facade must include capture before emit")
	}
	for _, snippet := range []string{
		"FUTEX_DIRECT_WAITV_ELEM_SIZE",
		"FUTEX_DIRECT_WAITV_MAX",
		"FUTEX_DIRECT_REQUEUE_WAITERS_SIZE",
		"futex_has_timeout_direct(",
	} {
		if !strings.Contains(facade, snippet) {
			t.Fatalf("futex facade missing policy %q", snippet)
		}
	}
	for _, snippet := range []string{
		"futex_waitv_user_len_direct(",
		"futex_waitv_copy_len_direct(",
		"capture_futex_waitv_waiters_tlv_direct(",
		"capture_futex_requeue_waiters_tlv_direct(",
		"bpf_probe_read_user(",
	} {
		if !strings.Contains(capture, snippet) {
			t.Fatalf("futex capture provider missing %q", snippet)
		}
	}
	for _, snippet := range []string{
		"emit_futex_enter_event_v2_direct(",
		"emit_futex_wait_enter_event_v2_direct(",
		"emit_futex_waitv_enter_event_v2_direct(",
		"emit_futex_requeue_enter_event_v2_direct(",
		"bpf_ringbuf_reserve_dynptr(",
		"bpf_ringbuf_submit_dynptr(",
	} {
		if !strings.Contains(emit, snippet) {
			t.Fatalf("futex emit provider missing %q", snippet)
		}
	}
	for _, forbidden := range []string{
		"capture_futex_waitv_waiters_tlv_direct(",
		"capture_futex_requeue_waiters_tlv_direct(",
	} {
		if strings.Contains(facade, forbidden) {
			t.Fatalf("futex facade must not own capture implementation %q", forbidden)
		}
	}
	if strings.Contains(capture, "emit_futex_enter_event_v2_direct(") ||
		strings.Contains(capture, "emit_futex_wait_enter_event_v2_direct(") ||
		strings.Contains(capture, "emit_futex_waitv_enter_event_v2_direct(") ||
		strings.Contains(capture, "emit_futex_requeue_enter_event_v2_direct(") {
		t.Fatal("futex capture provider must not own event emitters")
	}
	if strings.Contains(capture, "bpf_ringbuf_reserve_dynptr(") ||
		strings.Contains(capture, "bpf_ringbuf_submit_dynptr(") {
		t.Fatal("futex capture provider must not own ringbuf lifecycle")
	}
	if strings.Contains(emit, "bpf_probe_read_user(") {
		t.Fatal("futex emit provider must not own user memory reads")
	}
	body, ok := bpfFunctionBody(capture, "capture_futex_waitv_waiters_tlv_direct")
	if !ok {
		t.Fatal("futex capture provider missing waitv composer")
	}
	signature := strings.SplitN(body, "{", 2)[0]
	if strings.Count(signature, ",")+1 > 5 {
		t.Fatalf("futex waitv composer has more than five parameters: %s", signature)
	}

	for name, source := range map[string]string{
		"facade": facade, "capture": capture, "emit": emit,
	} {
		if lines := strings.Count(source, "\n") + 1; lines > 500 {
			t.Fatalf("futex %s provider lines = %d, want <= 500", name, lines)
		}
	}
}
