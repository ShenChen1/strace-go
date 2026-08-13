package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFAioGeteventsHasDedicatedCaptureAndEmitOwnership(t *testing.T) {
	root := repoRootForTest(t)
	facade := readTextFile(t, filepath.Join(root, "bpf/syscall_aio_getevents_direct_event_v2.h"))
	capture := readTextFile(t, filepath.Join(root, "bpf/syscall_aio_getevents_capture_direct_event_v2.h"))
	emit := readTextFile(t, filepath.Join(root, "bpf/syscall_aio_getevents_emit_direct_event_v2.h"))

	for _, include := range []string{
		`#include "syscall_aio_getevents_capture_direct_event_v2.h"`,
		`#include "syscall_aio_getevents_emit_direct_event_v2.h"`,
	} {
		if !strings.Contains(facade, include) {
			t.Fatalf("AIO getevents facade missing %q", include)
		}
	}
	for _, snippet := range []string{
		"capture_aio_getevents_timeout_tlv_direct(",
		"capture_aio_getevents_events_tlv_direct(",
		"capture_aio_pgetevents_sigset_tlv_direct(",
		"capture_aio_pgetevents_sigmask_tlv_direct(",
		"bpf_probe_read_user(&event_data, AIO_GETEVENTS_DIRECT_EVENT_SIZE",
	} {
		if !strings.Contains(capture, snippet) {
			t.Fatalf("AIO getevents capture module missing %q", snippet)
		}
	}
	for _, snippet := range []string{
		"emit_aio_getevents_enter_event_v2_direct(",
		"emit_aio_pgetevents_enter_event_v2_direct(",
		"emit_aio_getevents_exit_event_v2_direct(",
		"bpf_ringbuf_reserve_dynptr(&events",
	} {
		if !strings.Contains(emit, snippet) {
			t.Fatalf("AIO getevents emit module missing %q", snippet)
		}
	}
	for _, snippet := range []string{
		"static __always_inline u32 capture_aio_getevents_timeout_tlv_direct(",
		"static __always_inline u32 capture_aio_getevents_events_tlv_direct(",
	} {
		if strings.Contains(facade, snippet) || strings.Contains(emit, snippet) {
			t.Fatalf("AIO getevents capture implementation has the wrong owner %q", snippet)
		}
	}
	for _, snippet := range []string{
		"static __always_inline void emit_aio_getevents_enter_event_v2_direct(",
		"static __always_inline void emit_aio_pgetevents_enter_event_v2_direct(",
	} {
		if strings.Contains(facade, snippet) || strings.Contains(capture, snippet) {
			t.Fatalf("AIO getevents emitter implementation has the wrong owner %q", snippet)
		}
	}

	for name, source := range map[string]string{
		"syscall_aio_getevents_direct_event_v2.h":         facade,
		"syscall_aio_getevents_capture_direct_event_v2.h": capture,
		"syscall_aio_getevents_emit_direct_event_v2.h":    emit,
	} {
		if lines := strings.Count(source, "\n") + 1; lines > 500 {
			t.Fatalf("bpf/%s lines = %d, want <= 500", name, lines)
		}
	}
}
