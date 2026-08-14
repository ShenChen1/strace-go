package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFEpollHasDedicatedCaptureAndEmitOwnership(t *testing.T) {
	root := repoRootForTest(t)
	facade := readTextFile(t, filepath.Join(root, "bpf/syscall_epoll_direct_event_v2.h"))
	capture := readTextFile(t, filepath.Join(root, "bpf/syscall_epoll_capture_direct_event_v2.h"))
	emit := readTextFile(t, filepath.Join(root, "bpf/syscall_epoll_emit_direct_event_v2.h"))

	for _, include := range []string{
		`#include "syscall_epoll_capture_direct_event_v2.h"`,
		`#include "syscall_epoll_emit_direct_event_v2.h"`,
	} {
		if !strings.Contains(facade, include) {
			t.Fatalf("epoll facade missing %q", include)
		}
	}
	for _, snippet := range []string{
		"capture_epoll_events_tlv_direct(",
		"capture_epoll_timeout_tlv_direct(",
		"capture_epoll_ctl_event_tlv_direct(",
		"bpf_probe_read_user(payload_data, EPOLL_DIRECT_TIMEOUT_SIZE",
		"bpf_probe_read_user(&event_data, EPOLL_DIRECT_EVENT_SIZE",
	} {
		if !strings.Contains(capture, snippet) {
			t.Fatalf("epoll capture module missing %q", snippet)
		}
	}
	for _, snippet := range []string{
		"emit_epoll_ctl_enter_event_v2_direct(",
		"emit_epoll_pwait2_enter_event_v2_direct(",
		"emit_epoll_wait_exit_event_v2_direct(",
		"bpf_ringbuf_reserve_dynptr(&events",
		"init_syscall_enter_event_v2_from_args(",
		"init_syscall_exit_event_v2_from_pending(",
	} {
		if !strings.Contains(emit, snippet) {
			t.Fatalf("epoll emit module missing %q", snippet)
		}
	}
	for _, snippet := range []string{
		"static __always_inline u32 capture_epoll_events_tlv_direct(",
		"static __always_inline void emit_epoll_ctl_enter_event_v2_direct(",
	} {
		if strings.Contains(facade, snippet) {
			t.Fatalf("epoll facade owns implementation %q", snippet)
		}
	}
	if strings.Contains(emit, "static __always_inline u32 capture_epoll_events_tlv_direct(") {
		t.Fatal("epoll emit module owns capture implementation")
	}

	for name, source := range map[string]string{
		"syscall_epoll_direct_event_v2.h":         facade,
		"syscall_epoll_capture_direct_event_v2.h": capture,
		"syscall_epoll_emit_direct_event_v2.h":    emit,
	} {
		if lines := strings.Count(source, "\n") + 1; lines > 500 {
			t.Fatalf("bpf/%s lines = %d, want <= 500", name, lines)
		}
	}
}
