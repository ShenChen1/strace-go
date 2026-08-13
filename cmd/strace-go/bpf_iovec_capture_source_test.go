package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFIovecCaptureHasDedicatedOwnership(t *testing.T) {
	root := repoRootForTest(t)
	capture := readTextFile(t, filepath.Join(root, "bpf/syscall_iovec_capture_direct_event_v2.h"))
	direct := readTextFile(t, filepath.Join(root, "bpf/syscall_iovec_direct_event_v2.h"))

	for _, snippet := range []string{
		"#ifndef STRACE_GO_SYSCALL_IOVEC_CAPTURE_DIRECT_EVENT_V2_H",
		"#define IOVEC_DIRECT_ELEM_SIZE 16",
		"capture_iovec_tlv_direct(",
		"capture_iovec_base_tlv_direct(",
		"capture_iovec_base_payloads_tlv_direct_for_arg(",
		"capture_iovec_payloads_tlv_direct(",
		"bpf_probe_read_user(&iov_data, IOVEC_DIRECT_ELEM_SIZE",
		"PAYLOAD_TLV_KIND_IOVEC",
	} {
		if !strings.Contains(capture, snippet) {
			t.Fatalf("iovec capture module missing %q", snippet)
		}
	}

	if !strings.Contains(direct, `#include "syscall_iovec_capture_direct_event_v2.h"`) {
		t.Fatal("iovec direct facade must include the capture module")
	}
	for _, snippet := range []string{
		"static __always_inline u32 capture_iovec_tlv_direct(",
		"static __always_inline u32 capture_iovec_base_tlv_direct(",
		"static __always_inline u32 capture_iovec_payloads_tlv_direct(",
	} {
		if strings.Contains(direct, snippet) {
			t.Fatalf("iovec direct facade must not own capture implementation %q", snippet)
		}
	}
	for _, snippet := range []string{
		"static __noinline void emit_iovec_enter_event_v2_direct(",
		"static __noinline void emit_iovec_base_enter_event_v2_direct(",
	} {
		if !strings.Contains(direct, snippet) {
			t.Fatalf("iovec direct facade missing emitter %q", snippet)
		}
		if strings.Contains(capture, snippet) {
			t.Fatalf("iovec capture module must not own emitter %q", snippet)
		}
	}

	for name, source := range map[string]string{
		"syscall_iovec_capture_direct_event_v2.h": capture,
		"syscall_iovec_direct_event_v2.h":         direct,
	} {
		if lines := strings.Count(source, "\n") + 1; lines > 500 {
			t.Fatalf("bpf/%s lines = %d, want <= 500", name, lines)
		}
	}
}
