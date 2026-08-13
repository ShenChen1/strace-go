package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFAioCancelCaptureHasDedicatedOwnership(t *testing.T) {
	root := repoRootForTest(t)
	facade := readTextFile(t, filepath.Join(root, "bpf/syscall_aio_direct_event_v2.h"))
	capture := readTextFile(t, filepath.Join(root, "bpf/syscall_aio_cancel_capture_direct_event_v2.h"))
	emit := readTextFile(t, filepath.Join(root, "bpf/syscall_aio_emit_direct_event_v2.h"))

	if !strings.Contains(facade, `#include "syscall_aio_cancel_capture_direct_event_v2.h"`) {
		t.Fatal("AIO facade missing dedicated cancel capture include")
	}
	for _, snippet := range []string{
		"static __always_inline u32 capture_aio_cancel_iocb_tlv_direct(",
		"bpf_probe_read_user(payload_data, AIO_CANCEL_DIRECT_IOCB_SIZE",
		"PAYLOAD_TLV_KIND_STRUCT",
		"AIO_CANCEL_DIRECT_IOCB_SIZE",
		"            1,\n            0,",
	} {
		if !strings.Contains(capture, snippet) {
			t.Fatalf("AIO cancel capture module missing %q", snippet)
		}
	}
	for _, snippet := range []string{
		"emit_aio_cancel_enter_event_v2_direct(",
		"capture_aio_cancel_iocb_tlv_direct(",
		"bpf_ringbuf_reserve_dynptr(&events",
	} {
		if !strings.Contains(emit, snippet) {
			t.Fatalf("AIO emit module missing %q", snippet)
		}
	}
	if strings.Contains(emit, "static __always_inline u32 capture_aio_cancel_iocb_tlv_direct(") {
		t.Fatal("AIO cancel capture implementation has the wrong owner")
	}

	for name, source := range map[string]string{
		"syscall_aio_direct_event_v2.h":                facade,
		"syscall_aio_cancel_capture_direct_event_v2.h": capture,
		"syscall_aio_emit_direct_event_v2.h":           emit,
	} {
		if lines := strings.Count(source, "\n") + 1; lines > 500 {
			t.Fatalf("bpf/%s lines = %d, want <= 500", name, lines)
		}
	}
}
