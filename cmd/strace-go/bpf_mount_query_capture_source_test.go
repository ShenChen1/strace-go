package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFMountQueryHasDedicatedCaptureAndEmitOwnership(t *testing.T) {
	root := repoRootForTest(t)
	facade := readTextFile(t, filepath.Join(root, "bpf/syscall_mount_query_direct_event_v2.h"))
	capture := readTextFile(t, filepath.Join(root, "bpf/syscall_mount_query_capture_direct_event_v2.h"))
	emit := readTextFile(t, filepath.Join(root, "bpf/syscall_mount_query_emit_direct_event_v2.h"))

	for _, include := range []string{
		`#include "syscall_mount_query_capture_direct_event_v2.h"`,
		`#include "syscall_mount_query_emit_direct_event_v2.h"`,
	} {
		if !strings.Contains(facade, include) {
			t.Fatalf("mount query facade missing %q", include)
		}
	}
	for _, snippet := range []string{
		"capture_mnt_id_req_enter_tlv_direct(",
		"capture_statmount_exit_tlv_direct(",
		"capture_listmount_ids_tlv_direct(",
		"bpf_probe_read_user(&value, sizeof(value)",
	} {
		if !strings.Contains(capture, snippet) {
			t.Fatalf("mount query capture module missing %q", snippet)
		}
	}
	for _, snippet := range []string{
		"emit_mount_query_exit_event_v2_direct(",
		"bpf_ringbuf_reserve_dynptr(&events",
		"init_syscall_exit_event_v2_from_pending(",
	} {
		if !strings.Contains(emit, snippet) {
			t.Fatalf("mount query emit module missing %q", snippet)
		}
	}
	for _, snippet := range []string{
		"static __always_inline u32 capture_mnt_id_req_enter_tlv_direct(",
		"static __always_inline u32 capture_statmount_exit_tlv_direct(",
	} {
		if strings.Contains(facade, snippet) || strings.Contains(emit, snippet) {
			t.Fatalf("mount query capture implementation has the wrong owner %q", snippet)
		}
	}
	if strings.Contains(facade, "static __always_inline void emit_mount_query_exit_event_v2_direct(") ||
		strings.Contains(capture, "static __always_inline void emit_mount_query_exit_event_v2_direct(") {
		t.Fatal("mount query emitter implementation has the wrong owner")
	}

	for name, source := range map[string]string{
		"syscall_mount_query_direct_event_v2.h":         facade,
		"syscall_mount_query_capture_direct_event_v2.h": capture,
		"syscall_mount_query_emit_direct_event_v2.h":    emit,
	} {
		if lines := strings.Count(source, "\n") + 1; lines > 500 {
			t.Fatalf("bpf/%s lines = %d, want <= 500", name, lines)
		}
	}
}
