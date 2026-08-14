package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFFDPathHasDedicatedCaptureAndEmitOwnership(t *testing.T) {
	root := repoRootForTest(t)
	facade := readTextFile(t, filepath.Join(root, "bpf/syscall_fd_path_direct_event_v2.h"))
	capture := readTextFile(t, filepath.Join(root, "bpf/syscall_fd_path_capture_direct_event_v2.h"))
	emit := readTextFile(t, filepath.Join(root, "bpf/syscall_fd_path_emit_direct_event_v2.h"))
	walk := readTextFile(t, filepath.Join(root, "bpf/syscall_fd_path_walk_direct_event_v2.h"))
	fdState := readTextFile(t, filepath.Join(root, "bpf/syscall_fd_state_direct_event_v2.h"))
	enterDispatch := readTextFile(t, filepath.Join(root, "bpf/enter_dispatch.h"))

	for _, include := range []string{
		`#include "syscall_fd_path_capture_direct_event_v2.h"`,
		`#include "syscall_fd_path_emit_direct_event_v2.h"`,
	} {
		if !strings.Contains(facade, include) {
			t.Fatalf("fd path facade missing %q", include)
		}
	}
	if !strings.Contains(capture, `#include "syscall_fd_path_walk_direct_event_v2.h"`) {
		t.Fatal("fd path capture provider must own the walk dependency")
	}

	for _, snippet := range []string{
		"fd_path_arg_mask(",
		"fd_path_arg_count(",
		"fd_path_payload_capacity(",
	} {
		if !strings.Contains(facade, snippet) {
			t.Fatalf("fd path facade missing policy %q", snippet)
		}
	}
	for _, definition := range []string{
		"static __always_inline u32 capture_fd_cwd_path_tlv_direct(",
		"static __always_inline u32 capture_fd_path_tlv_direct(",
		"static __always_inline u32 capture_fd_paths_tlv_direct(",
	} {
		if !strings.Contains(capture, definition) {
			t.Fatalf("fd path capture provider missing %q", definition)
		}
		if strings.Contains(facade, definition) || strings.Contains(emit, definition) {
			t.Fatalf("fd path capture definition leaked into another provider %q", definition)
		}
	}
	for _, definition := range []string{
		"static __always_inline void emit_fd_path_enter_event_v2_direct(",
		"static __always_inline void emit_fd_path_or_no_payload_enter_event_v2_direct(",
	} {
		if !strings.Contains(emit, definition) {
			t.Fatalf("fd path emit provider missing %q", definition)
		}
		if strings.Contains(facade, definition) {
			t.Fatalf("fd path facade still owns emitter %q", definition)
		}
	}

	for _, snippet := range []string{
		"bpf_dynptr_write(",
		"payload_tlv_write_header_direct(",
		"lookup_current_fd_file(",
		"read_dentry_path_direct(",
	} {
		if !strings.Contains(capture, snippet) && !strings.Contains(walk, snippet) &&
			!strings.Contains(fdState, snippet) {
			t.Fatalf("fd path capture chain missing %q", snippet)
		}
	}
	for _, snippet := range []string{
		"bpf_ringbuf_reserve_dynptr(",
		"bpf_ringbuf_submit_dynptr(",
		"capture_fd_paths_tlv_direct(",
	} {
		if !strings.Contains(emit, snippet) {
			t.Fatalf("fd path emit provider missing %q", snippet)
		}
	}
	if strings.Contains(emit, "bpf_probe_read_user(") ||
		strings.Contains(emit, "bpf_probe_read_kernel(") {
		t.Fatal("fd path emit provider must not own kernel/user memory capture")
	}
	if strings.Contains(capture, "bpf_ringbuf_reserve_dynptr(") ||
		strings.Contains(capture, "bpf_ringbuf_submit_dynptr(") {
		t.Fatal("fd path capture provider must not own ringbuf lifecycle")
	}
	if !strings.Contains(enterDispatch,
		"emit_fd_path_or_no_payload_enter_event_v2_direct(pid, tid, ctx, cfg, enter_time);") {
		t.Fatal("enter dispatch must use the five-parameter fd path emitter")
	}
	if strings.Contains(enterDispatch,
		"emit_fd_path_or_no_payload_enter_event_v2_direct(pid, tid, sys_id, ctx, cfg, enter_time);") {
		t.Fatal("enter dispatch still uses the old fd path emitter signature")
	}

	for name, source := range map[string]string{
		"facade":  facade,
		"capture": capture,
		"emit":    emit,
		"walk":    walk,
	} {
		if strings.Count(source, "\n") > 500 {
			t.Fatalf("fd path %s provider exceeds 500 lines", name)
		}
	}
}
