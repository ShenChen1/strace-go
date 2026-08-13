package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFTimeEmittersHaveDedicatedOwnership(t *testing.T) {
	root := repoRootForTest(t)
	base := readTextFile(t, filepath.Join(root, "bpf/syscall_time_direct_event_v2.h"))
	emit := readTextFile(t, filepath.Join(root, "bpf/syscall_time_emit_direct_event_v2.h"))

	for _, name := range []string{
		"emit_time_struct_exit_event_v2_direct",
		"emit_time_struct_enter_event_v2_direct",
		"emit_itimer_enter_event_v2_direct",
		"emit_itimer_exit_event_v2_direct",
		"emit_gettimeofday_exit_event_v2_direct",
	} {
		signature := "static __always_inline void " + name + "("
		if !strings.Contains(emit, signature) {
			t.Fatalf("time emit module missing emitter %q", name)
		}
		if strings.Contains(base, signature) {
			t.Fatalf("time base module must not own emitter %q", name)
		}
	}

	if !strings.Contains(base, `#include "syscall_time_emit_direct_event_v2.h"`) {
		t.Fatal("time base module must include the time emit module")
	}
	for _, snippet := range []string{
		"capture_time_struct_tlv_direct_from_ptr(",
		"capture_time_struct_tlv_direct(",
		"TIME_DIRECT_TIMEX_SIZE 208",
	} {
		if !strings.Contains(base, snippet) {
			t.Fatalf("time base module missing shared helper %q", snippet)
		}
	}
	for _, snippet := range []string{
		"init_syscall_exit_event_v2_from_pending(",
		"init_syscall_enter_event_v2_from_ctx(",
		"bpf_ringbuf_submit_dynptr(&ptr, 0);",
	} {
		if !strings.Contains(emit, snippet) {
			t.Fatalf("time emit module missing event emission contract %q", snippet)
		}
	}
}

func TestBPFTimeModulesStayWithinFileLimit(t *testing.T) {
	root := repoRootForTest(t)
	for _, name := range []string{
		"syscall_time_direct_event_v2.h",
		"syscall_time_emit_direct_event_v2.h",
	} {
		source := readTextFile(t, filepath.Join(root, "bpf", name))
		if lines := strings.Count(source, "\n") + 1; lines > 500 {
			t.Fatalf("bpf/%s lines = %d, want <= 500", name, lines)
		}
	}
}
