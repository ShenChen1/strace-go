package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFFutexPayloadUsesDirectTLV(t *testing.T) {
	root := repoRootForTest(t)
	straceSource := readTextFile(t, filepath.Join(root, "bpf/strace.c"))
	timeDirectHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_time_direct_event_v2.h"))
	futexDirectHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_futex_direct_event_v2.h"))
	capturePolicy := readTextFile(t, filepath.Join(root, "cmd/generate-syscalls/capture_rules.yaml"))
	generatedCapture := readTextFile(t, filepath.Join(root, "bpf/syscall_capture.h"))

	for _, snippet := range []string{
		"#define SYS_FUTEX 202",
		"#define SYS_FUTEX_WAIT 455",
		`#include "syscall_futex_direct_event_v2.h"`,
		"sys_id == SYS_FUTEX",
		"sys_id == SYS_FUTEX_WAIT",
		"emit_futex_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);",
		"emit_futex_wait_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);",
		"is_futex_direct_syscall(sys_id)",
	} {
		if !strings.Contains(straceSource, snippet) && !strings.Contains(timeDirectHeader, snippet) {
			t.Fatalf("BPF source missing futex direct snippet %q", snippet)
		}
	}

	for _, snippet := range []string{
		"futex_has_timeout_direct(ctx->args[1])",
		"FUTEX_DIRECT_WAIT_BITSET",
		"FUTEX_DIRECT_LOCK_PI2",
		"capture_time_struct_tlv_direct_from_ptr(",
		"ctx->args[3]",
		"ctx->args[4]",
		"TIME_DIRECT_TIMESPEC_SIZE",
		"emit_futex_wait_enter_event_v2_direct(",
		"init_syscall_enter_event_v2_from_ctx(&body, ctx, payload_size, 0, -1, -1);",
	} {
		if !strings.Contains(futexDirectHeader, snippet) {
			t.Fatalf("futex direct header missing snippet %q", snippet)
		}
	}
	if strings.Contains(futexDirectHeader, "FUTEX_DIRECT_FD") {
		t.Fatalf("futex direct header must not treat FUTEX_FD as a timeout op")
	}

	for _, legacyRule := range []string{
		"syscalls: [futex]",
		"syscalls: [futex_wait]",
		"case 202: /* futex */",
		"case 455: /* futex_wait */",
	} {
		if strings.Contains(capturePolicy, legacyRule) || strings.Contains(generatedCapture, legacyRule) {
			t.Fatalf("futex still uses old fixed-window rule %q", legacyRule)
		}
	}
}
