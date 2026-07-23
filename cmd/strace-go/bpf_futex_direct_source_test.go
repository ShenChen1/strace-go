package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFFutexPayloadUsesDirectTLV(t *testing.T) {
	root := repoRootForTest(t)
	straceSource := readTextFile(t, filepath.Join(root, "bpf/strace.c"))
	legacyCaptureArtifacts := legacyCaptureArtifactsForTest(t)
	timeDirectHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_time_direct_event_v2.h"))
	futexDirectHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_futex_direct_event_v2.h"))

	for _, snippet := range []string{
		"#define SYS_FUTEX 202",
		"#define SYS_FUTEX_WAITV 449",
		"#define SYS_FUTEX_WAIT 455",
		"#define SYS_FUTEX_REQUEUE 456",
		`#include "syscall_futex_direct_event_v2.h"`,
		"sys_id == SYS_FUTEX",
		"sys_id == SYS_FUTEX_WAITV",
		"sys_id == SYS_FUTEX_WAIT",
		"sys_id == SYS_FUTEX_REQUEUE",
		"emit_futex_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);",
		"emit_futex_waitv_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);",
		"emit_futex_wait_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);",
		"emit_futex_requeue_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);",
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
		"FUTEX_DIRECT_WAITV_MAX_BYTES 3072",
		"capture_futex_waitv_waiters_tlv_direct(",
		"(u32)ctx->args[1]",
		"emit_futex_waitv_enter_event_v2_direct(",
		"FUTEX_DIRECT_REQUEUE_WAITERS_SIZE 48",
		"capture_futex_requeue_waiters_tlv_direct(",
		"emit_futex_requeue_enter_event_v2_direct(",
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
		"syscalls: [futex_waitv]",
		"syscalls: [futex_requeue]",
		"case 202: /* futex */",
		"case 455: /* futex_wait */",
		"case 449: /* futex_waitv */",
		"case 456: /* futex_requeue */",
	} {
		if strings.Contains(legacyCaptureArtifacts, legacyRule) {
			t.Fatalf("futex still uses old fixed-window rule %q", legacyRule)
		}
	}
}
