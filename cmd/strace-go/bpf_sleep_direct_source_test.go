package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFSleepPayloadsUseDirectTLV(t *testing.T) {
	root := repoRootForTest(t)
	straceSource := readTextFile(t, filepath.Join(root, "bpf/strace.c"))
	legacyCaptureArtifacts := legacyCaptureArtifactsForTest(t)
	timeDirectHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_time_direct_event_v2.h"))
	sleepDirectHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_sleep_direct_event_v2.h"))

	for _, constant := range []string{
		"volatile const u32 SYS_NANOSLEEP = 35;",
		"#define SYS_CLOCK_NANOSLEEP 230",
	} {
		if !strings.Contains(straceSource, constant) {
			t.Fatalf("strace.c missing sleep direct constant %q", constant)
		}
	}

	requiredSource := []string{
		`#include "syscall_sleep_direct_event_v2.h"`,
		"sys_id == SYS_NANOSLEEP",
		"emit_sleep_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time, 0, ctx->args[0], -1);",
		"should_emit_nanosleep_suspended_marker(tid, pid)",
		"emit_sleep_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time, 0, ctx->args[0], 3);",
		"sys_id == SYS_CLOCK_NANOSLEEP",
		"emit_sleep_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time, 2, ctx->args[2], -1);",
		"is_sleep_direct_syscall(p->sys_id)",
		"emit_sleep_exit_event_v2_direct(p, ret_value, duration);",
	}
	for _, snippet := range requiredSource {
		if !strings.Contains(straceSource, snippet) {
			t.Fatalf("strace.c missing sleep direct path %q", snippet)
		}
	}

	requiredHeader := []string{
		"return sys_id == SYS_NANOSLEEP || sys_id == SYS_CLOCK_NANOSLEEP;",
		"is_sleep_direct_syscall(sys_id)",
		"PAYLOAD_TLV_KIND_STRUCT",
		"PAYLOAD_TLV_FLAG_DIRECTION_OUT",
	}
	for _, snippet := range requiredHeader {
		if !strings.Contains(timeDirectHeader, snippet) {
			t.Fatalf("time direct header missing sleep snippet %q", snippet)
		}
	}

	requiredSleepHeader := []string{
		"sleep_request_arg_index(u32 sys_id)",
		"return 2;",
		"sleep_remaining_arg_index(u32 sys_id)",
		"return 3;",
		"ret_value == -516 || ret_value == -4",
		"capture_time_struct_tlv_direct_from_ptr(",
		"sleep_remaining_user_ptr(p)",
		"init_syscall_enter_event_v2_from_ctx(&body, ctx, payload_size, 0, probe_ret_enter, -1);",
		"should_emit_nanosleep_suspended_marker(",
	}
	for _, snippet := range requiredSleepHeader {
		if !strings.Contains(sleepDirectHeader, snippet) {
			t.Fatalf("sleep direct header missing snippet %q", snippet)
		}
	}

	for _, legacyRule := range []string{
		"syscalls: [nanosleep]",
		"syscalls: [clock_nanosleep]",
		"case 35: /* nanosleep */",
		"case 230: /* clock_nanosleep */",
	} {
		if strings.Contains(legacyCaptureArtifacts, legacyRule) {
			t.Fatalf("sleep still uses old fixed-window rule %q", legacyRule)
		}
	}
}
