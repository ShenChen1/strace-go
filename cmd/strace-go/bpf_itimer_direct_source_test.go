package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFItimerPayloadsUseDirectTLV(t *testing.T) {
	root := repoRootForTest(t)
	straceSource := readCombinedBPFSources(t)
	legacyCaptureArtifacts := legacyCaptureArtifactsForTest(t)
	timeDirectHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_time_direct_event_v2.h"))

	for _, constant := range []string{
		"#define SYS_GETITIMER 36",
		"#define SYS_SETITIMER 38",
	} {
		if !strings.Contains(straceSource, constant) {
			t.Fatalf("strace.c missing itimer direct constant %q", constant)
		}
	}

	requiredSource := []string{
		"is_itimer_enter_direct_syscall(sys_id)",
		"emit_itimer_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);",
		"is_itimer_exit_direct_syscall(p->sys_id) && ret_value >= 0",
		"emit_itimer_exit_event_v2_direct(p, ret_value, duration);",
	}
	for _, snippet := range requiredSource {
		if !strings.Contains(straceSource, snippet) {
			t.Fatalf("strace.c missing itimer direct path %q", snippet)
		}
	}

	requiredHeader := []string{
		"TIME_DIRECT_ITIMERVAL_SIZE 32",
		"return sys_id == SYS_GETITIMER || sys_id == SYS_SETITIMER;",
		"return sys_id == SYS_SETITIMER;",
		"bpf_dynptr_data(ptr, data_offset, TIME_DIRECT_ITIMERVAL_SIZE)",
		"capture_time_struct_tlv_direct_from_ptr(",
		"ctx->args[1]",
		"p->sys_id == SYS_SETITIMER",
		"PAYLOAD_TLV_KIND_STRUCT",
		"PAYLOAD_TLV_FLAG_DIRECTION_OUT",
	}
	for _, snippet := range requiredHeader {
		if !strings.Contains(timeDirectHeader, snippet) {
			t.Fatalf("time direct header missing itimer snippet %q", snippet)
		}
	}

	for _, legacyRule := range []string{
		"syscalls: [getitimer]",
		"syscalls: [setitimer]",
	} {
		if strings.Contains(legacyCaptureArtifacts, legacyRule) {
			t.Fatalf("capture policy still contains old fixed-window rule %q", legacyRule)
		}
	}
}
