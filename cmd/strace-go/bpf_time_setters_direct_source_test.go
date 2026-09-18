//go:build amd64 && linux

package main

import (
	"strings"
	"testing"
)

func TestBPFTimeSetterPayloadsUseDirectTLV(t *testing.T) {
	straceSource := readCombinedBPFSources(t)
	legacyCaptureArtifacts := legacyCaptureArtifactsForTest(t)
	timeDirectHeader := readTimeDirectEventSources(t)

	for _, constant := range []string{
		"#define SYS_SETTIMEOFDAY 164",
		"#define SYS_CLOCK_SETTIME 227",
	} {
		if !strings.Contains(straceSource, constant) {
			t.Fatalf("strace.c missing time setter direct constant %q", constant)
		}
	}

	requiredSource := []string{
		"is_time_struct_enter_direct_syscall(sys_id)",
		"emit_time_struct_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);",
	}
	for _, snippet := range requiredSource {
		if !strings.Contains(straceSource, snippet) {
			t.Fatalf("strace.c missing time setter direct path %q", snippet)
		}
	}

	requiredHeader := []string{
		"return sys_id == SYS_SETTIMEOFDAY;",
		"return sys_id == SYS_CLOCK_SETTIME;",
		"is_time_struct_enter_direct_syscall(sys_id)",
		"emit_time_struct_enter_event_v2_direct(",
		"sys_id == SYS_SETTIMEOFDAY",
		"ctx->args[0]",
		"ctx->args[1]",
		"TIME_DIRECT_TIMEZONE_SIZE",
		"PAYLOAD_TLV_KIND_STRUCT",
	}
	for _, snippet := range requiredHeader {
		if !strings.Contains(timeDirectHeader, snippet) {
			t.Fatalf("time direct header missing setter snippet %q", snippet)
		}
	}

	for _, legacyRule := range []string{
		"syscalls: [clock_settime]",
		"syscalls: [settimeofday]",
	} {
		if strings.Contains(legacyCaptureArtifacts, legacyRule) {
			t.Fatalf("capture policy still contains old fixed-window rule %q", legacyRule)
		}
	}
}
