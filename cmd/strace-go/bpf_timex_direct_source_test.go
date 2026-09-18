//go:build amd64 && linux

package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFTimexPayloadsUseDirectTLV(t *testing.T) {
	root := repoRootForTest(t)
	straceSource := readCombinedBPFSources(t)
	legacyCaptureArtifacts := legacyCaptureArtifactsForTest(t)
	timeDirectHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_time_direct_event_v2.h"))
	timexDirectHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_timex_direct_event_v2.h"))

	for _, constant := range []string{
		"#define SYS_ADJTIMEX 159",
		"#define SYS_CLOCK_ADJTIME 305",
	} {
		if !strings.Contains(straceSource, constant) {
			t.Fatalf("strace.c missing timex direct constant %q", constant)
		}
	}

	requiredSource := []string{
		`#include "syscall_timex_direct_event_v2.h"`,
		"is_timex_exit_direct_syscall(p->sys_id)",
		"emit_timex_exit_event_v2_direct(p, ret_value, duration);",
	}
	for _, snippet := range requiredSource {
		if !strings.Contains(straceSource, snippet) {
			t.Fatalf("strace.c missing timex direct path %q", snippet)
		}
	}

	requiredHeader := []string{
		"#define TIME_DIRECT_TIMEX_SIZE 208",
		"return sys_id == SYS_ADJTIMEX || sys_id == SYS_CLOCK_ADJTIME;",
		"is_timex_exit_direct_syscall(sys_id)",
		"bpf_dynptr_data(ptr, data_offset, TIME_DIRECT_TIMEX_SIZE)",
	}
	for _, snippet := range requiredHeader {
		if !strings.Contains(timeDirectHeader, snippet) {
			t.Fatalf("time direct header missing timex snippet %q", snippet)
		}
	}

	requiredTimexHeader := []string{
		"emit_timex_exit_event_v2_direct(",
		"timex_payload_arg_index(p->sys_id)",
	}
	for _, snippet := range requiredTimexHeader {
		if !strings.Contains(timexDirectHeader, snippet) {
			t.Fatalf("timex direct header missing snippet %q", snippet)
		}
	}

	for _, legacyRule := range []string{
		"syscalls: [adjtimex]",
		"syscalls: [clock_adjtime]",
	} {
		if strings.Contains(legacyCaptureArtifacts, legacyRule) {
			t.Fatalf("capture policy still contains old fixed-window rule %q", legacyRule)
		}
	}
}
