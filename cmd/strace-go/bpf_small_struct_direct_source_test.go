package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFSmallStructPayloadsUseDirectTLV(t *testing.T) {
	root := repoRootForTest(t)
	straceSource := readCombinedBPFSources(t)
	legacyCaptureArtifacts := legacyCaptureArtifactsForTest(t)
	timeDirectHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_time_direct_event_v2.h"))
	smallDirectHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_small_struct_direct_event_v2.h")) +
		"\n" + readTextFile(t, filepath.Join(root, "bpf/syscall_small_struct_capture_direct_event_v2.h")) +
		"\n" + readTextFile(t, filepath.Join(root, "bpf/syscall_small_struct_emit_direct_event_v2.h"))

	for _, constant := range []string{
		"#define SYS_SENDFILE 40",
		"#define SYS_ARCH_PRCTL 158",
		"#define SYS_GET_ROBUST_LIST 274",
		"#define SYS_COPY_FILE_RANGE 326",
	} {
		if !strings.Contains(straceSource, constant) {
			t.Fatalf("strace.c missing small struct direct constant %q", constant)
		}
	}

	requiredSource := []string{
		`#include "syscall_small_struct_direct_event_v2.h"`,
		"emit_small_struct_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);",
		"is_small_struct_direct_syscall(sys_id)",
		"is_small_struct_exit_direct_syscall(p->sys_id) && ret_value >= 0",
		"emit_small_struct_exit_event_v2_direct(p, ret_value, duration);",
	}
	for _, snippet := range requiredSource {
		if !strings.Contains(straceSource, snippet) {
			t.Fatalf("strace.c missing small struct direct path %q", snippet)
		}
	}

	requiredHeader := []string{
		"SMALL_STRUCT_DIRECT_WORD_SIZE 8",
		"return sys_id == SYS_SENDFILE || sys_id == SYS_ARCH_PRCTL ||",
		"sys_id == SYS_GET_ROBUST_LIST || sys_id == SYS_COPY_FILE_RANGE;",
		"return sys_id == SYS_SENDFILE || sys_id == SYS_COPY_FILE_RANGE;",
		"return sys_id == SYS_SENDFILE || sys_id == SYS_ARCH_PRCTL ||",
		"PAYLOAD_TLV_KIND_STRUCT",
		"PAYLOAD_TLV_FLAG_DIRECTION_OUT",
		"payload_offset,\n        2,\n        ctx->args[2]",
		"payload_offset, 1, ctx->args[1]",
		"payload_offset + payload_size, 3, ctx->args[3]",
		"is_arch_prctl_get_direct_option(p->args[0])",
	}
	for _, snippet := range requiredHeader {
		if !strings.Contains(smallDirectHeader, snippet) {
			t.Fatalf("small struct direct header missing %q", snippet)
		}
	}

	if !strings.Contains(timeDirectHeader, "is_small_struct_direct_syscall(sys_id)") {
		t.Fatal("sys_exit direct classifier should include small struct syscalls")
	}
	for _, legacyRule := range []string{
		"syscalls: [sendfile]",
		"syscalls: [copy_file_range]",
		"syscalls: [arch_prctl]",
		"syscalls: [get_robust_list]",
	} {
		if strings.Contains(legacyCaptureArtifacts, legacyRule) {
			t.Fatalf("capture policy still contains old fixed-window rule %q", legacyRule)
		}
	}
}
