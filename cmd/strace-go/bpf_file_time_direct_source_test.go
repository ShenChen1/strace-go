package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFFileTimePayloadsUseDirectTLV(t *testing.T) {
	root := repoRootForTest(t)
	straceSource := readTextFile(t, filepath.Join(root, "bpf/strace.c"))
	timeDirectHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_time_direct_event_v2.h"))
	fileTimeDirectHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_file_time_direct_event_v2.h"))
	capturePolicy := readTextFile(t, filepath.Join(root, "cmd/generate-syscalls/capture_rules.yaml"))
	generatedCapture := readTextFile(t, filepath.Join(root, "bpf/syscall_capture.h"))

	for _, snippet := range []string{
		"#define SYS_UTIME 132",
		"#define SYS_UTIMES 235",
		"#define SYS_FUTIMESAT 261",
		"#define SYS_UTIMENSAT 280",
		`#include "syscall_file_time_direct_event_v2.h"`,
		"is_file_time_direct_syscall(sys_id)",
		"emit_file_time_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);",
	} {
		if !strings.Contains(straceSource, snippet) {
			t.Fatalf("BPF source missing file-time direct snippet %q", snippet)
		}
	}

	if !strings.Contains(timeDirectHeader, "is_file_time_direct_syscall(sys_id)") {
		t.Fatal("time direct exit classification should include file-time direct syscalls")
	}

	for _, snippet := range []string{
		"FILE_TIME_DIRECT_UTIMBUF_SIZE 16",
		"FILE_TIME_DIRECT_TIMEVALS_SIZE 32",
		"is_file_time_direct_syscall(",
		"capture_file_time_value_tlv_direct(",
		"capture_file_time_payloads_tlv_direct(",
		"emit_file_time_enter_event_v2_direct(",
		"capture_path_stat_path_tlv_direct",
		"PAYLOAD_TLV_KIND_STRUCT",
		"bpf_probe_read_user(payload_data, FILE_TIME_DIRECT_UTIMBUF_SIZE",
		"bpf_probe_read_user(payload_data, FILE_TIME_DIRECT_TIMEVALS_SIZE",
		"init_syscall_enter_event_v2_from_ctx(&body, ctx, 0, 0, -1, -1);",
		"body.capture_len = payload_size;",
	} {
		if !strings.Contains(fileTimeDirectHeader, snippet) {
			t.Fatalf("file-time direct header missing snippet %q", snippet)
		}
	}

	for _, legacyRule := range []string{
		"syscalls: [utime]",
		"syscalls: [utimes]",
		"syscalls: [futimesat]",
		"syscalls: [utimensat]",
		"case 132: /* utime */",
		"case 235: /* utimes */",
		"case 261: /* futimesat */",
		"case 280: /* utimensat */",
	} {
		if strings.Contains(capturePolicy, legacyRule) || strings.Contains(generatedCapture, legacyRule) {
			t.Fatalf("file-time syscall still uses old fixed-window rule %q", legacyRule)
		}
	}
}
