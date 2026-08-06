package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFFSPayloadsUseDirectTLV(t *testing.T) {
	root := repoRootForTest(t)
	straceSource := readTextFile(t, filepath.Join(root, "bpf/strace.c"))
	legacyCaptureArtifacts := legacyCaptureArtifactsForTest(t)
	timeDirectHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_time_direct_event_v2.h"))
	fsDirectHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_fs_direct_event_v2.h"))

	for _, snippet := range []string{
		"#define SYS_MOUNT 165",
		"#define SYS_UMOUNT2 166",
		"#define SYS_GETDENTS64 217",
		"#define SYS_FSCONFIG 431",
		`#include "syscall_fs_direct_event_v2.h"`,
		"is_fs_enter_direct_syscall(sys_id)",
		"emit_fs_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);",
		"is_getdents64_direct_syscall(p->sys_id) && ret_value > 0",
		"emit_getdents64_exit_event_v2_direct(p, ret_value, duration);",
		"is_fs_direct_syscall(sys_id) ||",
	} {
		if !strings.Contains(straceSource, snippet) && !strings.Contains(timeDirectHeader, snippet) && !strings.Contains(fsDirectHeader, snippet) {
			t.Fatalf("BPF source missing fs direct snippet %q", snippet)
		}
	}

	for _, snippet := range []string{
		"FS_DIRECT_MOUNT_STRING_MAX 512",
		"FS_DIRECT_MOUNT_TYPE_MAX 128",
		"FS_DIRECT_FSCONFIG_KEY_MAX 257",
		"FS_DIRECT_FSCONFIG_VALUE_MAX 4096",
		"FS_DIRECT_GETDENTS64_BYTES_MAX 512",
		"FS_DIRECT_FSCONFIG_SET_BINARY 2",
		"is_fs_enter_direct_syscall(",
		"is_fs_direct_syscall(",
		"is_getdents64_direct_syscall(",
		"capture_fs_string_tlv_direct(",
		"capture_fs_bytes_tlv_direct(",
		"capture_fs_enter_payload_tlv_direct(",
		"capture_getdents64_bytes_tlv_direct(",
		"emit_getdents64_exit_event_v2_direct(",
		"((u32)ctx->args[1]) == FS_DIRECT_FSCONFIG_SET_BINARY",
		"PAYLOAD_TLV_KIND_STRING",
		"PAYLOAD_TLV_KIND_BYTES",
		"PAYLOAD_TLV_FLAG_DIRECTION_OUT",
		"bpf_probe_read_user_str(payload_data, max_len",
		"bpf_probe_read_user(payload_data, copied_len",
	} {
		if !strings.Contains(fsDirectHeader, snippet) {
			t.Fatalf("fs direct header missing snippet %q", snippet)
		}
	}

	for _, legacyRule := range []string{
		"syscalls: [mount]",
		"syscalls: [umount2]",
		"syscalls: [getdents64]",
		"syscalls: [fsconfig]",
		"case 165: /* mount */",
		"case 166: /* umount2 */",
		"case 217: /* getdents64 */",
		"case 431: /* fsconfig */",
	} {
		if strings.Contains(legacyCaptureArtifacts, legacyRule) {
			t.Fatalf("fs syscall still uses old fixed-window rule %q", legacyRule)
		}
	}
}
