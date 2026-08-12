package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFPathOnlyPayloadsUseDirectTLV(t *testing.T) {
	root := repoRootForTest(t)
	straceSource := readCombinedBPFSources(t)
	legacyCaptureArtifacts := legacyCaptureArtifactsForTest(t)
	pathDirectHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_path_direct_event_v2.h"))

	for _, snippet := range []string{
		"#define SYS_CHDIR 80",
		"#define SYS_MKDIR 83",
		"#define SYS_MKDIRAT 258",
		`#include "syscall_path_direct_event_v2.h"`,
		"is_path_only_direct_syscall(sys_id)",
		"emit_path_only_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);",
		"emit_path_only_exit_event_v2_direct(p, ret_value, duration);",
		"EXIT_PROG_PATH = 10",
		"is_path_only_direct_syscall(p->sys_id)",
	} {
		if !strings.Contains(straceSource, snippet) {
			t.Fatalf("BPF source missing path direct snippet %q", snippet)
		}
	}

	for _, snippet := range []string{
		"PATH_ONLY_DIRECT_PATH_MAX 4096",
		"PATH_ONLY_DIRECT_FIRST_CHUNK 2048",
		"PATH_ONLY_DIRECT_SECOND_CHUNK 2049",
		"is_path_only_arg0_direct_syscall(",
		"sys_id == SYS_CHDIR",
		"is_path_only_arg1_direct_syscall(",
		"capture_path_only_tlv_direct(",
		"emit_path_only_enter_event_v2_direct(",
		"emit_path_only_exit_event_v2_direct(",
		"PAYLOAD_TLV_KIND_STRING",
		"bpf_probe_read_user_str(payload_data, PATH_ONLY_DIRECT_FIRST_CHUNK",
		"user_ptr + PATH_ONLY_DIRECT_FIRST_CHUNK - 1",
		"init_syscall_enter_event_v2_from_ctx(&body, ctx, 0, 0, -1, -1);",
		"body.capture_len = payload_size;",
	} {
		if !strings.Contains(pathDirectHeader, snippet) {
			t.Fatalf("path direct header missing snippet %q", snippet)
		}
	}

	for _, legacyRule := range []string{
		"syscalls: [chdir]",
		"syscalls: [access, chdir, chroot, chmod, chown, lchown, mkdir, mknod, rmdir, unlink, swapon, swapoff, acct, truncate, fsopen]",
		"syscalls: [mkdirat, mknodat, chmodat, fchmodat, faccessat, faccessat2, unlinkat, fchownat, fspick]",
		"case 80: /* chdir */",
		"case 83: /* mkdir */",
		"case 258: /* mkdirat */",
	} {
		if strings.Contains(legacyCaptureArtifacts, legacyRule) {
			t.Fatalf("path-only syscall still uses old fixed-window rule %q", legacyRule)
		}
	}
}
