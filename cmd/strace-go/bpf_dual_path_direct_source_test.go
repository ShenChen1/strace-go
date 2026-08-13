package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFDualPathPayloadsUseDirectTLV(t *testing.T) {
	root := repoRootForTest(t)
	straceSource := readCombinedBPFSources(t)
	legacyCaptureArtifacts := legacyCaptureArtifactsForTest(t)
	pathDirectHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_path_direct_event_v2.h"))
	timeDirectHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_time_direct_event_v2.h"))

	for _, snippet := range []string{
		"#define SYS_RENAME 82",
		"#define SYS_RENAMEAT 264",
		"#define SYS_RENAMEAT2 316",
		"is_dual_path_direct_syscall(sys_id)",
		"emit_dual_path_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);",
		"is_dual_path_direct_syscall(sys_id) ||",
		"EXIT_PROG_PATH = 8",
		"emit_dual_path_exit_event_v2_direct(p, ret_value, duration);",
		"is_dual_path_direct_syscall(p->sys_id)",
	} {
		if !strings.Contains(straceSource, snippet) && !strings.Contains(pathDirectHeader, snippet) && !strings.Contains(timeDirectHeader, snippet) {
			t.Fatalf("BPF source missing dual path direct snippet %q", snippet)
		}
	}

	for _, snippet := range []string{
		"DUAL_PATH_DIRECT_PATH_MAX 512",
		"is_dual_path_0_1_direct_syscall(",
		"is_dual_path_0_2_direct_syscall(",
		"is_dual_path_1_3_direct_syscall(",
		"capture_dual_path_tlv_direct(",
		"emit_dual_path_enter_event_v2_direct(",
		"PAYLOAD_TLV_KIND_STRING",
		"bpf_probe_read_user_str(payload_data, DUAL_PATH_DIRECT_PATH_MAX",
		"init_syscall_enter_event_v2_from_ctx(&body, ctx, 0, 0, -1, -1);",
		"body.capture_len = payload_size;",
	} {
		if !strings.Contains(pathDirectHeader, snippet) {
			t.Fatalf("path direct header missing dual path snippet %q", snippet)
		}
	}

	for _, legacyRule := range []string{
		"syscalls: [rename, link, symlink]",
		"syscalls: [symlinkat]",
		"syscalls: [renameat, renameat2, linkat]",
		"case 82: /* rename */",
		"case 264: /* renameat */",
		"case 316: /* renameat2 */",
	} {
		if strings.Contains(legacyCaptureArtifacts, legacyRule) {
			t.Fatalf("dual path syscall still uses old fixed-window rule %q", legacyRule)
		}
	}
}
