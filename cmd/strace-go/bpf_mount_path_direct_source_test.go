package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFMountPathSyscallsUseProbeSiteTLV(t *testing.T) {
	root := repoRootForTest(t)
	dispatch := readTextFile(t, filepath.Join(root, "bpf/mount_path_dispatch.h"))
	combined := readCombinedBPFSources(t) + "\n" + dispatch
	header := readTextFile(t, filepath.Join(root, "bpf/syscall_mount_path_direct_event_v2.h"))

	for _, snippet := range []string{
		"#define SYS_OPEN_TREE 428",
		"#define SYS_MOVE_MOUNT 429",
		`#include "syscall_mount_path_direct_event_v2.h"`,
		"ENTER_PROG_MOUNT_PATH = 44",
		"is_mount_path_direct_syscall(sys_id)",
		"emit_mount_path_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);",
	} {
		if !strings.Contains(combined, snippet) {
			t.Fatalf("BPF combined source missing mount path snippet %q", snippet)
		}
	}

	for _, snippet := range []string{
		"sys_id == SYS_MOVE_MOUNT",
		"2 * (PAYLOAD_TLV_HEADER_SIZE + PATH_ONLY_DIRECT_PATH_MAX)",
		"capture_path_only_tlv_direct(",
		"ctx->args[1]",
		"ctx->args[3]",
	} {
		if !strings.Contains(header, snippet) {
			t.Fatalf("mount path direct header missing snippet %q", snippet)
		}
	}
}
