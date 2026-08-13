package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFExitDispatcherDelegatesProgramSelection(t *testing.T) {
	root := repoRootForTest(t)
	straceSource := readTextFile(t, filepath.Join(root, "bpf/strace.c"))
	routerSource := readTextFile(t, filepath.Join(root, "bpf/exit_router.h"))
	exitBody, ok := bpfFunctionBody(straceSource, "trace_sys_exit")
	if !ok {
		t.Fatal("strace.c missing trace_sys_exit body")
	}
	if !strings.Contains(exitBody, "u32 index = select_exit_prog_index(sys_id);") {
		t.Fatal("trace_sys_exit must delegate program selection")
	}
	if !strings.Contains(straceSource, `#include "exit_router.h"`) {
		t.Fatal("strace.c must include exit_router.h")
	}
	for _, forbidden := range []string{
		"is_path_only_direct_syscall(sys_id)",
		"is_quota_direct_syscall(sys_id)",
		"is_mount_query_direct_syscall(sys_id)",
		"is_iovec_base_exit_direct_syscall(sys_id)",
		"is_single_msg_direct_syscall(sys_id)",
		"is_mmsg_direct_syscall(sys_id)",
	} {
		if strings.Contains(exitBody, forbidden) {
			t.Fatalf("trace_sys_exit still owns selector branch %q", forbidden)
		}
	}

	selector, ok := bpfFunctionBody(routerSource, "select_exit_prog_index")
	if !ok {
		t.Fatal("exit_router.h missing select_exit_prog_index")
	}
	if !strings.Contains(routerSource, "static __always_inline u32 select_exit_prog_index(u32 sys_id)") {
		t.Fatal("exit selector must be a static inline helper")
	}
	for _, required := range []string{
		"u32 index = EXIT_PROG_GENERIC;",
		"index = EXIT_PROG_PATH;",
		"index = EXIT_PROG_QUOTA;",
		"index = EXIT_PROG_MOUNT_QUERY;",
		"index = EXIT_PROG_IOVEC_BASE;",
		"index = EXIT_PROG_MSG;",
		"? EXIT_PROG_RECVMMSG_BASE01 : EXIT_PROG_MMSG_FINAL;",
		"return index;",
	} {
		if !strings.Contains(selector, required) {
			t.Fatalf("exit selector missing %q", required)
		}
	}
	assertBPFSourceOrder(t, selector, []string{
		"is_path_only_direct_syscall(sys_id)",
		"is_quota_direct_syscall(sys_id)",
		"is_mount_query_direct_syscall(sys_id)",
		"is_iovec_base_exit_direct_syscall(sys_id)",
		"is_single_msg_direct_syscall(sys_id)",
		"is_mmsg_direct_syscall(sys_id)",
	})
}
