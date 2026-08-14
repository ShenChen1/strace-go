package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFExitDispatcherUsesDirectRouteMap(t *testing.T) {
	root := repoRootForTest(t)
	straceSource := readTextFile(t, filepath.Join(root, "bpf/strace.c"))
	runtimeABI := readTextFile(t, filepath.Join(root, "bpf/runtime_abi.h"))
	exitBody, ok := bpfFunctionBody(straceSource, "trace_sys_exit")
	if !ok {
		t.Fatal("strace.c missing trace_sys_exit body")
	}
	if !strings.Contains(exitBody, "bpf_tail_call(ctx, &exit_routes, sys_id);") {
		t.Fatal("trace_sys_exit must use the syscall-id route map")
	}
	if strings.Contains(straceSource, `#include "exit_router.h"`) {
		t.Fatal("strace.c must not compile the legacy predicate router")
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
	if !strings.Contains(runtimeABI, "} exit_routes SEC(\".maps\");") {
		t.Fatal("runtime_abi.h must declare exit_routes")
	}
}
