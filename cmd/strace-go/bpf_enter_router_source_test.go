package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFEnterDispatcherUsesDirectRouteMap(t *testing.T) {
	root := repoRootForTest(t)
	straceSource := readTextFile(t, filepath.Join(root, "bpf/strace.c"))
	runtimeABI := readTextFile(t, filepath.Join(root, "bpf/runtime_abi.h"))
	enterBody, ok := bpfFunctionBody(straceSource, "trace_sys_enter")
	if !ok {
		t.Fatal("strace.c missing trace_sys_enter body")
	}
	if !strings.Contains(enterBody, "bpf_tail_call(ctx, &enter_routes, sys_id);") {
		t.Fatal("trace_sys_enter must use the syscall-id route map")
	}
	if strings.Contains(straceSource, `#include "enter_router.h"`) {
		t.Fatal("strace.c must not compile the legacy predicate router")
	}
	for _, forbidden := range []string{
		"is_terminating_direct_syscall(sys_id)",
		"is_exec_payload_direct_syscall(sys_id)",
		"is_path_stat_direct_syscall(sys_id)",
		"is_network_direct_syscall(sys_id)",
		"is_payload_direct_syscall(sys_id)",
	} {
		if strings.Contains(enterBody, forbidden) {
			t.Fatalf("trace_sys_enter still owns selector branch %q", forbidden)
		}
	}
	if !strings.Contains(runtimeABI, "} enter_routes SEC(\".maps\");") {
		t.Fatal("runtime_abi.h must declare enter_routes")
	}
	if !strings.Contains(runtimeABI, "__uint(max_entries, 512)") {
		t.Fatal("runtime_abi.h route map capacity must cover generated syscall ids")
	}
}
