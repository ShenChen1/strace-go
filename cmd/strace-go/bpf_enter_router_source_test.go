package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFEnterDispatcherDelegatesProgramSelection(t *testing.T) {
	root := repoRootForTest(t)
	straceSource := readTextFile(t, filepath.Join(root, "bpf/strace.c"))
	routerSource := readTextFile(t, filepath.Join(root, "bpf/enter_router.h"))
	enterBody, ok := bpfFunctionBody(straceSource, "trace_sys_enter")
	if !ok {
		t.Fatal("strace.c missing trace_sys_enter body")
	}
	if !strings.Contains(enterBody, "u32 index = select_enter_prog_index(sys_id);") {
		t.Fatal("trace_sys_enter must delegate program selection")
	}
	if !strings.Contains(straceSource, `#include "enter_router.h"`) {
		t.Fatal("strace.c must include enter_router.h")
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

	selector, ok := bpfFunctionBody(routerSource, "select_enter_prog_index")
	if !ok {
		t.Fatal("enter_router.h missing select_enter_prog_index")
	}
	if !strings.Contains(routerSource, "static __always_inline u32 select_enter_prog_index(u32 sys_id)") {
		t.Fatal("enter selector must be a static inline helper")
	}
	for _, required := range []string{
		"u32 index = ENTER_PROG_NO_PAYLOAD_DIRECT;",
		"index = ENTER_PROG_TERMINATING;",
		"index = ENTER_PROG_EXEC;",
		"index = ENTER_PROG_PATH_ONLY;",
		"? ENTER_PROG_MSG : ENTER_PROG_MMSG;",
		"index = ENTER_PROG_NETWORK;",
		"index = ENTER_PROG_FS;",
		"index = ENTER_PROG_AIO;",
		"index = ENTER_PROG_PAYLOAD_DIRECT;",
		"return index;",
	} {
		if !strings.Contains(selector, required) {
			t.Fatalf("enter selector missing %q", required)
		}
	}
	assertBPFSourceOrder(t, selector, []string{
		"is_terminating_direct_syscall(sys_id)",
		"is_exec_payload_direct_syscall(sys_id)",
		"is_path_only_direct_syscall(sys_id)",
		"is_msg_direct_syscall(sys_id)",
		"is_payload_direct_syscall(sys_id)",
	})
}
