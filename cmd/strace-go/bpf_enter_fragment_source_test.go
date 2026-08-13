package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFEnterFragmentsHaveDedicatedOwnership(t *testing.T) {
	root := repoRootForTest(t)
	straceSource := readTextFile(t, filepath.Join(root, "bpf/strace.c"))
	familySource := readTextFile(t, filepath.Join(root, "bpf/enter_dispatch.h"))
	fragmentSource := readTextFile(t, filepath.Join(root, "bpf/enter_fragment_dispatch.h"))
	if !strings.Contains(straceSource, `#include "enter_fragment_dispatch.h"`) {
		t.Fatal("strace.c must include the dedicated enter fragment header")
	}
	for _, name := range []string{
		"enter_iovec_base",
		"enter_sendmsg_base",
		"enter_aio_iovec",
		"enter_aio_buf",
	} {
		if !strings.Contains(fragmentSource, "int "+name+"(") {
			t.Fatalf("enter fragment header missing %s", name)
		}
		if strings.Contains(familySource, "int "+name+"(") {
			t.Fatalf("enter family header still owns fragment %s", name)
		}
	}
	if strings.Contains(fragmentSource, "save_pending_syscall_args(") ||
		strings.Contains(fragmentSource, "save_pending_msg_syscall_args(") {
		t.Fatal("enter fragment handlers must not own pending state")
	}

	fragmentExpectations := []struct {
		name     string
		snippets []string
	}{
		{
			name: "enter_iovec_base",
			snippets: []string{
				"ENTER_PROLOGUE(ctx);",
				"if (!is_iovec_base_enter_direct_syscall(sys_id))",
				"emit_iovec_base_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);",
			},
		},
		{
			name: "enter_sendmsg_base",
			snippets: []string{
				"ENTER_PROLOGUE(ctx);",
				"if (sys_id != SYS_SENDMSG)",
				"emit_sendmsg_base_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);",
			},
		},
		{
			name: "enter_aio_iovec",
			snippets: []string{
				"ENTER_PROLOGUE(ctx);",
				"if (sys_id != SYS_IO_SUBMIT)",
				"emit_aio_submit_iovec_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);",
				"bpf_tail_call(ctx, &enter_progs, ENTER_PROG_AIO_BUF);",
			},
		},
		{
			name: "enter_aio_buf",
			snippets: []string{
				"ENTER_PROLOGUE(ctx);",
				"if (sys_id != SYS_IO_SUBMIT)",
				"emit_aio_submit_buf_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);",
			},
		},
	}
	for _, expectation := range fragmentExpectations {
		body, ok := bpfFunctionBody(fragmentSource, expectation.name)
		if !ok {
			t.Fatalf("fragment header missing body for %s", expectation.name)
		}
		for _, snippet := range expectation.snippets {
			if !strings.Contains(body, snippet) {
				t.Fatalf("%s missing %q", expectation.name, snippet)
			}
		}
	}
}
