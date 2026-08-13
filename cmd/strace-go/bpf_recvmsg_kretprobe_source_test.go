package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFRecvmsgKretprobeHandlersHaveDedicatedOwnership(t *testing.T) {
	root := repoRootForTest(t)
	straceSource := readTextFile(t, filepath.Join(root, "bpf/strace.c"))
	fragmentSource := readTextFile(t, filepath.Join(root, "bpf/recvmsg_kretprobe_dispatch.h"))
	if !strings.Contains(straceSource, `#include "recvmsg_kretprobe_dispatch.h"`) {
		t.Fatal("strace.c must include the recvmsg kretprobe dispatch header")
	}
	for _, name := range []string{
		"trace_kretprobe_recvmsg_dispatch",
		"trace_kretprobe_recvmsg_name",
		"trace_kretprobe_recvmsg_control",
		"trace_kretprobe_recvmsg_final",
	} {
		if !strings.Contains(fragmentSource, "int "+name+"(") {
			t.Fatalf("recvmsg kretprobe header missing %s", name)
		}
		if strings.Contains(straceSource, "int "+name+"(") {
			t.Fatalf("strace.c still owns recvmsg kretprobe handler %s", name)
		}
	}
	if !strings.Contains(fragmentSource, "bpf_tail_call(ctx, &recvmsg_progs, RECVMSG_PROG_NAME);") ||
		!strings.Contains(fragmentSource, "bpf_tail_call(ctx, &recvmsg_progs, RECVMSG_PROG_CONTROL);") ||
		!strings.Contains(fragmentSource, "bpf_tail_call(ctx, &recvmsg_progs, RECVMSG_PROG_FINAL);") {
		t.Fatal("recvmsg kretprobe header missing serialized fragment chain")
	}
	if !strings.Contains(fragmentSource, "consume_pending_syscall(pid, tid, p, 0);") {
		t.Fatal("recvmsg final handler must own pending consume")
	}
}
