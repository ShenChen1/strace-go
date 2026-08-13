package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFExitDurationUsesSharedPendingHelper(t *testing.T) {
	root := repoRootForTest(t)
	pending := readTextFile(t, filepath.Join(root, "bpf/pending_state.h"))
	exitDispatch := readTextFile(t, filepath.Join(root, "bpf/exit_dispatch.h"))
	quotaDispatch := readTextFile(t, filepath.Join(root, "bpf/quota_dispatch.h"))
	mountDispatch := readTextFile(t, filepath.Join(root, "bpf/mount_query_dispatch.h"))
	straceSource := readTextFile(t, filepath.Join(root, "bpf/strace.c"))

	for _, snippet := range []string{
		"static __always_inline u64 pending_syscall_duration(",
		"if (p->enter_time == 0) return 0;",
		"u64 exit_time = bpf_ktime_get_ns();",
		"if (exit_time <= p->enter_time) return 0;",
	} {
		if !strings.Contains(pending, snippet) {
			t.Fatalf("pending_state.h missing shared duration snippet %q", snippet)
		}
	}
	if !strings.Contains(exitDispatch, "u64 duration = pending_syscall_duration(p);") {
		t.Fatal("EXIT_PROLOGUE must calculate duration with the shared helper")
	}
	if strings.Contains(exitDispatch, "if (p->enter_time > 0)") {
		t.Fatal("exit_dispatch.h still contains an inline duration block")
	}
	for name, source := range map[string]string{
		"exit_dispatch.h":        exitDispatch,
		"quota_dispatch.h":       quotaDispatch,
		"mount_query_dispatch.h": mountDispatch,
		"strace.c":               straceSource,
	} {
		if strings.Contains(source, "if (p->enter_time > 0)") {
			t.Fatalf("%s still contains an inline duration block", name)
		}
	}
}
