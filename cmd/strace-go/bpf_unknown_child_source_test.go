package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFUnknownChildLifecycleUsesCloneFlags(t *testing.T) {
	root := repoRootForTest(t)
	straceSource := readTextFile(t, filepath.Join(root, "bpf/strace.c"))
	lifecycleSource := readTextFile(t, filepath.Join(root, "bpf/lifecycle_dispatch.h"))
	stateSource := readTextFile(t, filepath.Join(root, "bpf/lifecycle_state.h"))
	for _, required := range []string{
		"capture_pending_fork_flags(tid, sys_id, ctx);",
		"clear_pending_fork_flags(tid, sys_id);",
		"pending_fork_flags(parent_tid)",
		"CLONE_PTRACE_FLAG",
		"LIFECYCLE_UNKNOWN_DETACH",
		"CLONE_PARENT_FLAG",
		"mark_unknown_child(child_pid, parent_tgid)",
		"take_unknown_child(tid)",
		"LIFECYCLE_UNKNOWN_EXIT",
	} {
		combined := straceSource + lifecycleSource + stateSource
		if !strings.Contains(combined, required) {
			t.Fatalf("unknown-child lifecycle is missing %q", required)
		}
	}
}

func TestBPFUnknownChildMapsAreBounded(t *testing.T) {
	source := readTextFile(t, filepath.Join(repoRootForTest(t), "bpf/runtime_abi.h"))
	for _, mapName := range []string{"pending_fork_flags_map", "unknown_children_map"} {
		if !strings.Contains(source, mapName) {
			t.Fatalf("runtime ABI is missing %s", mapName)
		}
	}
}
