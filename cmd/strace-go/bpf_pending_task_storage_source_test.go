package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFPendingStateUsesTaskStorageOwner(t *testing.T) {
	root := repoRootForTest(t)
	abi := readTextFile(t, filepath.Join(root, "bpf/runtime_abi.h"))
	core := readTextFile(t, filepath.Join(root, "bpf/syscall_event_core_v2.h"))
	pending := readTextFile(t, filepath.Join(root, "bpf/pending_state.h"))
	lifecycle := readTextFile(t, filepath.Join(root, "bpf/lifecycle_state.h"))
	combined := readCombinedBPFSources(t)

	for _, snippet := range []string{
		"struct pending_task_state {",
		"__uint(type, BPF_MAP_TYPE_TASK_STORAGE);",
		"__uint(map_flags, BPF_F_NO_PREALLOC);",
		"__type(key, int);",
		"__uint(max_entries, 0);",
		"u32 valid;",
		"} pending_task_storage SEC(\".maps\");",
	} {
		if !strings.Contains(abi, snippet) {
			t.Fatalf("runtime_abi.h missing task storage contract %q", snippet)
		}
	}
	for _, snippet := range []string{
		"bpf_get_current_task_btf()",
		"bpf_task_storage_get(&pending_task_storage",
		"BPF_LOCAL_STORAGE_GET_F_CREATE",
		"state->valid = 1;",
		"state->valid = 0;",
	} {
		if !strings.Contains(core, snippet) && !strings.Contains(pending, snippet) {
			t.Fatalf("pending task storage helper missing %q", snippet)
		}
	}
	if !strings.Contains(pending, "clear_pending_task_state();") {
		t.Fatal("pending_state.h must clear task storage after consuming state")
	}
	if !strings.Contains(lifecycle, "clear_pending_task_state();") {
		t.Fatal("lifecycle cleanup must clear task storage for the current task")
	}
	if strings.Contains(core, "bpf_task_storage_delete(&pending_task_storage") {
		t.Fatal("pending state must not reallocate task storage on every syscall")
	}
	for _, forbidden := range []string{
		"pending_syscalls SEC(\".maps\")",
		"pending_syscall_aux_map SEC(\".maps\")",
		"bpf_map_lookup_elem(&pending_syscalls",
		"bpf_map_update_elem(&pending_syscalls",
		"bpf_map_delete_elem(&pending_syscalls",
	} {
		if strings.Contains(combined, forbidden) {
			t.Fatalf("task storage migration retains hash pending operation %q", forbidden)
		}
	}
}
