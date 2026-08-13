package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFAttachExitFactIsWrittenBeforeLifecycleCleanup(t *testing.T) {
	root := repoRootForTest(t)
	abi := readTextFile(t, filepath.Join(root, "bpf/runtime_abi.h"))
	if !strings.Contains(abi, "} attach_exited_map SEC(\".maps\");") {
		t.Fatal("runtime ABI is missing attach_exited_map")
	}
	if !strings.Contains(abi, "} attach_roots_map SEC(\".maps\");") {
		t.Fatal("runtime ABI is missing attach_roots_map")
	}

	source := loadBPFSources(t).straceSource
	markBody, ok := bpfFunctionBody(source, "mark_attach_task_exited")
	if !ok {
		t.Fatal("lifecycle source is missing mark_attach_task_exited")
	}
	for _, snippet := range []string{
		"bpf_map_lookup_elem(&attach_roots_map, &tid)",
		"if (!root) {",
	} {
		if !strings.Contains(markBody, snippet) {
			t.Fatalf("attach exit fact must be root-bound: missing %q", snippet)
		}
	}
	exitBody, ok := bpfFunctionBody(source, "trace_sched_process_exit")
	if !ok {
		t.Fatal("strace.c is missing trace_sched_process_exit")
	}
	mark := strings.Index(exitBody, "mark_attach_task_exited(tid);")
	clear := strings.Index(exitBody, "clear_lifecycle_task_state(pid, tid);")
	if mark < 0 || clear < 0 || mark > clear {
		t.Fatalf("exit fact must be marked before lifecycle cleanup: mark=%d clear=%d", mark, clear)
	}
	for name, snippets := range map[string][]string{
		"clear_process_lifecycle_state": {"bpf_map_delete_elem(&attach_roots_map, &pid);"},
		"clear_lifecycle_task_state":    {"bpf_map_delete_elem(&attach_roots_map, &tid);"},
	} {
		body, ok := bpfFunctionBody(source, name)
		if !ok {
			t.Fatalf("BPF source is missing %s", name)
		}
		for _, snippet := range snippets {
			if !strings.Contains(body, snippet) {
				t.Fatalf("%s is missing root cleanup %q", name, snippet)
			}
		}
	}
}

func TestBPFAttachExitFactFilterLifecycleClearsStaleEntries(t *testing.T) {
	root := repoRootForTest(t)
	source := readTextFile(t, filepath.Join(root, "cmd/strace-go/bpf_runtime.go"))
	for _, method := range []string{
		"r.objects.AttachExitedMap.Delete(pid)",
		"r.objects.AttachRootsMap.Update(pid, uint32(1), 0)",
		"r.objects.AttachRootsMap.Delete(pid)",
	} {
		if !strings.Contains(source, method) {
			t.Fatalf("BPF runtime must maintain attach root state: %q", method)
		}
	}
}

func TestBPFReadPortsExposeAttachExitLookupPort(t *testing.T) {
	root := repoRootForTest(t)
	source := readTextFile(t, filepath.Join(root, "cmd/strace-go/bpf_read_ports.go"))
	for _, required := range []string{
		"type traceAttachExitReader interface",
		"IsExited(pid uint32) (bool, error)",
		"AttachExits traceAttachExitReader",
		"objs.AttachExitedMap",
		"ebpf.ErrKeyNotExist",
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("BPF read ports missing attach exit contract %q", required)
		}
	}
}

func TestBPFReadAttachExitRejectsUnavailableMap(t *testing.T) {
	exited, err := (&bpfAttachExitReader{}).IsExited(505)
	if exited {
		t.Fatal("unavailable attach exit map reported an exited task")
	}
	if err == nil || !strings.Contains(err.Error(), "attach exit map unavailable") {
		t.Fatalf("unavailable attach exit map error = %v", err)
	}
}
