package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFComplexEmittersBuildHeaderInRingbufMemory(t *testing.T) {
	root := repoRootForTest(t)
	core := readTextFile(t, filepath.Join(root, "bpf/syscall_event_core_v2.h"))
	if !strings.Contains(core, "event_v2_header_from_dynptr_direct") {
		t.Fatal("event v2 core is missing dynptr header access")
	}
	bpfEmitter := readTextFile(t, filepath.Join(root, "bpf/syscall_bpf_direct_event_v2.h"))
	if strings.Contains(bpfEmitter, "struct event_v2_header header = {};") {
		t.Fatal("complex BPF emitters still allocate event headers on the BPF stack")
	}
}
