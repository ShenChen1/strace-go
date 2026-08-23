package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestJSONSyscallHotPathsUseSharedWireWriter(t *testing.T) {
	root := repoRootForTest(t)
	decodedSource := readTextFile(t, filepath.Join(root, "cmd/strace-go/json_decoded_encoder.go"))
	wireSource := readTextFile(t, filepath.Join(root, "cmd/strace-go/json_syscall_wire.go"))
	if !strings.Contains(decodedSource, "appendJSONSyscallWireEvent") {
		t.Fatal("raw/decoded syscall paths must use the shared JSON wire writer")
	}
	if strings.Contains(decodedSource, "jsonLineBuilder") {
		t.Fatal("raw/decoded syscall paths must not construct jsonLineBuilder")
	}
	for _, required := range []string{
		"type jsonSyscallWireEvent struct",
		"func appendJSONSyscallWireEvent(",
		"appendJSONSyscallWireHeader",
		"appendJSONSyscallWireReturn",
	} {
		if !strings.Contains(wireSource, required) {
			t.Fatalf("shared JSON wire writer is missing %q", required)
		}
	}
}
