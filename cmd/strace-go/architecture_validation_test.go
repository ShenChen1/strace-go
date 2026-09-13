package main

import (
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"strace-go/pkg/meta"
)

func TestBPFArtifactArchitecture(t *testing.T) {
	spec, err := loadBpf()
	if err != nil {
		t.Fatal(err)
	}
	if err := validateBPFArchitecture(spec, meta.SyscallABIHash); err != nil {
		t.Fatal(err)
	}
	if err := validateBPFArchitecture(spec, meta.SyscallABIHash^1); err == nil || !strings.Contains(err.Error(), "BPF syscall ABI mismatch") {
		t.Fatalf("wrong ABI accepted: %v", err)
	}
	if err := validateBPFArchitecture(&ebpf.CollectionSpec{}, meta.SyscallABIHash); err == nil {
		t.Fatal("missing ABI fingerprint accepted")
	}
}
