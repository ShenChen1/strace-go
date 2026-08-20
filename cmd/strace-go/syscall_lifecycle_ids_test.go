package main

import (
	"testing"

	"strace-go/pkg/meta"
)

func TestSyscallLifecycleIDsResolveFromCatalog(t *testing.T) {
	ids := newSyscallLifecycleIDs(map[uint32]meta.Syscall{
		12: {Name: "exit"},
		42: {Name: "exit_group"},
		7:  {Name: "getpid"},
	})

	if !ids.configured() || !ids.isTerminating(12) || !ids.isTerminating(42) {
		t.Fatalf("lifecycle IDs = %+v, want exit and exit_group", ids)
	}
	if ids.isTerminating(7) {
		t.Fatal("non-terminating syscall was classified as terminating")
	}
}

func TestTraceStateFallsBackToMetadataWithoutLifecycleIDs(t *testing.T) {
	state := &TraceState{}
	if !state.isTerminatingSyscall(syscallEventView{sysID: 60}) {
		t.Fatal("unconfigured state did not preserve exit metadata fallback")
	}
}
