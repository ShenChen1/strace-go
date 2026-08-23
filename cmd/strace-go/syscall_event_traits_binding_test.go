package main

import (
	"testing"

	"strace-go/pkg/meta"
)

func TestSyscallEventContextUsesSessionBoundTraits(t *testing.T) {
	const syscallID = 39
	table := newSyscallMetadataTable(map[uint32]meta.Syscall{
		syscallID: {Name: "openat"},
	})
	deps := syscallEventContextDeps{syscallMetadata: table}
	view := syscallEventView{valid: true, sysID: syscallID}

	exit := newSyscallEventContextFromViewWithDeps(deps, view, 101, nil, nil)
	want := syscallEventTraitHandler | syscallEventTraitState | syscallEventTraitOffset
	if got := exit.eventTraits(); got != want {
		t.Fatalf("exit traits = %#x, want %#x", got, want)
	}
	if !exit.isFDStateSyscall() {
		t.Fatal("session-bound openat traits should enable FD state handling")
	}

	enter := newSyscallEnterEventContextFromDeps(deps, view, 101, nil)
	if got := enter.eventTraits(); got != want {
		t.Fatalf("enter traits = %#x, want %#x", got, want)
	}

	zeroTable := newSyscallMetadataTable(map[uint32]meta.Syscall{
		syscallID: {Name: "getpid"},
	})
	zero := newSyscallEventContextFromViewWithDeps(
		syscallEventContextDeps{syscallMetadata: zeroTable},
		view,
		101,
		nil,
		nil,
	)
	if !zero.traitsBound {
		t.Fatal("zero-trait syscall should still be marked as session-bound")
	}
	if got := zero.eventTraits(); got != 0 {
		t.Fatalf("zero-trait syscall traits = %#x, want 0", got)
	}
}
