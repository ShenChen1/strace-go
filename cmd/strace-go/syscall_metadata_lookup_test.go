package main

import (
	"testing"

	"strace-go/pkg/meta"
)

func TestSyscallMetadataLookupUsesBoundTable(t *testing.T) {
	const syscallID = 39
	table := newSyscallMetadataTable(map[uint32]meta.Syscall{
		syscallID: {Name: "bound_getpid"},
	})

	got := lookupSyscallMetadata(table, syscallID)
	if got.Name != "bound_getpid" {
		t.Fatalf("bound metadata name = %q, want bound_getpid", got.Name)
	}
}

func TestSyscallMetadataLookupFallsBackForUnknownTableEntries(t *testing.T) {
	const syscallID = 39
	got := lookupSyscallMetadata(nil, syscallID)
	if got.Name != "getpid" {
		t.Fatalf("fallback metadata name = %q, want getpid", got.Name)
	}

	unknown := lookupSyscallMetadata(newSyscallMetadataTable(nil), 511)
	if unknown.Name != "syscall_0x1ff" {
		t.Fatalf("unknown metadata name = %q, want syscall_0x1ff", unknown.Name)
	}
}
