package main

import (
	"reflect"
	"testing"

	"strace-go/internal/architecture"
	"strace-go/pkg/meta"
)

func TestAMD64SyscallNumbers(t *testing.T) {
	assertTargetNumbers(t, architecture.AMD64, []int{0, 1, 3, 257, 267, 56, 435, 59, 322, 41, 42, 43, 32, 72, 16, 202, 281})
}
func TestARM64SyscallNumbers(t *testing.T) {
	assertTargetNumbers(t, architecture.ARM64, []int{63, 64, 57, 56, 78, 220, 435, 221, 281, 198, 203, 202, 23, 25, 29, 98, 22})
}

func assertTargetNumbers(t *testing.T, target architecture.Architecture, ids []int) {
	t.Helper()
	table, err := loadTargetSyscalls(target)
	if err != nil {
		t.Fatal(err)
	}
	names := []string{"read", "write", "close", "openat", "readlinkat", "clone", "clone3", "execve", "execveat", "socket", "connect", "accept", "dup", "fcntl", "ioctl", "futex", "epoll_pwait"}
	for i, name := range names {
		if table[ids[i]].Name != name {
			t.Errorf("%s[%d] = %q, want %q", target, ids[i], table[ids[i]].Name, name)
		}
	}
	if target == architecture.ARM64 {
		for _, sc := range table {
			if sc.Name == "arch_specific_syscall" || sc.Name == "epoll_wait" || sc.Name == "open" || sc.Name == "fork" {
				t.Errorf("unsupported ARM64 syscall: %s", sc.Name)
			}
		}
		want := []string{"clone_flags", "newsp", "parent_tidptr", "tls", "child_tidptr"}
		if !reflect.DeepEqual(table[220].Args, want) {
			t.Fatalf("ARM64 clone = %v", table[220].Args)
		}
	}
}

func TestCheckedSchemaPreservesAMD64Metadata(t *testing.T) {
	table, err := loadTargetSyscalls(architecture.AMD64)
	if err != nil {
		t.Fatal(err)
	}
	for id, got := range table {
		old := meta.SyscallTable[uint32(id)]
		if got.Name != old.Name || !reflect.DeepEqual(got.Args, old.Args) || !reflect.DeepEqual(got.ArgTypes, old.ArgTypes) || got.Flags != old.Flags {
			t.Fatalf("amd64 metadata changed at %d: %+v != %+v", id, got, old)
		}
	}
}
