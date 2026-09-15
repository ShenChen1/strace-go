package handler

import (
	"testing"

	"strace-go/pkg/meta"
)

func nativeSyscallMetadataForTest(t testing.TB, name string) meta.Syscall {
	t.Helper()
	for _, sc := range meta.SyscallTable {
		if sc.Name == name {
			return sc
		}
	}
	if meta.SyscallArchitecture == "arm64" && name == "getdents" {
		t.Skip("legacy getdents is unavailable on native arm64; getdents64 is tested")
	}
	t.Fatalf("native syscall metadata missing: %s", name)
	return meta.Syscall{}
}
