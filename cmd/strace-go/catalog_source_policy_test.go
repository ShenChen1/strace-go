package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestCatalogConsumersDoNotConstructFallbackCatalog(t *testing.T) {
	root := filepath.Join(repoRootForTest(t), "cmd/strace-go")
	for _, name := range []string{"event_utils.go", "syscall_event_context.go"} {
		source := readTextFile(t, filepath.Join(root, name))
		if strings.Contains(source, "meta.NewCatalog(") {
			t.Fatalf("%s constructs an implicit catalog", name)
		}
	}
}

func TestNilCatalogConsumersRemainInert(t *testing.T) {
	view := syscallEventView{valid: true, args: [6]uint64{2, 1, 0}}
	context := newSyscallEnterEventContextWithCatalog(view, 101, nil, nil)
	if context.catalog != nil {
		t.Fatal("nil catalog context unexpectedly created a catalog")
	}
	if got := socketFDInfoFromCatalog(nil, view); got != "" {
		t.Fatalf("nil catalog socket info = %q, want empty info", got)
	}
}
