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

func TestNilFlagDecoderConsumersRemainInert(t *testing.T) {
	view := syscallEventView{valid: true, args: [6]uint64{2, 1, 0}}
	context := newSyscallEnterEventContextWithFlagDecoder(view, 101, nil, nil)
	if context.fdFlags != nil {
		t.Fatal("nil flag decoder context unexpectedly created a decoder")
	}
	if got := socketFDInfoFromFlags(nil, view); got != "" {
		t.Fatalf("nil flag decoder socket info = %q, want empty info", got)
	}
}
