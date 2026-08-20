package main

import (
	"io"
	"path/filepath"
	"strings"
	"testing"
)

type ownerCountingCloser struct {
	calls int
}

func (c *ownerCountingCloser) Close() error {
	c.calls++
	return nil
}

var _ io.Closer = (*ownerCountingCloser)(nil)

func TestBPFResourceOwnerTransfersNamedResourcesAndClearsSource(t *testing.T) {
	first := &ownerCountingCloser{}
	second := &ownerCountingCloser{}
	var owner bpfResourceOwner
	owner.addGroup("handler", []io.Closer{first, nil, second})

	transferred := owner.transfer()
	if len(owner.resources) != 0 {
		t.Fatalf("source owner resources = %d, want 0 after transfer", len(owner.resources))
	}
	if got, want := len(transferred.resources), 2; got != want {
		t.Fatalf("transferred resources = %d, want %d", got, want)
	}
	if got, want := transferred.resources[0].Name, "handler_0"; got != want {
		t.Fatalf("first resource name = %q, want %q", got, want)
	}
	if got, want := transferred.resources[1].Name, "handler_2"; got != want {
		t.Fatalf("second resource name = %q, want %q", got, want)
	}
	if err := transferred.close(); err != nil {
		t.Fatalf("transferred.close() error = %v", err)
	}
	if first.calls != 1 || second.calls != 1 {
		t.Fatalf("resource close calls = %d/%d, want 1/1", first.calls, second.calls)
	}
}

func TestBPFResourceOwnerCloseIsIdempotent(t *testing.T) {
	closer := &ownerCountingCloser{}
	var owner bpfResourceOwner
	owner.add("core", closer)
	if err := owner.close(); err != nil {
		t.Fatalf("first owner.close() error = %v", err)
	}
	if err := owner.close(); err != nil {
		t.Fatalf("second owner.close() error = %v", err)
	}
	if closer.calls != 1 {
		t.Fatalf("close calls = %d, want 1", closer.calls)
	}
}

func TestBPFResourceOwnerReplacesRawCloserSlices(t *testing.T) {
	root := repoRootForTest(t)
	for _, name := range []string{
		"cmd/strace-go/bpf_object_loader.go",
		"cmd/strace-go/bpf_runtime.go",
	} {
		source := readTextFile(t, filepath.Join(root, name))
		for _, forbidden := range []string{"handlerClosers", "extraClosers"} {
			if strings.Contains(source, forbidden) {
				t.Fatalf("%s still owns raw closer slice %q", name, forbidden)
			}
		}
	}
}
