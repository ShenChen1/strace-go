package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestSessionUsesSymbolResolverPort(t *testing.T) {
	source := readTextFile(t, filepath.Join(repoRootForTest(t), "cmd", "strace-go", "session_composition.go"))
	if !strings.Contains(source, "Resolver      traceSymbolResolver") {
		t.Fatal("traceSessionDeps must expose the symbol resolver port")
	}
	if strings.Contains(source, "Resolver      *stacktrace.Resolver") {
		t.Fatal("traceSessionDeps still exposes concrete stacktrace.Resolver")
	}
}

type fakeSessionSymbolResolver struct{}

func (fakeSessionSymbolResolver) Resolve(uint64) string {
	return "fake_symbol"
}

func TestTraceSessionAcceptsSymbolResolverPort(t *testing.T) {
	resolver := fakeSessionSymbolResolver{}
	session := newTestTraceSession(traceSessionDeps{Resolver: resolver})

	if session.dependencies.Resolver != resolver {
		t.Fatal("session did not retain the injected symbol resolver port")
	}
	if session.textRenderer().resolver != resolver {
		t.Fatal("text renderer did not receive the injected symbol resolver port")
	}
}

var _ traceSymbolResolver = fakeSessionSymbolResolver{}
