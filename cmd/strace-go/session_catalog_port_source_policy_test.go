package main

import (
	"path/filepath"
	"strings"
	"testing"

	"strace-go/pkg/meta"
)

func TestSessionUsesCatalogPort(t *testing.T) {
	source := readTextFile(t, filepath.Join(repoRootForTest(t), "cmd", "strace-go", "session_composition.go"))
	if !strings.Contains(source, "Catalog       meta.CatalogPort") {
		t.Fatal("traceSessionDeps must expose the catalog port")
	}
	if strings.Contains(source, "Catalog       *meta.Catalog") {
		t.Fatal("traceSessionDeps still exposes concrete Catalog")
	}
}

type fakeSessionCatalog struct{}

func (fakeSessionCatalog) Format() string {
	return "abbrev"
}

func (fakeSessionCatalog) Table(string) (meta.XlatTable, bool) {
	return meta.XlatTable{}, false
}

func (fakeSessionCatalog) SyscallArgXlat(string, string) (string, bool) {
	return "", false
}

func (fakeSessionCatalog) DecodeFlags(uint64, string) string {
	return "0"
}

func TestTraceSessionAcceptsCatalogPort(t *testing.T) {
	catalog := fakeSessionCatalog{}
	session := newTestTraceSession(traceSessionDeps{Catalog: catalog})

	if session.dependencies.Catalog != catalog {
		t.Fatal("session did not retain the injected catalog port")
	}
	dispatcher, ok := session.traceEventRouter().dispatcher.(*TraceEventDispatcher)
	if !ok {
		t.Fatalf("router dispatcher = %T, want *TraceEventDispatcher", session.traceEventRouter().dispatcher)
	}
	if dispatcher.contextDeps.catalog != catalog {
		t.Fatal("event context did not receive the injected catalog port")
	}
}

var _ meta.CatalogPort = fakeSessionCatalog{}
