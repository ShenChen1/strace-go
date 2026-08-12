package main

import (
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/event"
	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

type fakeContextFDStateReader struct {
	path        string
	cwd         string
	observation handler.FDStateObservation
}

func (r *fakeContextFDStateReader) Path(int, int32) (string, bool) {
	return r.path, r.path != ""
}

func (r *fakeContextFDStateReader) Cwd(int) (string, bool) {
	return r.cwd, r.cwd != ""
}

func (r *fakeContextFDStateReader) Observation(int, int32) (handler.FDStateObservation, bool) {
	return r.observation, r.observation.FD != 0
}

type fakeContextFDPathReader struct {
	path string
}

func (r *fakeContextFDPathReader) Path(int, int32) (string, bool) {
	return r.path, r.path != ""
}

func (r *fakeContextFDPathReader) Cwd(int) (string, bool) {
	return "", false
}

type fakeContextRuntime struct{}

func (*fakeContextRuntime) NextFiemapCall(int) int {
	return 7
}

type fakeSyscallEventContextDependencySource struct {
	deps syscallEventContextDeps
}

func (s fakeSyscallEventContextDependencySource) eventContextDependencies() syscallEventContextDeps {
	return s.deps
}

func TestSyscallEventContextDependencySourceProjectsPorts(t *testing.T) {
	decoder := event.NewDecoder()
	catalog := meta.NewCatalog("raw")
	fdState := &fakeContextFDStateReader{path: "/state"}
	runtime := &fakeContextRuntime{}
	registry := handler.NewRegistry()
	policy := newTraceEventPolicy(&cli.Options{DebugEvents: true})
	source := fakeSyscallEventContextDependencySource{deps: syscallEventContextDeps{
		decoder:     decoder,
		handlerOpts: policy.handlerOptions,
		filter:      policy.filter,
		catalog:     catalog,
		fdState:     fdState,
		fdPath:      fdState,
		registry:    registry,
		runtime:     runtime,
	}}

	got := newSyscallEventContextDeps(source)
	if got.decoder != decoder || got.catalog != catalog || got.fdState != fdState || got.fdPath != fdState || got.runtime != runtime {
		t.Fatalf("dependency ports = %+v, want source-owned ports", got)
	}
	if got.registry != registry || got.handlerOpts != policy.handlerOptions || got.filter != policy.filter {
		t.Fatal("dependency source did not preserve registry and immutable policy")
	}
}

func TestSyscallEventContextDependencyConstructorAcceptsNilSource(t *testing.T) {
	got := newSyscallEventContextDeps(nil)
	if got.decoder != nil || got.catalog != nil || got.fdState != nil || got.fdPath != nil || got.registry != nil || got.runtime != nil {
		t.Fatalf("nil source dependencies = %+v, want empty dependencies", got)
	}
}

func TestSyscallEventContextUsesSeparateFDReaderPorts(t *testing.T) {
	stateReader := &fakeContextFDStateReader{
		path:        "/persistent",
		cwd:         "/work",
		observation: handler.FDStateObservation{FD: 9, Inode: 42},
	}
	pathReader := &fakeContextFDPathReader{path: "/filter-path"}
	runtime := &fakeContextRuntime{}
	deps := syscallEventContextDeps{
		decoder:     event.NewDecoder(),
		handlerOpts: &cli.Options{},
		filter:      newTraceFilterOptions(&cli.Options{}),
		catalog:     meta.NewCatalog("abbrev"),
		fdState:     stateReader,
		fdPath:      pathReader,
		runtime:     runtime,
	}

	ev := newSyscallEventContextFromViewWithDeps(
		deps,
		syscallEventView{valid: true, pid: 101, tid: 101, sysID: syscallIDByName(t, "getpid")},
		101,
		nil,
		nil,
	)

	if ev.handlerContext.FDStateView != stateReader {
		t.Fatal("handler context did not receive FD state reader port")
	}
	if ev.handlerContext.Runtime != runtime {
		t.Fatal("handler context did not receive runtime port")
	}
	if got, ok := ev.handlerContext.FDState(9); !ok || got.Inode != 42 {
		t.Fatalf("handler context observation = %+v, %v; want inode 42", got, ok)
	}
	if got, ok := deps.fdPathReader().Path(101, 9); !ok || got != "/filter-path" {
		t.Fatalf("event context path reader = %q, %v; want /filter-path", got, ok)
	}
}

var (
	_ handler.FDStateReader   = (*fakeContextFDStateReader)(nil)
	_ event.FDPathReader      = (*fakeContextFDPathReader)(nil)
	_ handler.RuntimeServices = (*fakeContextRuntime)(nil)
)
