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

func TestSyscallEventContextUsesSeparateFDReaderPorts(t *testing.T) {
	stateReader := &fakeContextFDStateReader{
		path:        "/persistent",
		cwd:         "/work",
		observation: handler.FDStateObservation{FD: 9, Inode: 42},
	}
	pathReader := &fakeContextFDPathReader{path: "/filter-path"}
	runtime := &fakeContextRuntime{}
	deps := syscallEventContextDeps{
		decoder: event.NewDecoder(),
		opts:    &cli.Options{},
		catalog: meta.NewCatalog("abbrev"),
		fdState: stateReader,
		fdPath:  pathReader,
		runtime: runtime,
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
