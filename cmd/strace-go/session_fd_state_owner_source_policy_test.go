package main

import (
	"path/filepath"
	"strings"
	"testing"

	"strace-go/pkg/event"
	"strace-go/pkg/handler"
)

func TestSessionUsesFDStateOwnerPort(t *testing.T) {
	root := repoRootForTest(t)
	sessionSource := readTextFile(t, filepath.Join(root, "cmd", "strace-go", "session_composition.go"))
	ownerSource := readTextFile(t, filepath.Join(root, "cmd", "strace-go", "fd_state_owner_port.go"))
	if !strings.Contains(ownerSource, "type traceFDStateOwner interface") {
		t.Fatal("FD state owner port is missing")
	}
	if !strings.Contains(sessionSource, "FDState       traceFDStateOwner") {
		t.Fatal("traceSessionDeps must expose the FD state owner port")
	}
	if strings.Contains(sessionSource, "FDState       *FDStateStore") {
		t.Fatal("traceSessionDeps still exposes concrete FDStateStore")
	}
}

type fakeSessionFDStateOwner struct{}

func (fakeSessionFDStateOwner) TaintHistory() {}

func (fakeSessionFDStateOwner) Path(int, int32) (string, bool) {
	return "", false
}

func (fakeSessionFDStateOwner) Cwd(int) (string, bool) {
	return "", false
}

func (fakeSessionFDStateOwner) Observation(int, int32) (handler.FDStateObservation, bool) {
	return handler.FDStateObservation{}, false
}

func (fakeSessionFDStateOwner) ApplyFDState(fdStateUpdate) {}

func (fakeSessionFDStateOwner) ApplyFDOffsets(fdOffsetUpdate) {}

func (fakeSessionFDStateOwner) CleanupClosedFD(fdCloseUpdate) {}

func (fakeSessionFDStateOwner) InheritProcessState(int, int) {}

func (fakeSessionFDStateOwner) CleanupProcess(int) {}

func (fakeSessionFDStateOwner) CloseOnExecProcess(int) {}

func TestTraceSessionAcceptsFDStateOwnerPort(t *testing.T) {
	owner := fakeSessionFDStateOwner{}
	session := newTestTraceSession(traceSessionDeps{FDState: owner})

	if session.dependencies.FDState != owner {
		t.Fatal("session did not retain the injected FD state owner")
	}
	if session.fdStateStore() != owner {
		t.Fatal("session FD state accessor did not retain the owner")
	}
	dispatcher, ok := session.traceEventRouter().dispatcher.(*TraceEventDispatcher)
	if !ok {
		t.Fatalf("router dispatcher = %T, want *TraceEventDispatcher", session.traceEventRouter().dispatcher)
	}
	deps := dispatcher.contextDeps
	if deps.fdState != owner || deps.fdPath != owner {
		t.Fatal("event context did not receive the FD reader projections")
	}
}

var (
	_ traceFDStateOwner  = fakeSessionFDStateOwner{}
	_ event.FDPathReader = fakeSessionFDStateOwner{}
)
