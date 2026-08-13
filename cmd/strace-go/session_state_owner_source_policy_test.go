package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestSessionUsesTraceStateOwnerPort(t *testing.T) {
	root := repoRootForTest(t)
	sessionSource := readTextFile(t, filepath.Join(root, "cmd", "strace-go", "session_composition.go"))
	ownerSource := readTextFile(t, filepath.Join(root, "cmd", "strace-go", "state_owner_port.go"))
	if !strings.Contains(ownerSource, "type traceStateOwner interface") {
		t.Fatal("TraceState owner port is missing")
	}
	if !strings.Contains(sessionSource, "State         traceStateOwner") {
		t.Fatal("traceSessionDeps must expose the TraceState owner port")
	}
	if strings.Contains(sessionSource, "State         *TraceState") {
		t.Fatal("traceSessionDeps still exposes concrete TraceState")
	}
}

type fakeSessionStateOwner struct{}

func (fakeSessionStateOwner) handleEnvelope(traceEventEnvelope) TraceStateUpdate {
	return TraceStateUpdate{}
}

func (fakeSessionStateOwner) releaseTraceStateUpdate(TraceStateUpdate) {}
func (fakeSessionStateOwner) markUnfinishedPrinted(uint32)             {}
func (fakeSessionStateOwner) requeueUnfinished(uint32)                 {}
func (fakeSessionStateOwner) setUnfinishedEnabled(bool)                {}
func (fakeSessionStateOwner) PendingStaleCount() int                   { return 0 }
func (fakeSessionStateOwner) consumeSuspendedSyscall(int) bool         { return false }
func (fakeSessionStateOwner) rememberPendingExecArgs(int, string)      {}
func (fakeSessionStateOwner) takePendingExecArgs(int) (string, bool)   { return "", false }
func (fakeSessionStateOwner) pendingExecArgsFor(int) (string, bool)    { return "", false }
func (fakeSessionStateOwner) deletePendingExecArgs(int)                {}
func (fakeSessionStateOwner) deleteSuspendedSyscall(int)               {}
func (fakeSessionStateOwner) rememberSuspendedSyscall(int, string)     {}
func (fakeSessionStateOwner) AttachTargetsDone() bool                  { return true }
func (fakeSessionStateOwner) RefreshAttachTargets() error              { return nil }

func TestTraceSessionAcceptsTraceStateOwnerPort(t *testing.T) {
	owner := fakeSessionStateOwner{}
	session := newTestTraceSession(traceSessionDeps{State: owner})

	if session.dependencies.State != owner {
		t.Fatal("session did not retain the injected TraceState owner")
	}
	if session.traceState() != owner {
		t.Fatal("session TraceState accessor did not retain the owner")
	}
	if session.traceEventRouter().state != owner {
		t.Fatal("event router did not receive the TraceState event port")
	}
	if session.traceRunFinalizer().pendingState != owner {
		t.Fatal("run finalizer did not receive the TraceState pending port")
	}
	if session.textRenderer().state != owner {
		t.Fatal("text renderer did not receive the TraceState renderer port")
	}
	textOutput := session.syscallTextOutput()
	execOutput, ok := textOutput.exec.(*ExecSyscallOutput)
	if !ok || execOutput.state != owner {
		t.Fatal("exec output did not receive the TraceState exec port")
	}
	suspendedOutput, ok := textOutput.suspended.(*SuspendedSyscallOutput)
	if !ok || suspendedOutput.state != owner {
		t.Fatal("suspended output did not receive the TraceState suspended port")
	}
}

var _ traceStateOwner = fakeSessionStateOwner{}
