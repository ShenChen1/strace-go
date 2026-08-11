package main

import (
	"testing"

	"strace-go/pkg/meta"
)

type recordingFDStateUpdatePort struct {
	update *fdStateUpdate
}

func (p *recordingFDStateUpdatePort) ApplyFDState(update fdStateUpdate) {
	p.update = &update
}

type recordingFDOffsetUpdatePort struct {
	update *fdOffsetUpdate
}

func (p *recordingFDOffsetUpdatePort) ApplyFDOffsets(update fdOffsetUpdate) {
	p.update = &update
}

type recordingFDCloseUpdatePort struct {
	update *fdCloseUpdate
}

func (p *recordingFDCloseUpdatePort) CleanupClosedFD(update fdCloseUpdate) {
	p.update = &update
}

func TestSyscallEventContextSendsTypedFDMutationCommands(t *testing.T) {
	catalog := meta.NewCatalog("abbrev")
	view := syscallEventView{
		valid: true,
		pid:   101,
		tid:   102,
		ret:   7,
		args:  [6]uint64{3, 4, 5},
	}
	ev := syscallEventContext{
		view:            view,
		statePID:        101,
		meta:            meta.Syscall{Name: "close"},
		catalog:         catalog,
		pathText:        "/tmp/input",
		payloadSections: nil,
	}

	statePort := &recordingFDStateUpdatePort{}
	offsetPort := &recordingFDOffsetUpdatePort{}
	closePort := &recordingFDCloseUpdatePort{}
	ev.updateFDState(statePort)
	ev.updateFDOffsets(offsetPort)
	ev.cleanupClosedFD(closePort)

	if statePort.update == nil {
		t.Fatal("FD state update port did not receive a command")
	}
	if got := statePort.update.targetPID; got != 101 {
		t.Fatalf("state target PID = %d, want 101", got)
	}
	if got := statePort.update.pathText; got != "/tmp/input" {
		t.Fatalf("state path = %q, want /tmp/input", got)
	}
	if statePort.update.catalog != catalog || statePort.update.source.view != view {
		t.Fatal("state command lost event context identity")
	}
	if offsetPort.update == nil || offsetPort.update.view != view || offsetPort.update.statePID != 101 {
		t.Fatalf("offset command = %+v, want event view and target PID", offsetPort.update)
	}
	if closePort.update == nil || closePort.update.view != view || closePort.update.statePID != 101 {
		t.Fatalf("close command = %+v, want event view and target PID", closePort.update)
	}
}

func TestSyscallEventContextAcceptsAbsentMutationPorts(t *testing.T) {
	ev := syscallEventContext{}
	ev.updateFDState(nil)
	ev.updateFDOffsets(nil)
	ev.cleanupClosedFD(nil)
}

var (
	_ fdStateUpdatePort  = (*recordingFDStateUpdatePort)(nil)
	_ fdOffsetUpdatePort = (*recordingFDOffsetUpdatePort)(nil)
	_ fdCloseUpdatePort  = (*recordingFDCloseUpdatePort)(nil)
)
