package main

import (
	"os"
	"testing"

	"strace-go/pkg/meta"
)

func syscallIDByName(t *testing.T, name string) uint32 {
	t.Helper()
	for id, sc := range meta.SyscallTable {
		if sc.Name == name {
			return id
		}
	}
	t.Fatalf("syscall %s not found", name)
	return 0
}

func TestFDOffsetsExposeWriteStartAndAdvance(t *testing.T) {
	session := &traceSession{
		targetPid: 101,
		fdState: newFDStateStoreFromMaps(nil, map[string]int64{
			"101:1": 15,
		}, make(map[string]*os.File)),
	}
	eventRaw := &bpfEvent{
		SysId: syscallIDByName(t, "write"),
		Tid:   101,
		Args:  [6]uint64{1, 0x1000, 4},
		Ret:   4,
	}
	scMeta := meta.SyscallTable[eventRaw.SysId]

	off, ok := session.bufferFileOffset(eventRaw, scMeta)
	if !ok || off != 15 {
		t.Fatalf("bufferFileOffset = %d, %v; want 15, true", off, ok)
	}
	session.updateFDOffsets(eventRaw, scMeta)
	if got := session.fdState.offsets["101:1"]; got != 19 {
		t.Fatalf("fd offset after write = %d, want 19", got)
	}
}

func TestFDOffsetsUseEventProcessID(t *testing.T) {
	session := &traceSession{
		targetPid: 100,
		fdState: newFDStateStoreFromMaps(nil, map[string]int64{
			"100:1": 3,
			"101:1": 15,
		}, make(map[string]*os.File)),
	}
	eventRaw := &bpfEvent{
		SysId: syscallIDByName(t, "write"),
		Pid:   101,
		Tid:   101,
		Args:  [6]uint64{1, 0x1000, 4},
		Ret:   4,
	}
	scMeta := meta.SyscallTable[eventRaw.SysId]

	off, ok := session.bufferFileOffset(eventRaw, scMeta)
	if !ok || off != 15 {
		t.Fatalf("child bufferFileOffset = %d, %v; want 15, true", off, ok)
	}
	session.updateFDOffsets(eventRaw, scMeta)
	if got := session.fdState.offsets["101:1"]; got != 19 {
		t.Fatalf("child fd offset after write = %d, want 19", got)
	}
	if got := session.fdState.offsets["100:1"]; got != 3 {
		t.Fatalf("parent fd offset after child write = %d, want 3", got)
	}
}

func TestFDOffsetsUseEventViewForSyscallContext(t *testing.T) {
	session := &traceSession{
		targetPid: 101,
		fdState: newFDStateStoreFromMaps(nil, map[string]int64{
			"101:1": 15,
			"101:2": 30,
		}, make(map[string]*os.File)),
	}
	scMeta := meta.Syscall{Name: "write"}
	ev := syscallEventContext{
		raw:      &bpfEvent{Tid: 101, Args: [6]uint64{2}, Ret: 1},
		view:     syscallEventView{valid: true, tid: 101, args: [6]uint64{1}, ret: 4},
		statePID: 101,
		meta:     scMeta,
	}

	off, ok := session.fdState.BufferFileOffsetFromView(ev.eventView(), scMeta, ev.statePID)
	if !ok || off != 15 {
		t.Fatalf("view buffer offset = %d, %v; want 15, true", off, ok)
	}
	session.updateSyscallFDOffsets(ev)
	if got := session.fdState.offsets["101:1"]; got != 19 {
		t.Fatalf("view fd offset after write = %d, want 19", got)
	}
	if got := session.fdState.offsets["101:2"]; got != 30 {
		t.Fatalf("raw fd offset after write = %d, want unchanged 30", got)
	}
}
