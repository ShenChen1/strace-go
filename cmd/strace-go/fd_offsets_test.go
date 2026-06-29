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
		fdOffsets: map[string]int64{"101:1": 15},
		fdFiles:   make(map[string]*os.File),
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
	if got := session.fdOffsets["101:1"]; got != 19 {
		t.Fatalf("fd offset after write = %d, want 19", got)
	}
}

func TestFDOffsetsUseEventProcessID(t *testing.T) {
	session := &traceSession{
		targetPid: 100,
		fdOffsets: map[string]int64{
			"100:1": 3,
			"101:1": 15,
		},
		fdFiles: make(map[string]*os.File),
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
	if got := session.fdOffsets["101:1"]; got != 19 {
		t.Fatalf("child fd offset after write = %d, want 19", got)
	}
	if got := session.fdOffsets["100:1"]; got != 3 {
		t.Fatalf("parent fd offset after child write = %d, want 3", got)
	}
}
