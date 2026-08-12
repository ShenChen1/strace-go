package main

import (
	"testing"

	"strace-go/pkg/handler"
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

func TestFDOffsetsExposeWriteStartAndAdvanceFromView(t *testing.T) {
	store := newFDStateStoreFromMaps(nil, map[string]int64{
		"101:1": 15,
	})
	view := syscallEventView{
		valid: true,
		tid:   101,
		args:  [6]uint64{1, 0x1000, 4},
		ret:   4,
	}
	scMeta := meta.Syscall{Name: "write"}

	off, ok := store.bufferFileOffsetFromView(view, scMeta, 101)
	if !ok || off != 15 {
		t.Fatalf("bufferFileOffset = %d, %v; want 15, true", off, ok)
	}
	store.updateOffsetsFromView(view, scMeta, 101)
	if got := store.offsets["101:1"]; got != 19 {
		t.Fatalf("fd offset after write = %d, want 19", got)
	}
}

func TestFDOffsetsUseStatePIDFromView(t *testing.T) {
	store := newFDStateStoreFromMaps(nil, map[string]int64{
		"100:1": 3,
		"101:1": 15,
	})
	view := syscallEventView{
		valid: true,
		tid:   101,
		args:  [6]uint64{1, 0x1000, 4},
		ret:   4,
	}
	scMeta := meta.Syscall{Name: "write"}

	off, ok := store.bufferFileOffsetFromView(view, scMeta, 101)
	if !ok || off != 15 {
		t.Fatalf("child bufferFileOffset = %d, %v; want 15, true", off, ok)
	}
	store.updateOffsetsFromView(view, scMeta, 101)
	if got := store.offsets["101:1"]; got != 19 {
		t.Fatalf("child fd offset after write = %d, want 19", got)
	}
	if got := store.offsets["100:1"]; got != 3 {
		t.Fatalf("parent fd offset after child write = %d, want 3", got)
	}
}

func TestSyscallExitEffectsUpdateFDOffsetsUsesEventView(t *testing.T) {
	session := newBareTestTraceSession(traceSessionDeps{
		TargetPID: 101,
		FDState: newFDStateStoreFromMaps(nil, map[string]int64{
			"101:1": 15,
			"101:2": 30,
		}),
	})
	scMeta := meta.Syscall{Name: "write"}
	ev := syscallEventContext{
		view:     syscallEventView{valid: true, tid: 101, args: [6]uint64{1}, ret: 4},
		statePID: 101,
		meta:     scMeta,
	}

	newTraceSessionSyscallExitEffects(nil, session.fdStateStore(), session.fdStateStore()).UpdateFDOffsets(ev)
	if got := session.fdStateStore().offsets["101:1"]; got != 19 {
		t.Fatalf("view fd offset after write = %d, want 19", got)
	}
	if got := session.fdStateStore().offsets["101:2"]; got != 30 {
		t.Fatalf("raw fd offset after write = %d, want unchanged 30", got)
	}
}

func TestFDOffsetsUpdateUsesEffectiveMetadata(t *testing.T) {
	store := newFDStateStoreFromMaps(nil, map[string]int64{"101:1": 15})
	ev := syscallEventContext{
		view:     syscallEventView{valid: true, tid: 101, args: [6]uint64{1}, ret: 4},
		statePID: 101,
		handlerContext: &handler.Context{
			ScMeta: meta.Syscall{Name: "write"},
		},
	}

	ev.updateFDOffsets(store)

	if got := store.offsets["101:1"]; got != 19 {
		t.Fatalf("fd offset after effective metadata write = %d, want 19", got)
	}
}
