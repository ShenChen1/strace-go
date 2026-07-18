package main

import (
	"encoding/binary"
	"os"
	"testing"

	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

func TestFDStateStoreCleanupClosedFDRemovesOwnedState(t *testing.T) {
	store := newFDStateStoreFromMaps(
		map[string]string{"101:3": "/tmp/remove", "101:4": "/tmp/keep"},
		map[string]int64{"101:3": 12, "101:4": 99},
	)

	store.cleanupClosedFDFromView(syscallEventView{
		valid: true,
		args:  [6]uint64{3},
		ret:   0,
	}, meta.Syscall{Name: "close"}, 101)

	if _, ok := store.paths["101:3"]; ok {
		t.Fatal("closed fd path was not removed")
	}
	if _, ok := store.offsets["101:3"]; ok {
		t.Fatal("closed fd offset was not removed")
	}
	if got := store.paths["101:4"]; got != "/tmp/keep" {
		t.Fatalf("unrelated fd path = %q, want /tmp/keep", got)
	}
}

func TestSyscallEventContextUpdateFDStateUsesEventViewForOpenedPath(t *testing.T) {
	store := newFDStateStoreFromMaps(make(map[string]string), nil)
	ev := syscallEventContext{
		view:     syscallEventView{valid: true, pid: 201, tid: 201, ret: 7},
		statePID: 101,
		meta:     meta.Syscall{Name: "openat"},
		pathText: `"/tmp/view-path"`,
	}

	ev.updateFDState(store)

	if got := store.paths["101:7"]; got != "/tmp/view-path" {
		t.Fatalf("view fd path = %q, want /tmp/view-path", got)
	}
	if got := store.paths["101:4"]; got != "" {
		t.Fatalf("raw fd path = %q, want empty", got)
	}
}

func TestSyscallEventContextUpdateFDStateUsesEventViewForDup(t *testing.T) {
	store := newFDStateStoreFromMaps(map[string]string{"101:5": "/tmp/source"}, nil)
	ev := syscallEventContext{
		view:     syscallEventView{valid: true, pid: 201, tid: 201, args: [6]uint64{5}, ret: 6},
		statePID: 101,
		meta:     meta.Syscall{Name: "dup"},
	}

	ev.updateFDState(store)

	if got := store.paths["101:6"]; got != "/tmp/source" {
		t.Fatalf("view dup path = %q, want /tmp/source", got)
	}
	if got := store.paths["101:4"]; got != "" {
		t.Fatalf("raw dup path = %q, want empty", got)
	}
}

func TestSyscallEventContextUpdateFDStateUsesEffectiveMetadata(t *testing.T) {
	store := newFDStateStoreFromMaps(make(map[string]string), nil)
	ev := syscallEventContext{
		view:     syscallEventView{valid: true, pid: 201, tid: 201, ret: 7},
		statePID: 101,
		pathText: `"/tmp/effective-path"`,
		handlerContext: &handler.Context{
			ScMeta: meta.Syscall{Name: "openat"},
		},
	}

	ev.updateFDState(store)

	if got := store.paths["101:7"]; got != "/tmp/effective-path" {
		t.Fatalf("effective metadata fd path = %q, want /tmp/effective-path", got)
	}
}

func TestSyscallEventContextUpdateFDStateBuildsPayloadWithEffectiveMetadata(t *testing.T) {
	readEnd, writeEnd, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe() failed: %v", err)
	}
	defer readEnd.Close()
	defer writeEnd.Close()

	raw := &bpfEvent{
		Pid:          uint32(os.Getpid()),
		Tid:          uint32(os.Getpid()),
		EventType:    bpfEventTypeExit,
		Ret:          0,
		ProbeRetExit: 0,
		DataLen:      uint32(payloadExitArgOffset + 8),
	}
	binary.LittleEndian.PutUint32(raw.StrArg[payloadExitArgOffset:], uint32(readEnd.Fd()))
	binary.LittleEndian.PutUint32(raw.StrArg[payloadExitArgOffset+4:], uint32(writeEnd.Fd()))
	store := newFDStateStoreFromMaps(make(map[string]string), nil)
	ev := syscallEventContextFromRawForTest(raw, meta.Syscall{Name: "pipe"}, 101)
	ev.handlerContext = &handler.Context{
		ScMeta: meta.Syscall{Name: "pipe"},
	}

	ev.updateFDState(store)

	readKey := fdStateKey(101, int32(readEnd.Fd()))
	writeKey := fdStateKey(101, int32(writeEnd.Fd()))
	if store.paths[readKey] == "" {
		t.Fatalf("fd path %q missing after effective metadata payload update", readKey)
	}
	if store.paths[writeKey] == "" {
		t.Fatalf("fd path %q missing after effective metadata payload update", writeKey)
	}
}

func TestTraceSessionCleanupClosedFDUsesEventView(t *testing.T) {
	store := newFDStateStoreFromMaps(
		map[string]string{"101:3": "/tmp/remove", "101:4": "/tmp/keep"},
		map[string]int64{"101:3": 12, "101:4": 99},
	)
	session := &traceSession{fdState: store}
	ev := syscallEventContext{
		view:     syscallEventView{valid: true, args: [6]uint64{3}, ret: 0},
		statePID: 101,
		meta:     meta.Syscall{Name: "close"},
	}

	session.cleanupClosedFD(ev)

	if _, ok := store.paths["101:3"]; ok {
		t.Fatal("view-selected fd path was not removed")
	}
	if _, ok := store.offsets["101:3"]; ok {
		t.Fatal("view-selected fd offset was not removed")
	}
	if got := store.paths["101:4"]; got != "/tmp/keep" {
		t.Fatalf("raw-selected fd path = %q, want untouched /tmp/keep", got)
	}
	if got := store.offsets["101:4"]; got != 99 {
		t.Fatalf("raw-selected fd offset = %d, want untouched 99", got)
	}
}

func TestSyscallEventContextCleanupClosedFDUsesEffectiveMetadata(t *testing.T) {
	store := newFDStateStoreFromMaps(
		map[string]string{"101:3": "/tmp/remove"},
		map[string]int64{"101:3": 12},
	)
	ev := syscallEventContext{
		view:     syscallEventView{valid: true, args: [6]uint64{3}, ret: 0},
		statePID: 101,
		handlerContext: &handler.Context{
			ScMeta: meta.Syscall{Name: "close"},
		},
	}

	ev.cleanupClosedFD(store)

	if _, ok := store.paths["101:3"]; ok {
		t.Fatal("effective metadata close did not remove fd path")
	}
	if _, ok := store.offsets["101:3"]; ok {
		t.Fatal("effective metadata close did not remove fd offset")
	}
}
