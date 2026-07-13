package main

import (
	"os"
	"testing"

	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

func TestFDStateStoreCleanupClosedFDRemovesOwnedState(t *testing.T) {
	tmp, err := os.CreateTemp(t.TempDir(), "fd-state-*")
	if err != nil {
		t.Fatalf("CreateTemp failed: %v", err)
	}
	defer tmp.Close()

	store := newFDStateStoreFromMaps(
		map[string]string{"101:3": tmp.Name(), "101:4": "/tmp/keep"},
		map[string]int64{"101:3": 12, "101:4": 99},
		map[string]*os.File{"101:3": tmp},
	)

	store.CleanupClosedFDFromView(syscallEventView{
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
	if _, ok := store.files["101:3"]; ok {
		t.Fatal("closed fd file was not removed")
	}
	if got := store.paths["101:4"]; got != "/tmp/keep" {
		t.Fatalf("unrelated fd path = %q, want /tmp/keep", got)
	}
}

func TestFDStateStoreUpdateFromSyscallUsesEventViewForOpenedPath(t *testing.T) {
	store := newFDStateStoreFromMaps(make(map[string]string), nil, nil)
	ev := syscallEventContext{
		raw:      &bpfEvent{Pid: 1, Tid: 1, Ret: 4},
		view:     syscallEventView{valid: true, pid: 201, tid: 201, ret: 7},
		statePID: 101,
		meta:     meta.Syscall{Name: "openat"},
		pathText: `"/tmp/view-path"`,
	}

	store.UpdateFromSyscall(ev)

	if got := store.paths["101:7"]; got != "/tmp/view-path" {
		t.Fatalf("view fd path = %q, want /tmp/view-path", got)
	}
	if got := store.paths["101:4"]; got != "" {
		t.Fatalf("raw fd path = %q, want empty", got)
	}
}

func TestFDStateStoreUpdateFromSyscallUsesEventViewForDup(t *testing.T) {
	store := newFDStateStoreFromMaps(map[string]string{"101:5": "/tmp/source"}, nil, nil)
	ev := syscallEventContext{
		raw:      &bpfEvent{Pid: 1, Tid: 1, Args: [6]uint64{3}, Ret: 4},
		view:     syscallEventView{valid: true, pid: 201, tid: 201, args: [6]uint64{5}, ret: 6},
		statePID: 101,
		meta:     meta.Syscall{Name: "dup"},
	}

	store.UpdateFromSyscall(ev)

	if got := store.paths["101:6"]; got != "/tmp/source" {
		t.Fatalf("view dup path = %q, want /tmp/source", got)
	}
	if got := store.paths["101:4"]; got != "" {
		t.Fatalf("raw dup path = %q, want empty", got)
	}
}

func TestTraceSessionCleanupClosedFDUsesEventView(t *testing.T) {
	store := newFDStateStoreFromMaps(
		map[string]string{"101:3": "/tmp/remove", "101:4": "/tmp/keep"},
		map[string]int64{"101:3": 12, "101:4": 99},
		make(map[string]*os.File),
	)
	session := &traceSession{fdState: store}
	ev := syscallEventContext{
		raw:      &bpfEvent{Args: [6]uint64{4}, Ret: 0},
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
		make(map[string]*os.File),
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
