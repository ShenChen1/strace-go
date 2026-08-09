package main

import (
	"testing"

	"strace-go/pkg/event"
	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

func TestDecodeMoveMountPathArgumentsPreservesDirFDPairs(t *testing.T) {
	deps := syscallEventContextDeps{decoder: event.NewDecoder()}
	view := viewWithArgs([6]uint64{3, 0x1000, 4, 0x2000, 0})
	sections := []handler.PayloadSection{
		{Kind: handler.PayloadKindString, Direction: handler.PayloadDirectionIn, ArgIndex: 1, UserPtr: 0x1000, ProbeRet: 0, Data: []byte("source\x00")},
		{Kind: handler.PayloadKindString, Direction: handler.PayloadDirectionIn, ArgIndex: 3, UserPtr: 0x2000, ProbeRet: 0, Data: []byte("target\x00")},
	}

	got := decodePathArguments(deps, view, meta.SyscallTable[429], sections)
	want := []event.PathArgument{{Text: `"source"`, DirFD: 3}, {Text: `"target"`, DirFD: 4}}
	if len(got) != len(want) {
		t.Fatalf("path arguments = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("path argument %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestOpenTreeIsFDStateSyscall(t *testing.T) {
	ev := syscallEventContext{meta: meta.Syscall{Name: "open_tree"}}
	if !ev.isFDStateSyscall() || !ev.shouldRunHandler() {
		t.Fatal("open_tree must keep flowing to maintain returned fd state")
	}
}

func TestOpenTreeUpdatesReturnedFDPath(t *testing.T) {
	store := newFDStateStoreFromMaps(make(map[string]string), nil)
	ev := syscallEventContext{
		view:     syscallEventView{valid: true, pid: 101, tid: 101, ret: 7},
		statePID: 101,
		meta:     meta.Syscall{Name: "open_tree"},
		pathText: `"/dev/full"`,
	}

	ev.updateFDState(store)
	if got := store.paths["101:7"]; got != "/dev/full" {
		t.Fatalf("open_tree fd path = %q, want /dev/full", got)
	}
}

func TestOpenTreeEmptyPathInheritsSourceFDPath(t *testing.T) {
	store := newFDStateStoreFromMaps(map[string]string{"101:4": "/dev/full"}, nil)
	ev := syscallEventContext{
		view: syscallEventView{
			valid: true,
			pid:   101,
			tid:   101,
			args:  [6]uint64{4},
			ret:   7,
		},
		statePID: 101,
		meta:     meta.Syscall{Name: "open_tree"},
		pathText: `""`,
	}

	ev.updateFDState(store)
	if got := store.paths["101:7"]; got != "/dev/full" {
		t.Fatalf("open_tree empty-path fd = %q, want inherited /dev/full", got)
	}
}
