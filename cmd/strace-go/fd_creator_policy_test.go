package main

import (
	"fmt"
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/handler"
)

func TestFDCreatorPoliciesExposeStateContract(t *testing.T) {
	tests := []struct {
		name     string
		args     [6]uint64
		ret      int64
		wantFD   int32
		wantOff  int64
		wantPath string
		wantClo  bool
	}{
		{name: "eventfd", ret: 7, wantFD: 7, wantOff: 11, wantPath: "anon_inode:[eventfd]"},
		{name: "eventfd2", args: [6]uint64{0, 0x100000000 | 0x80000}, ret: 8, wantFD: 8, wantOff: 13, wantPath: "anon_inode:[eventfd]", wantClo: true},
		{name: "epoll_create", args: [6]uint64{1}, ret: 9, wantFD: 9, wantOff: 17, wantPath: "anon_inode:[eventpoll]"},
		{name: "epoll_create1", args: [6]uint64{0x100000000 | 0x80000}, ret: 10, wantFD: 10, wantOff: 19, wantPath: "anon_inode:[eventpoll]", wantClo: true},
		{name: "timerfd_create", args: [6]uint64{1, 0x100000000 | 0x80000}, ret: 11, wantFD: 11, wantOff: 23, wantPath: "anon_inode:[timerfd]", wantClo: true},
		{name: "inotify_init", ret: 12, wantFD: 12, wantOff: 29, wantPath: "anon_inode:inotify"},
		{name: "inotify_init1", args: [6]uint64{0x100000000 | 0x80000}, ret: 13, wantFD: 13, wantOff: 31, wantPath: "anon_inode:inotify", wantClo: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			payload := fdStatePayloadSection(fdStateSnapshotBytes(
				test.wantFD, handler.FDStateFlagIdentity|handler.FDStateFlagOffset,
				0100600, 1, 2, uint64(test.wantFD)+100, test.wantOff,
			))
			event := newFDStateEvent(test.name, test.args, test.ret, []handler.PayloadSection{payload})
			policy, ok := fdCreatorPolicyFor(test.name, event.view)
			if !ok {
				t.Fatalf("missing creator policy for %s", test.name)
			}
			state := policy.state(fdStateSource{view: event.view, payloadSections: []handler.PayloadSection{payload}})
			if state.path != test.wantPath || state.cloexec != test.wantClo || !state.cloexecKnown {
				t.Fatalf("creator state = %+v, want path=%q cloexec=%v known", state, test.wantPath, test.wantClo)
			}

			store := newFDStateStoreFromMaps(nil, nil)
			event.updateFDState(store)
			event.updateFDOffsets(store)
			if got := store.PathMap()[fdStateKey(101, test.wantFD)]; got != test.wantPath {
				t.Fatalf("creator path = %q, want %q", got, test.wantPath)
			}
			if got := store.offsets[fdStateKey(101, test.wantFD)]; got != test.wantOff {
				t.Fatalf("creator offset = %d, want %d", got, test.wantOff)
			}
			if got := store.FDCloexecMap()[fdStateKey(101, test.wantFD)]; got != test.wantClo {
				t.Fatalf("creator cloexec = %v, want %v", got, test.wantClo)
			}
		})
	}
}

func TestFDCreatorSnapshotBoundaries(t *testing.T) {
	store := newFDStateStoreFromMaps(
		map[string]string{"101:9": "stale"},
		map[string]int64{"101:9": 99},
	)
	store.FDStateMap()["101:9"] = handler.FDStateObservation{FD: 9, Inode: 90}
	store.FDCloexecMap()["101:9"] = true

	for _, test := range []struct {
		name    string
		ret     int64
		payload []handler.PayloadSection
		clear   bool
	}{
		{name: "failed", ret: -1},
		{name: "missing", ret: 9, clear: true},
		{name: "wrong fd", ret: 9, clear: true, payload: []handler.PayloadSection{fdStatePayloadSection(fdStateSnapshotBytes(
			10, handler.FDStateFlagIdentity|handler.FDStateFlagOffset, 0100600, 1, 2, 100, 1,
		))}},
	} {
		t.Run(test.name, func(t *testing.T) {
			resetFDCreatorState(store)
			event := newFDStateEvent("epoll_create1", [6]uint64{0x80000}, test.ret, test.payload)
			event.updateFDState(store)
			event.updateFDOffsets(store)
			_, observationExists := store.FDStateMap()["101:9"]
			_, pathExists := store.PathMap()["101:9"]
			_, offsetExists := store.offsets["101:9"]
			_, cloexecExists := store.FDCloexecMap()["101:9"]
			if test.clear && (observationExists || pathExists || offsetExists || cloexecExists) {
				t.Fatal("invalid creator snapshot retained stale state")
			}
			if !test.clear && (!observationExists || !pathExists || !offsetExists || !cloexecExists) {
				t.Fatal("failed creator syscall changed old state")
			}
		})
	}
}

func TestFDCreatorStateEventsRunWhenHidden(t *testing.T) {
	for _, name := range []string{"eventfd", "eventfd2", "epoll_create", "epoll_create1", "timerfd_create", "inotify_init", "inotify_init1"} {
		event := newFDStateEvent(name, [6]uint64{}, 7, nil)
		event.shouldPrint = false
		if !event.isFDStateSyscall() || !event.shouldRunHandler() {
			t.Fatalf("%s must keep running when hidden by the syscall filter", name)
		}
	}
}

func TestInotifyReturnPathUsesEventSourcedState(t *testing.T) {
	ctx := &handler.Context{
		TargetPid: 101,
		Opts:      &cli.Options{ShowPaths: true, ShowPathsMode: 1},
		FdMap: map[string]string{
			"101:12": "anon_inode:inotify",
			"101:13": "anon_inode:inotify",
		},
	}
	for _, test := range []struct {
		name string
		fd   int64
	}{
		{name: "inotify_init", fd: 12},
		{name: "inotify_init1", fd: 13},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := formatSyscallRet(test.name, test.fd, handler.Result{}, ctx); got != formatInotifyFD(test.fd) {
				t.Fatalf("inotify return = %q, want %q", got, formatInotifyFD(test.fd))
			}
		})
	}
}

func formatInotifyFD(fd int64) string {
	return fmt.Sprintf("%d<anon_inode:inotify>", fd)
}

func resetFDCreatorState(store *FDStateStore) {
	store.PathMap()["101:9"] = "stale"
	store.offsets["101:9"] = 99
	store.FDStateMap()["101:9"] = handler.FDStateObservation{FD: 9, Inode: 90}
	store.FDCloexecMap()["101:9"] = true
}
