package main

import (
	"encoding/binary"
	"path/filepath"
	"strings"
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/event"
	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

func TestFDPathOverlayFeedsPathFilterAndFormatter(t *testing.T) {
	store := newFDStateStoreFromMaps(nil, nil)
	opts := cli.ParseArgs([]string{"-y", "-P", "/dev/full", "--trace=dup", "/bin/true"})
	deps := syscallEventContextDeps{
		decoder:     event.NewDecoder(),
		handlerOpts: opts,
		filter:      newTraceFilterOptions(opts),
		fdState:     store,
	}
	view := syscallEventView{
		valid:     true,
		pid:       101,
		tid:       101,
		sysID:     32,
		eventType: bpfEventTypeExit,
		args:      [6]uint64{9},
		ret:       5,
	}
	sections := []handler.PayloadSection{{
		Kind:      handler.PayloadKindFDPath,
		Direction: handler.PayloadDirectionIn,
		ArgIndex:  0,
		ProbeRet:  0,
		Data:      []byte("/dev/full\x00"),
	}}

	ev := newSyscallEventContextFromViewWithDeps(deps, view, 101, nil, sections)
	if !ev.shouldOutput() {
		t.Fatal("dup with an event-time /dev/full path did not match -P")
	}
	if got := handler.FormatFdWithPath(ev.handlerContext, 9); got != "9</dev/full>" {
		t.Fatalf("event-time fd path = %q, want 9</dev/full>", got)
	}

	ev.updateFDState(store)
	for _, key := range []string{"101:9", "101:5"} {
		if got := store.paths[key]; got != "/dev/full" {
			t.Fatalf("FD path %s = %q, want /dev/full", key, got)
		}
	}
}

func TestFDPathOverlayReaderDoesNotMutateStoreBeforeCommit(t *testing.T) {
	store := newFDStateStoreFromMaps(map[string]string{"101:9": "/old"}, nil)
	opts := cli.ParseArgs([]string{"-y", "--trace=dup", "/bin/true"})
	deps := syscallEventContextDeps{
		decoder:     event.NewDecoder(),
		handlerOpts: opts,
		filter:      newTraceFilterOptions(opts),
		fdState:     store,
	}
	view := syscallEventView{
		valid:     true,
		pid:       101,
		tid:       101,
		sysID:     32,
		eventType: bpfEventTypeExit,
		args:      [6]uint64{9},
		ret:       5,
	}
	ev := newSyscallEventContextFromViewWithDeps(deps, view, 101, nil, []handler.PayloadSection{{
		Kind:      handler.PayloadKindFDPath,
		Direction: handler.PayloadDirectionIn,
		ArgIndex:  0,
		ProbeRet:  0,
		Data:      []byte("/new\x00"),
	}})

	if got := handler.FormatFdWithPath(ev.handlerContext, 9); got != "9</new>" {
		t.Fatalf("overlay path = %q, want 9</new>", got)
	}
	if got, ok := store.Path(101, 9); !ok || got != "/old" {
		t.Fatalf("store path before commit = %q, %v; want /old", got, ok)
	}
}

func TestDup3ReturnUsesSourcePathButArgumentsKeepTargetSnapshot(t *testing.T) {
	store := newFDStateStoreFromMaps(map[string]string{
		"101:0": "/dev/null",
		"101:5": "/dev/full",
	}, nil)
	opts := cli.ParseArgs([]string{"-y", "--trace=dup3", "/bin/true"})
	deps := syscallEventContextDeps{
		decoder:     event.NewDecoder(),
		handlerOpts: opts,
		filter:      newTraceFilterOptions(opts),
		fdState:     store,
		registry:    handler.NewRegistry(),
		catalog:     meta.NewCatalog("abbrev"),
	}
	view := syscallEventView{
		valid:     true,
		pid:       101,
		tid:       101,
		sysID:     syscallIDByName(t, "dup3"),
		eventType: bpfEventTypeExit,
		args:      [6]uint64{0, 5},
		ret:       5,
	}
	ev := newSyscallEventContextFromViewWithDeps(deps, view, 101, nil, []handler.PayloadSection{
		{
			Kind:      handler.PayloadKindFDPath,
			Direction: handler.PayloadDirectionIn,
			ArgIndex:  0,
			ProbeRet:  0,
			Data:      []byte("/dev/null\x00"),
		},
		{
			Kind:      handler.PayloadKindFDPath,
			Direction: handler.PayloadDirectionIn,
			ArgIndex:  1,
			ProbeRet:  0,
			Data:      []byte("/dev/full\x00"),
		},
	})
	result := defaultHandleSyscall("dup3", ev.handlerContext)
	if got, want := result.ArgParts, []string{"0</dev/null>", "5</dev/full>", "0"}; len(got) != len(want) || got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
		t.Fatalf("dup3 args = %#v, want %#v", got, want)
	}

	ev.updateFDState(store)
	if got := formatSyscallRet("dup3", view.ret, result, ev.handlerContextForFormatting()); got != "5</dev/null>" {
		t.Fatalf("dup3 return = %q, want 5</dev/null>", got)
	}
}

func TestDup3ReturnOverlayIgnoresFailedReturn(t *testing.T) {
	eventView := eventFDStateView{paths: map[int32]string{
		0: "/dev/null",
		5: "/dev/full",
	}}
	got, applied := dupReturnFDView(eventView, "dup3", syscallEventView{
		valid:     true,
		eventType: bpfEventTypeExit,
		args:      [6]uint64{0, 5},
		ret:       -9,
	}, newFDStateStoreFromMaps(map[string]string{"101:0": "/dev/null"}, nil), 101)
	if applied {
		t.Fatal("failed dup3 return received an event-time path overlay")
	}
	if path, ok := got.Path(5); !ok || path != "/dev/full" {
		t.Fatalf("failed dup3 target path = %q, %v; want /dev/full", path, ok)
	}
}

func TestDup2ReturnUsesSourcePathButArgumentsKeepTargetSnapshot(t *testing.T) {
	store := newFDStateStoreFromMaps(map[string]string{
		"101:0": "/dev/null",
		"101:5": "/dev/full",
	}, nil)
	opts := cli.ParseArgs([]string{"-y", "--trace=dup2", "/bin/true"})
	deps := syscallEventContextDeps{
		decoder:     event.NewDecoder(),
		handlerOpts: opts,
		filter:      newTraceFilterOptions(opts),
		fdState:     store,
		registry:    handler.NewRegistry(),
		catalog:     meta.NewCatalog("abbrev"),
	}
	view := syscallEventView{
		valid:     true,
		pid:       101,
		tid:       101,
		sysID:     syscallIDByName(t, "dup2"),
		eventType: bpfEventTypeExit,
		args:      [6]uint64{0, 5},
		ret:       5,
	}
	ev := newSyscallEventContextFromViewWithDeps(deps, view, 101, nil, []handler.PayloadSection{
		{
			Kind:      handler.PayloadKindFDPath,
			Direction: handler.PayloadDirectionIn,
			ArgIndex:  0,
			ProbeRet:  0,
			Data:      []byte("/dev/null\x00"),
		},
		{
			Kind:      handler.PayloadKindFDPath,
			Direction: handler.PayloadDirectionIn,
			ArgIndex:  1,
			ProbeRet:  0,
			Data:      []byte("/dev/full\x00"),
		},
	})
	result := defaultHandleSyscall("dup2", ev.handlerContext)
	if got, want := result.ArgParts, []string{"0</dev/null>", "5</dev/full>"}; len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("dup2 args = %#v, want %#v", got, want)
	}

	ev.updateFDState(store)
	if got := formatSyscallRet("dup2", view.ret, result, ev.handlerContextForFormatting()); got != "5</dev/null>" {
		t.Fatalf("dup2 return = %q, want 5</dev/null>", got)
	}
}

func TestFDPathOverlayStripsEventStatePrefix(t *testing.T) {
	data := make([]byte, handler.FDPathStatePrefixSize+len("/null")+1)
	binary.LittleEndian.PutUint32(data[0:4], 0)
	binary.LittleEndian.PutUint32(data[4:8], 1|2)
	binary.LittleEndian.PutUint32(data[8:12], 0x21b6)
	binary.LittleEndian.PutUint64(data[16:24], 7)
	binary.LittleEndian.PutUint64(data[24:32], 0x100003)
	binary.LittleEndian.PutUint64(data[32:40], 5)
	copy(data[handler.FDPathStatePrefixSize:], "/null\x00")

	overlay := fdPathOverlayFromSections([]handler.PayloadSection{{
		Kind:      handler.PayloadKindFDPath,
		Direction: handler.PayloadDirectionIn,
		ArgIndex:  0,
		ProbeRet:  0,
		Data:      data,
	}})
	view := overlay.resolve(syscallEventView{
		valid: true,
		args:  [6]uint64{0},
	})
	path, ok := view.Path(0)
	if !ok || path != "/null" {
		t.Fatalf("decoded event path = %q, %v; want /null", path, ok)
	}
	state, ok := view.Observation(0)
	if !ok || state.Mode != 0x21b6 || state.Rdev != 0x100003 {
		t.Fatalf("decoded event state = %+v, %v; want mode/rdev snapshot", state, ok)
	}
}

func TestFDPathOverlayResolvesNestedFDFromSnapshot(t *testing.T) {
	data := make([]byte, handler.FDPathStatePrefixSize+len("/dev/full")+1)
	binary.LittleEndian.PutUint32(data[0:4], 9)
	binary.LittleEndian.PutUint32(data[4:8], handler.FDStateFlagIdentity)
	copy(data[handler.FDPathStatePrefixSize:], "/dev/full\x00")

	overlay := fdPathOverlayFromSections([]handler.PayloadSection{{
		Kind:      handler.PayloadKindFDPath,
		Direction: handler.PayloadDirectionIn,
		ArgIndex:  handler.PayloadFDPathNestedArgIndex,
		ProbeRet:  0,
		Data:      data,
	}})
	view := overlay.resolve(syscallEventView{valid: true})
	if path, ok := view.Path(9); !ok || path != "/dev/full" {
		t.Fatalf("nested event path = %q, %v; want fd 9 /dev/full", path, ok)
	}
	if _, ok := view.Path(0); ok {
		t.Fatal("nested event path was resolved through a syscall argument")
	}
}

func TestFDPathSnapshotReachesHandlerFormatter(t *testing.T) {
	data := make([]byte, handler.FDPathStatePrefixSize+len("/null")+1)
	binary.LittleEndian.PutUint32(data[0:4], 0)
	binary.LittleEndian.PutUint32(data[4:8], 1|2)
	binary.LittleEndian.PutUint32(data[8:12], 0x21b6)
	binary.LittleEndian.PutUint64(data[24:32], 0x100003)
	copy(data[handler.FDPathStatePrefixSize:], "/null\x00")

	opts := cli.ParseArgs([]string{"-yy", "--trace=dup", "/bin/true"})
	deps := syscallEventContextDeps{
		decoder:     event.NewDecoder(),
		handlerOpts: opts,
		filter:      newTraceFilterOptions(opts),
		fdState:     newFDStateStoreFromMaps(nil, nil),
		registry:    handler.NewRegistry(),
	}
	ev := newSyscallEventContextFromViewWithDeps(deps, syscallEventView{
		valid: true,
		pid:   101,
		tid:   101,
		sysID: 32,
		args:  [6]uint64{0},
		ret:   3,
	}, 101, nil, []handler.PayloadSection{{
		Kind:      handler.PayloadKindFDPath,
		Direction: handler.PayloadDirectionIn,
		ArgIndex:  0,
		ProbeRet:  0,
		Data:      data,
	}})
	result := defaultHandleSyscall("dup", ev.handlerContext)
	if len(result.ArgParts) != 1 || strings.ContainsAny(result.ArgParts[0], "\x00\x01\x02\x03") {
		t.Fatalf("handler fd argument = %q, want decoded path without binary state prefix", result.ArgParts)
	}
	if !strings.Contains(result.ArgParts[0], "/null") {
		t.Fatalf("handler fd argument = %q, want /null", result.ArgParts[0])
	}
}

func TestTraceCommandFDStateSeedsInheritedCWD(t *testing.T) {
	seed := initialTraceCommandFDSeed(101, "/opt/strace-go")
	store := newFDStateStoreFromSeed(seed)
	if got, ok := store.Cwd(101); !ok || got != "/opt/strace-go" {
		t.Fatalf("initial cwd = %q, %v; want /opt/strace-go", got, ok)
	}
}

func TestFDPathOverlayDoesNotOverwriteKnownCWD(t *testing.T) {
	paths := map[string]string{"101:cwd": "/opt/strace-go/strace-upstream/tests"}
	source := fdStateSource{
		view: syscallEventView{valid: true, pid: 101, tid: 101},
		payloadSections: []handler.PayloadSection{{
			Kind:      handler.PayloadKindFDPath,
			Direction: handler.PayloadDirectionIn,
			ArgIndex:  handler.PayloadFDPathCwdArgIndex,
			ProbeRet:  0,
			Data:      []byte("/partial-cwd"),
		}},
	}

	updateFDPathStateFromSource(source, 101, paths, nil)
	if got := paths["101:cwd"]; got != "/opt/strace-go/strace-upstream/tests" {
		t.Fatalf("known cwd = %q, want preserved complete cwd", got)
	}
}

func TestSignalFDEventTimePathReachesReturnFormatter(t *testing.T) {
	tests := []struct {
		name     string
		syscall  string
		args     [6]uint64
		ret      int64
		mask     uint64
		wantPath string
	}{
		{
			name:     "signalfd4 create",
			syscall:  "signalfd4",
			args:     [6]uint64{^uint64(0), 0x1000, 8, 0x80000},
			ret:      8,
			mask:     1 << 11,
			wantPath: "8<signalfd:[USR2]>",
		},
		{
			name:     "signalfd update",
			syscall:  "signalfd",
			args:     [6]uint64{7, 0x2000, 8},
			ret:      7,
			mask:     1<<11 | 1<<16,
			wantPath: "7<signalfd:[USR2 CHLD]>",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			opts := cli.ParseArgs([]string{"--decode-fds=signalfd", "/bin/true"})
			store := newFDStateStoreFromMaps(nil, nil)
			deps := syscallEventContextDeps{
				decoder:     event.NewDecoder(),
				handlerOpts: opts,
				filter:      newTraceFilterOptions(opts),
				fdState:     store,
				registry:    handler.NewRegistry(),
			}
			sections := []handler.PayloadSection{
				signalMaskPayloadSection(test.mask),
				fdStatePayloadSection(fdStateSnapshotBytes(
					int32(test.ret), handler.FDStateFlagIdentity|handler.FDStateFlagOffset,
					0100600, 1, 2, uint64(test.ret)+100, 37,
				)),
			}
			ev := newSyscallEventContextFromViewWithDeps(deps, syscallEventView{
				valid:     true,
				eventType: bpfEventTypeExit,
				sysID:     syscallIDByName(t, test.syscall),
				args:      test.args,
				ret:       test.ret,
			}, 101, nil, sections)

			if got := formatSyscallRet(test.syscall, test.ret, handler.Result{}, ev.handlerContextForFormatting()); got != test.wantPath {
				t.Fatalf("signalfd return = %q, want %q", got, test.wantPath)
			}
			if _, ok := store.Path(101, int32(test.ret)); ok {
				t.Fatal("event-time signalfd overlay mutated the persistent store")
			}
		})
	}
}

func TestSignalFDReturnOverlayKeepsArgumentState(t *testing.T) {
	store := newFDStateStoreFromMaps(map[string]string{
		"101:4": "signalfd:[USR2]",
	}, nil)
	opts := cli.ParseArgs([]string{"-yy", "--decode-fds=signalfd", "--trace=signalfd4", "/bin/true"})
	deps := syscallEventContextDeps{
		decoder:     event.NewDecoder(),
		handlerOpts: opts,
		filter:      newTraceFilterOptions(opts),
		catalog:     meta.NewCatalog("abbrev"),
		fdState:     store,
		registry:    handler.NewRegistry(),
	}
	view := syscallEventView{
		valid:     true,
		eventType: bpfEventTypeExit,
		sysID:     syscallIDByName(t, "signalfd4"),
		args:      [6]uint64{4, 0x1000, 8, 0},
		ret:       4,
	}
	ev := newSyscallEventContextFromViewWithDeps(deps, view, 101, nil, []handler.PayloadSection{
		signalMaskPayloadSection(1<<11 | 1<<16),
		fdStatePayloadSection(fdStateSnapshotBytes(
			4, handler.FDStateFlagIdentity|handler.FDStateFlagOffset,
			0100600, 1, 2, 104, 37,
		)),
	})
	result := defaultHandleSyscall("signalfd4", ev.handlerContext)
	if got := result.ArgParts[0]; got != "4<signalfd:[USR2]>" {
		t.Fatalf("signalfd argument = %q, want old mask path", got)
	}
	if got := formatSyscallRet("signalfd4", view.ret, result, ev.handlerContextForFormatting()); got != "4<signalfd:[USR2 CHLD]>" {
		t.Fatalf("signalfd return = %q, want new mask path", got)
	}
}

func TestSignalFDEventTimePathIgnoresFailedReturn(t *testing.T) {
	opts := cli.ParseArgs([]string{"--decode-fds=signalfd", "/bin/true"})
	deps := syscallEventContextDeps{
		decoder:     event.NewDecoder(),
		handlerOpts: opts,
		filter:      newTraceFilterOptions(opts),
		fdState:     newFDStateStoreFromMaps(nil, nil),
		registry:    handler.NewRegistry(),
	}
	ev := newSyscallEventContextFromViewWithDeps(deps, syscallEventView{
		valid:     true,
		eventType: bpfEventTypeExit,
		sysID:     syscallIDByName(t, "signalfd"),
		args:      [6]uint64{7, 0x1000, 8},
		ret:       -14,
	}, 101, nil, []handler.PayloadSection{
		signalMaskPayloadSection(1 << 11),
	})

	if _, ok := ev.eventFDView.Path(7); ok {
		t.Fatal("failed signalfd return received an event-time path")
	}
}

func TestFDPathOverlayDecodesCWDAsPathOnly(t *testing.T) {
	data := append([]byte("/abc"), []byte{3, 0, 0, 0}...)
	data = append(data, []byte(strings.Repeat("x", 40))...)
	data = append(data, []byte("/tail")...)
	overlay := fdPathOverlayFromSections([]handler.PayloadSection{{
		Kind:      handler.PayloadKindFDPath,
		Direction: handler.PayloadDirectionIn,
		ArgIndex:  handler.PayloadFDPathCwdArgIndex,
		ProbeRet:  0,
		Data:      data,
	}})
	if overlay.cwdPath != string(data) {
		t.Fatalf("cwd path = %q, want path-only payload %q", overlay.cwdPath, string(data))
	}
}

func TestBPFFDPathCaptureUsesProbeSiteOnly(t *testing.T) {
	root := repoRootForTest(t)
	source := readTextFile(t, filepath.Join(root, "bpf/syscall_fd_path_direct_event_v2.h")) +
		"\n" + readTextFile(t, filepath.Join(root, "bpf/syscall_fd_path_capture_direct_event_v2.h")) +
		"\n" + readTextFile(t, filepath.Join(root, "bpf/syscall_fd_path_walk_direct_event_v2.h"))
	combined := readCombinedBPFSources(t) + "\n" + readDirectEventSources(t)
	for _, token := range []string{
		"read_dentry_path_direct(",
		"FD_PATH_DIRECT_MAX 512",
		"PAYLOAD_TLV_KIND_FD_PATH",
		"FD_PATH_STATE_PREFIX_SIZE 48",
		"bpf_dynptr_data(",
	} {
		if !strings.Contains(source, token) && !strings.Contains(combined, token) {
			t.Fatalf("BPF FD path capture missing %q", token)
		}
	}
	if strings.Contains(combined, "/proc/") || strings.Contains(combined, "process_vm_readv") {
		t.Fatal("BPF FD path capture must not depend on procfs or process_vm_readv")
	}
	if strings.Contains(source, "bpf_d_path(") {
		t.Fatal("raw tracepoint FD path capture cannot use bpf_d_path")
	}
}
