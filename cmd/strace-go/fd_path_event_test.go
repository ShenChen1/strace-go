package main

import (
	"encoding/binary"
	"path/filepath"
	"strings"
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/event"
	"strace-go/pkg/handler"
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
