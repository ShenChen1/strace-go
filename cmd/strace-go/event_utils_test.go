package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

func updateFDMapForTest(
	view syscallEventView,
	scMeta meta.Syscall,
	payloadSections []handler.PayloadSection,
	pathText string,
	targetPid int,
	fdMap map[string]string,
) *FDStateStore {
	store := newFDStateStoreFromMaps(fdMap, nil)
	ev := syscallEventContext{
		view:            view,
		statePID:        targetPid,
		meta:            scMeta,
		fdFlags:         meta.NewCatalog("abbrev"),
		pathText:        pathText,
		payloadSections: payloadSections,
	}
	ev.updateFDState(store)
	return store
}

func TestDup2FormatsArgsBeforeFDMapUpdateAndReturnAfter(t *testing.T) {
	fdMap := map[string]string{
		"101:3": "/dev/null",
		"101:4": "/dev/full",
	}
	sc := meta.Syscall{
		Name:     "dup2",
		Args:     []string{"oldfd", "newfd"},
		ArgTypes: []string{"unsigned int", "unsigned int"},
	}
	args := [6]uint64{3, 4}
	ret := int64(4)
	ctx := &handler.Context{
		Pid:       101,
		TargetPid: 101,
		Args:      args,
		Ret:       ret,
		ScMeta:    sc,
		Opts: &cli.Options{
			ShowPaths:     true,
			ShowPathsMode: 1,
		},
		FDStateView: newFDStateStore(fdMap),
	}

	res := handler.NewRegistry().Resolve("dup2").Handle(ctx)
	if got, want := res.ArgParts, []string{"3</dev/null>", "4</dev/full>"}; len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("dup2 args = %#v, want %#v", got, want)
	}

	updatedStore := updateFDMapForTest(syscallEventView{valid: true, pid: 101, tid: 101, args: args, ret: ret}, sc, nil, "", 101, fdMap)
	ctx.FDStateView = updatedStore
	if got := formatSyscallRet("dup2", 4, res, ctx); got != "4</dev/null>" {
		t.Fatalf("dup2 return = %q, want %q", got, "4</dev/null>")
	}
}

func TestUpdateFDMapUsesPipePayloadSection(t *testing.T) {
	readEnd, writeEnd, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe() failed: %v", err)
	}
	defer readEnd.Close()
	defer writeEnd.Close()

	for _, name := range []string{"pipe", "pipe2"} {
		t.Run(name, func(t *testing.T) {
			fdData := fdArrayJSONData(uint32(readEnd.Fd()), uint32(writeEnd.Fd()))
			sections := fdArrayPayloadSectionsForTest(0, fdData)
			view := syscallEventView{valid: true, tid: uint32(os.Getpid()), eventType: bpfEventTypeExit, ret: 0}

			fdMap := make(map[string]string)
			store := updateFDMapForTest(view, meta.Syscall{Name: name}, sections, "", 101, fdMap)

			readKey := fmt.Sprintf("101:%d", int32(readEnd.Fd()))
			writeKey := fmt.Sprintf("101:%d", int32(writeEnd.Fd()))
			if got, ok := store.Path(101, int32(readEnd.Fd())); !ok || got == "" {
				t.Fatalf("fdMap[%q] missing after %s payload update", readKey, name)
			}
			if got, ok := store.Path(101, int32(writeEnd.Fd())); !ok || got == "" {
				t.Fatalf("fdMap[%q] missing after %s payload update", writeKey, name)
			}
		})
	}
}

func TestUpdateFDMapUsesSocketpairPayloadSection(t *testing.T) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("socketpair() failed: %v", err)
	}
	defer syscall.Close(fds[0])
	defer syscall.Close(fds[1])

	fdData := fdArrayJSONData(uint32(fds[0]), uint32(fds[1]))
	sections := fdArrayPayloadSectionsForTest(3, fdData)
	view := syscallEventView{
		valid:     true,
		tid:       uint32(os.Getpid()),
		args:      [6]uint64{syscall.AF_UNIX, syscall.SOCK_STREAM, 0, 0x2000},
		eventType: bpfEventTypeExit,
		ret:       0,
	}

	fdMap := make(map[string]string)
	store := updateFDMapForTest(view, meta.Syscall{Name: "socketpair"}, sections, "", 101, fdMap)

	for _, fd := range fds {
		key := fmt.Sprintf("101:%d", int32(fd))
		if got, ok := store.Path(101, int32(fd)); !ok || got == "" {
			t.Fatalf("fdMap[%q] missing after socketpair payload update", key)
		}
	}
}

func TestSyscallEventContextUpdateFDStateUsesViewForSocketpairInfo(t *testing.T) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("socketpair() failed: %v", err)
	}
	defer syscall.Close(fds[0])
	defer syscall.Close(fds[1])

	fdData := make([]byte, fdArrayPayloadSize)
	binary.LittleEndian.PutUint32(fdData, uint32(fds[0]))
	binary.LittleEndian.PutUint32(fdData[4:], uint32(fds[1]))
	rawView := syscallEventView{valid: true, args: [6]uint64{syscall.AF_NETLINK, syscall.SOCK_DGRAM, 4}}
	view := syscallEventView{
		valid:     true,
		tid:       uint32(os.Getpid()),
		args:      [6]uint64{syscall.AF_UNIX, syscall.SOCK_STREAM, 0, 0x2000},
		ret:       0,
		eventType: bpfEventTypeExit,
	}
	ev := syscallEventContext{
		view:     view,
		statePID: 101,
		meta:     meta.Syscall{Name: "socketpair"},
		payloadSections: []handler.PayloadSection{{
			Kind:      handler.PayloadKindStruct,
			Direction: handler.PayloadDirectionOut,
			ArgIndex:  3,
			ProbeRet:  0,
			Data:      fdData,
		}},
	}

	fdMap := make(map[string]string)
	store := newFDStateStoreFromMaps(fdMap, nil)
	catalog := meta.NewCatalog("abbrev")
	ev.fdFlags = catalog
	ev.updateFDState(store)

	wantSuffix := "|" + socketFDInfoFromFlags(catalog, view)
	rawSuffix := "|" + socketFDInfoFromFlags(catalog, rawView)
	if wantSuffix == rawSuffix {
		t.Fatal("test setup produced identical view and raw socket info")
	}
	for _, fd := range fds {
		got, ok := store.Path(101, int32(fd))
		if !ok || !strings.HasSuffix(got, wantSuffix) {
			t.Fatalf("socketpair fd target = %q, want suffix %q", got, wantSuffix)
		}
		if strings.HasSuffix(got, rawSuffix) {
			t.Fatalf("socketpair fd target = %q, unexpectedly used raw suffix %q", got, rawSuffix)
		}
	}
}

func TestUpdateFDMapSkipsSocketpairWithoutPayloadSection(t *testing.T) {
	fdMap := make(map[string]string)
	view := syscallEventView{
		valid: true,
		pid:   1234,
		tid:   1234,
		args:  [6]uint64{syscall.AF_UNIX, syscall.SOCK_STREAM, 0, 0x2000},
		ret:   0,
	}
	store := updateFDMapForTest(view, meta.Syscall{Name: "socketpair"}, nil, "", 101, fdMap)

	if len(store.paths) != 0 {
		t.Fatalf("store entries = %d, want 0 without socketpair exit snapshot", len(store.paths))
	}
}

func TestUpdateFDMapUsesOpenatPayloadPathText(t *testing.T) {
	fdMap := make(map[string]string)
	view := syscallEventView{valid: true, pid: 1234, tid: 1234, ret: 7}

	store := updateFDMapForTest(view, meta.Syscall{Name: "openat"}, nil, `"/tmp/section"`, 101, fdMap)
	if got, ok := store.Path(101, 7); !ok || got != "/tmp/section" {
		t.Fatalf("fdMap[101:7] = %q, want payload raw path", got)
	}
}

func TestUpdateFDMapUsesNetlinkSockaddrPayloadSection(t *testing.T) {
	tests := []struct {
		name      string
		eventType uint16
		args      [6]uint64
		direction handler.PayloadDirection
		enterRet  int32
		exitRet   int32
	}{
		{
			name:      "bind",
			eventType: bpfEventTypeExit,
			args:      [6]uint64{7, 0x3000, 8},
			direction: handler.PayloadDirectionIn,
			enterRet:  0,
			exitRet:   -1,
		},
		{
			name:      "getsockname",
			eventType: bpfEventTypeExit,
			args:      [6]uint64{7, 0x3000, 0x4000},
			direction: handler.PayloadDirectionOut,
			enterRet:  -1,
			exitRet:   0,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			view := syscallEventView{
				valid:         true,
				pid:           1234,
				tid:           1234,
				args:          test.args,
				eventType:     test.eventType,
				ret:           0,
				probeRetEnter: test.enterRet,
				probeRetExit:  test.exitRet,
			}
			sections := []handler.PayloadSection{netlinkSockaddrPayloadSectionForTest(test.direction, test.args[1], 42)}

			fdMap := make(map[string]string)
			store := updateFDMapForTest(view, meta.Syscall{Name: test.name}, sections, "", 101, fdMap)

			if got, ok := store.Path(101, 7); !ok || got != "socket:[SOCK_DIAG:42]|AF_NETLINK:NETLINK_SOCK_DIAG" {
				t.Fatalf("fdMap[101:7] = %q, want NETLINK socket", got)
			}
		})
	}
}

func TestUpdateFDMapUsesSocketFDStateInode(t *testing.T) {
	view := syscallEventView{
		valid:     true,
		pid:       1234,
		tid:       1234,
		args:      [6]uint64{syscall.AF_NETLINK, syscall.SOCK_RAW, 4},
		eventType: bpfEventTypeExit,
		ret:       7,
	}
	sections := []handler.PayloadSection{fdStatePayloadSection(fdStateSnapshotBytes(
		7, handler.FDStateFlagIdentity, 0140777, 1, 0, 3373601, 0,
	))}

	store := updateFDMapForTest(view, meta.Syscall{Name: "socket"}, sections, "", 101, nil)
	if got, ok := store.Path(101, 7); !ok || got != "socket:[3373601]|AF_NETLINK:NETLINK_SOCK_DIAG" {
		t.Fatalf("socket fd target = %q, %v; want event-time inode and protocol", got, ok)
	}
	if observation, ok := store.Observation(101, 7); !ok || observation.Inode != 3373601 {
		t.Fatalf("socket observation = %+v, %v; want inode 3373601", observation, ok)
	}
}

func fdArrayPayloadSectionsForTest(argIndex int, data []byte) []handler.PayloadSection {
	return []handler.PayloadSection{{
		Kind:      handler.PayloadKindStruct,
		Direction: handler.PayloadDirectionOut,
		ArgIndex:  argIndex,
		UserLen:   uint32(len(data)),
		CopiedLen: uint32(len(data)),
		ProbeRet:  0,
		Data:      data,
	}}
}

func netlinkSockaddrPayloadSectionForTest(
	direction handler.PayloadDirection,
	userPtr uint64,
	netlinkPID uint32,
) handler.PayloadSection {
	data := make([]byte, 8)
	binary.LittleEndian.PutUint16(data[0:2], 16)
	binary.LittleEndian.PutUint32(data[4:8], netlinkPID)
	return handler.PayloadSection{
		Kind:      handler.PayloadKindStruct,
		Direction: direction,
		ArgIndex:  1,
		UserPtr:   userPtr,
		UserLen:   uint32(len(data)),
		CopiedLen: uint32(len(data)),
		ProbeRet:  0,
		Data:      data,
	}
}

func TestSyscallEventContextUpdateFDStateUsesViewForNetlinkFD(t *testing.T) {
	data := make([]byte, 8)
	binary.LittleEndian.PutUint16(data, 16)
	binary.LittleEndian.PutUint32(data[4:], 42)
	ev := syscallEventContext{
		view: syscallEventView{
			valid:     true,
			args:      [6]uint64{5, 0x3000, 8},
			ret:       0,
			eventType: bpfEventTypeExit,
		},
		statePID: 101,
		meta:     meta.Syscall{Name: "bind"},
		payloadSections: []handler.PayloadSection{{
			Kind:      handler.PayloadKindStruct,
			Direction: handler.PayloadDirectionIn,
			ArgIndex:  1,
			ProbeRet:  0,
			Data:      data,
		}},
	}

	fdMap := make(map[string]string)
	store := newFDStateStoreFromMaps(fdMap, nil)
	ev.updateFDState(store)

	if got, ok := store.Path(101, 5); !ok || got != "socket:[SOCK_DIAG:42]|AF_NETLINK:NETLINK_SOCK_DIAG" {
		t.Fatalf("fdMap[101:5] = %q, want NETLINK socket from view fd", got)
	}
	if got, ok := store.Path(101, 7); ok && got != "" {
		t.Fatalf("raw fd entry = %q, want empty", got)
	}
}

func TestExpandTracePathSetKeepsRawAndRealpathVariants(t *testing.T) {
	dir := t.TempDir()
	sample := filepath.Join(dir, "stat.sample")
	if err := os.WriteFile(sample, []byte("x"), 0o644); err != nil {
		t.Fatalf("write sample: %v", err)
	}
	origWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	defer os.Chdir(origWD)

	expanded := expandTracePathSet(map[string]bool{"stat.sample": true})
	if !expanded["stat.sample"] {
		t.Fatal("raw relative -P entry must be kept")
	}
	if !expanded[sample] {
		t.Fatalf("expanded set missing absolute realpath %q: %v", sample, expanded)
	}
}
