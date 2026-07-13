package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"syscall"
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

func updateFDMapForTest(eventRaw *bpfEvent, scMeta meta.Syscall, pathText string, targetPid int, fdMap map[string]string) {
	store := newFDStateStoreFromMaps(fdMap, nil, nil)
	ev := syscallEventContext{
		raw:             eventRaw,
		view:            newSyscallEventViewFromBPF(eventRaw),
		statePID:        targetPid,
		meta:            scMeta,
		pathText:        pathText,
		payloadSections: payloadSectionsForEvent(eventRaw, scMeta),
	}
	ev.updateFDState(store)
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
	eventRaw := &bpfEvent{
		Pid:  101,
		Tid:  101,
		Args: [6]uint64{3, 4},
		Ret:  4,
	}
	ctx := &handler.Context{
		Pid:       101,
		TargetPid: 101,
		Args:      eventRaw.Args,
		Ret:       eventRaw.Ret,
		ScMeta:    sc,
		Opts: &cli.Options{
			ShowPaths:     true,
			ShowPathsMode: 1,
		},
		FdMap: fdMap,
	}

	res := handler.Get("dup2").Handle(ctx)
	if got, want := res.ArgParts, []string{"3</dev/null>", "4</dev/full>"}; len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("dup2 args = %#v, want %#v", got, want)
	}

	updateFDMapForTest(eventRaw, sc, "", 101, fdMap)
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
			eventRaw := &bpfEvent{
				Pid:          uint32(os.Getpid()),
				Tid:          uint32(os.Getpid()),
				EventType:    bpfEventTypeExit,
				Ret:          0,
				ProbeRetExit: 0,
				DataLen:      uint32(handler.BpfExitArgOffset + 8),
			}
			binary.LittleEndian.PutUint32(eventRaw.StrArg[handler.BpfExitArgOffset:], uint32(readEnd.Fd()))
			binary.LittleEndian.PutUint32(eventRaw.StrArg[handler.BpfExitArgOffset+4:], uint32(writeEnd.Fd()))

			fdMap := make(map[string]string)
			updateFDMapForTest(eventRaw, meta.Syscall{Name: name}, "", 101, fdMap)

			readKey := fmt.Sprintf("101:%d", int32(readEnd.Fd()))
			writeKey := fmt.Sprintf("101:%d", int32(writeEnd.Fd()))
			if fdMap[readKey] == "" {
				t.Fatalf("fdMap[%q] missing after %s payload update", readKey, name)
			}
			if fdMap[writeKey] == "" {
				t.Fatalf("fdMap[%q] missing after %s payload update", writeKey, name)
			}
		})
	}
}

func TestUpdateFDMapIgnoresLegacyPipeExitSnapshot(t *testing.T) {
	eventRaw := &bpfEvent{
		Pid:          uint32(os.Getpid()),
		Tid:          uint32(os.Getpid()),
		Ret:          0,
		ProbeRetExit: 0,
		DataLen:      uint32(handler.BpfExitArgOffset + 8),
	}
	binary.LittleEndian.PutUint32(eventRaw.StrArg[handler.BpfExitArgOffset:], 21)
	binary.LittleEndian.PutUint32(eventRaw.StrArg[handler.BpfExitArgOffset+4:], 22)

	fdMap := make(map[string]string)
	updateFDMapForTest(eventRaw, meta.Syscall{Name: "pipe"}, "", 101, fdMap)
	if len(fdMap) != 0 {
		t.Fatalf("fdMap entries = %d, want 0 without fd array payload section", len(fdMap))
	}
}

func TestUpdateFDMapUsesSocketpairPayloadSection(t *testing.T) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("socketpair() failed: %v", err)
	}
	defer syscall.Close(fds[0])
	defer syscall.Close(fds[1])

	eventRaw := &bpfEvent{
		Pid:          uint32(os.Getpid()),
		Tid:          uint32(os.Getpid()),
		Args:         [6]uint64{syscall.AF_UNIX, syscall.SOCK_STREAM, 0, 0x2000},
		EventType:    bpfEventTypeExit,
		Ret:          0,
		ProbeRetExit: 0,
		DataLen:      uint32(handler.BpfExitArgOffset + 8),
	}
	binary.LittleEndian.PutUint32(eventRaw.StrArg[handler.BpfExitArgOffset:], uint32(fds[0]))
	binary.LittleEndian.PutUint32(eventRaw.StrArg[handler.BpfExitArgOffset+4:], uint32(fds[1]))

	fdMap := make(map[string]string)
	updateFDMapForTest(eventRaw, meta.Syscall{Name: "socketpair"}, "", 101, fdMap)

	for _, fd := range fds {
		key := fmt.Sprintf("101:%d", int32(fd))
		if got := fdMap[key]; got == "" {
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
	rawView := newSyscallEventViewFromBPF(&bpfEvent{Args: [6]uint64{syscall.AF_NETLINK, syscall.SOCK_DGRAM, 4}})
	view := syscallEventView{
		valid:     true,
		tid:       uint32(os.Getpid()),
		args:      [6]uint64{syscall.AF_UNIX, syscall.SOCK_STREAM, 0, 0x2000},
		ret:       0,
		eventType: bpfEventTypeExit,
	}
	ev := syscallEventContext{
		raw:      &bpfEvent{Tid: uint32(os.Getpid()), Args: rawView.args, Ret: 0},
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
	store := newFDStateStoreFromMaps(fdMap, nil, nil)
	ev.updateFDState(store)

	wantSuffix := "|" + socketFDInfoFromView(view)
	rawSuffix := "|" + socketFDInfoFromView(rawView)
	if wantSuffix == rawSuffix {
		t.Fatal("test setup produced identical view and raw socket info")
	}
	for _, fd := range fds {
		got := fdMap[fmt.Sprintf("101:%d", int32(fd))]
		if !strings.HasSuffix(got, wantSuffix) {
			t.Fatalf("socketpair fd target = %q, want suffix %q", got, wantSuffix)
		}
		if strings.HasSuffix(got, rawSuffix) {
			t.Fatalf("socketpair fd target = %q, unexpectedly used raw suffix %q", got, rawSuffix)
		}
	}
}

func TestUpdateFDMapIgnoresLegacySocketpairExitSnapshot(t *testing.T) {
	eventRaw := &bpfEvent{
		Pid:          uint32(os.Getpid()),
		Tid:          uint32(os.Getpid()),
		Args:         [6]uint64{syscall.AF_UNIX, syscall.SOCK_STREAM, 0, 0x2000},
		Ret:          0,
		ProbeRetExit: 0,
		DataLen:      uint32(handler.BpfExitArgOffset + 8),
	}
	binary.LittleEndian.PutUint32(eventRaw.StrArg[handler.BpfExitArgOffset:], 21)
	binary.LittleEndian.PutUint32(eventRaw.StrArg[handler.BpfExitArgOffset+4:], 22)

	fdMap := make(map[string]string)
	updateFDMapForTest(eventRaw, meta.Syscall{Name: "socketpair"}, "", 101, fdMap)
	if len(fdMap) != 0 {
		t.Fatalf("fdMap entries = %d, want 0 without fd array payload section", len(fdMap))
	}
}

func TestUpdateFDMapSkipsSocketpairWithoutPayloadSection(t *testing.T) {
	fdMap := make(map[string]string)
	updateFDMapForTest(&bpfEvent{
		Pid:  1234,
		Tid:  1234,
		Args: [6]uint64{syscall.AF_UNIX, syscall.SOCK_STREAM, 0, 0x2000},
		Ret:  0,
	}, meta.Syscall{Name: "socketpair"}, "", 101, fdMap)

	if len(fdMap) != 0 {
		t.Fatalf("fdMap entries = %d, want 0 without socketpair exit snapshot", len(fdMap))
	}
}

func TestUpdateFDMapUsesOpenatPayloadPathText(t *testing.T) {
	fdMap := make(map[string]string)
	eventRaw := &bpfEvent{
		Pid: 1234,
		Tid: 1234,
		Ret: 7,
	}

	updateFDMapForTest(eventRaw, meta.Syscall{Name: "openat"}, `"/tmp/section"`, 101, fdMap)
	if got := fdMap["101:7"]; got != "/tmp/section" {
		t.Fatalf("fdMap[101:7] = %q, want payload raw path", got)
	}
}

func TestUpdateFDMapIgnoresLegacyOpenatStringSnapshot(t *testing.T) {
	fdMap := make(map[string]string)
	eventRaw := &bpfEvent{
		Pid:           1234,
		Tid:           1234,
		Args:          [6]uint64{rawAtFdcwd, 0x1000},
		Ret:           7,
		ProbeRetEnter: 0,
		DataLen:       uint32(len("/tmp/legacy") + 1),
	}
	copy(eventRaw.StrArg[:], []byte("/tmp/legacy\x00"))

	updateFDMapForTest(eventRaw, meta.Syscall{Name: "openat"}, "0x1000", 101, fdMap)
	if len(fdMap) != 0 {
		t.Fatalf("fdMap entries = %d, want 0 without path payload section", len(fdMap))
	}
}

func TestUpdateFDMapUsesNetlinkSockaddrPayloadSection(t *testing.T) {
	tests := []struct {
		name      string
		eventType uint16
		args      [6]uint64
		offset    int
		enterRet  int32
		exitRet   int32
		dataLen   uint32
	}{
		{
			name:      "bind",
			eventType: bpfEventTypeExit,
			args:      [6]uint64{7, 0x3000, 8},
			offset:    0,
			enterRet:  0,
			exitRet:   -1,
			dataLen:   8,
		},
		{
			name:      "getsockname",
			eventType: bpfEventTypeExit,
			args:      [6]uint64{7, 0x3000, 0x4000},
			offset:    handler.BpfExitArgOffset,
			enterRet:  -1,
			exitRet:   0,
			dataLen:   uint32(handler.BpfExitArgOffset + 8),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			eventRaw := &bpfEvent{
				Pid:           1234,
				Tid:           1234,
				Args:          test.args,
				EventType:     test.eventType,
				Ret:           0,
				ProbeRetEnter: test.enterRet,
				ProbeRetExit:  test.exitRet,
				DataLen:       test.dataLen,
			}
			binary.LittleEndian.PutUint16(eventRaw.StrArg[test.offset:], 16)
			binary.LittleEndian.PutUint32(eventRaw.StrArg[test.offset+4:], 42)

			fdMap := make(map[string]string)
			updateFDMapForTest(eventRaw, meta.Syscall{Name: test.name}, "", 101, fdMap)

			if got := fdMap["101:7"]; got != "NETLINK:[SOCK_DIAG:42]" {
				t.Fatalf("fdMap[101:7] = %q, want NETLINK socket", got)
			}
		})
	}
}

func TestSyscallEventContextUpdateFDStateUsesViewForNetlinkFD(t *testing.T) {
	data := make([]byte, 8)
	binary.LittleEndian.PutUint16(data, 16)
	binary.LittleEndian.PutUint32(data[4:], 42)
	ev := syscallEventContext{
		raw: &bpfEvent{Args: [6]uint64{7, 0x3000, 8}, Ret: 0},
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
	store := newFDStateStoreFromMaps(fdMap, nil, nil)
	ev.updateFDState(store)

	if got := fdMap["101:5"]; got != "NETLINK:[SOCK_DIAG:42]" {
		t.Fatalf("fdMap[101:5] = %q, want NETLINK socket from view fd", got)
	}
	if got := fdMap["101:7"]; got != "" {
		t.Fatalf("raw fd entry = %q, want empty", got)
	}
}

func TestUpdateFDMapIgnoresLegacyNetlinkSockaddrSnapshot(t *testing.T) {
	tests := []struct {
		name     string
		args     [6]uint64
		offset   int
		enterRet int32
		exitRet  int32
		dataLen  uint32
	}{
		{name: "bind", args: [6]uint64{7, 0x3000, 8}, offset: 0, enterRet: 0, exitRet: -1, dataLen: 8},
		{name: "getsockname", args: [6]uint64{7, 0x3000, 0x4000}, offset: handler.BpfExitArgOffset, enterRet: -1, exitRet: 0, dataLen: uint32(handler.BpfExitArgOffset + 8)},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			eventRaw := &bpfEvent{
				Pid:           1234,
				Tid:           1234,
				Args:          test.args,
				Ret:           0,
				ProbeRetEnter: test.enterRet,
				ProbeRetExit:  test.exitRet,
				DataLen:       test.dataLen,
			}
			binary.LittleEndian.PutUint16(eventRaw.StrArg[test.offset:], 16)
			binary.LittleEndian.PutUint32(eventRaw.StrArg[test.offset+4:], 42)

			fdMap := make(map[string]string)
			updateFDMapForTest(eventRaw, meta.Syscall{Name: test.name}, "", 101, fdMap)

			if len(fdMap) != 0 {
				t.Fatalf("fdMap entries = %d, want 0 without netlink sockaddr payload section", len(fdMap))
			}
		})
	}
}
