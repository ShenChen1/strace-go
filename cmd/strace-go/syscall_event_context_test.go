package main

import (
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/event"
	"strace-go/pkg/handler"
)

func TestSyscallEventContextBuildsPayloadHandlerContext(t *testing.T) {
	opts := cli.ParseArgs([]string{"-e", "trace=openat", "/bin/true"})
	session := &traceSession{
		targetPid: 101,
		opts:      opts,
		decoder:   event.NewDecoder(),
		fdState: newFDStateStoreFromMaps(map[string]string{
			"101:cwd": "/tmp",
		}, nil, nil),
	}
	path := []byte("input.txt\x00")
	eventRaw := &bpfEvent{
		Pid:           101,
		Tid:           101,
		SysId:         syscallIDByName(t, "openat"),
		EventType:     bpfEventTypeExit,
		Args:          [6]uint64{rawAtFdcwd, 0x1000, 0},
		Ptr:           0x1000,
		DataLen:       uint32(len(path)),
		ProbeRetEnter: 0,
		Ret:           3,
	}
	copy(eventRaw.StrArg[:], path)

	ev := newSyscallEventContext(session, eventRaw, 101, nil)

	if ev.meta.Name != "openat" || !ev.isPath || !ev.shouldPrint {
		t.Fatalf("event context metadata = name:%s isPath:%v shouldPrint:%v", ev.meta.Name, ev.isPath, ev.shouldPrint)
	}
	if ev.pathText != `"input.txt"` {
		t.Fatalf("pathText = %q, want quoted path snapshot", ev.pathText)
	}
	section, ok := ev.handlerContext.Section(1, handler.PayloadKindString)
	if !ok {
		t.Fatalf("handler context missing path payload section")
	}
	if section.UserPtr != 0x1000 || string(section.Data) != string(path) {
		t.Fatalf("payload section = ptr:%#x data:%q", section.UserPtr, string(section.Data))
	}
	if ev.handlerContext.TargetPid != 101 {
		t.Fatalf("handler context target mismatch: %+v", ev.handlerContext)
	}
}

func TestSyscallEventContextIgnoresLegacyPathStringBuffer(t *testing.T) {
	opts := cli.ParseArgs([]string{"-e", "trace=openat", "/bin/true"})
	session := &traceSession{
		targetPid: 101,
		opts:      opts,
		decoder:   event.NewDecoder(),
		fdState:   newFDStateStoreFromMaps(nil, nil, nil),
	}
	path := []byte("legacy.txt\x00")
	eventRaw := &bpfEvent{
		Pid:           101,
		Tid:           101,
		SysId:         syscallIDByName(t, "openat"),
		Args:          [6]uint64{rawAtFdcwd, 0x1000, 0},
		Ptr:           0x1000,
		DataLen:       uint32(len(path)),
		ProbeRetEnter: 0,
		Ret:           3,
	}
	copy(eventRaw.StrArg[:], path)

	ev := newSyscallEventContext(session, eventRaw, 101, nil)
	if ev.pathText != "0x1000" {
		t.Fatalf("pathText = %q, want pointer fallback", ev.pathText)
	}
	if _, ok := ev.handlerContext.Section(1, handler.PayloadKindString); ok {
		t.Fatalf("handler context unexpectedly exposed legacy path string section")
	}
}
