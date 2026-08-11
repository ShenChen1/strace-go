package main

import (
	"bytes"
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/event"
	"strace-go/pkg/handler"
)

func TestSyscallEventContextUsesTLVPathSection(t *testing.T) {
	session := &traceSession{
		targetPid: 101,
		opts:      cli.ParseArgs([]string{"-e", "trace=openat", "/bin/true"}),
		decoder:   event.NewDecoder(),
		fdState:   newFDStateStoreFromMaps(nil, nil),
	}
	path := []byte("from-tlv\x00")
	payload := payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindString,
		arg:     1,
		userPtr: 0x1000,
		userLen: uint32(len(path)),
		data:    path,
	})
	update := session.traceState().handleEnvelope(testTLVSyscallEnvelope(
		t,
		"openat",
		bpfEventTypeExit,
		[6]uint64{rawAtFdcwd, 0x1000, 0},
		3,
		payload,
	))

	ev := newSyscallEventContextFromView(session, update.syscallView, 101, update.pendingEnter, update.payloadSections)

	section, ok := ev.handlerContext.Section(1, handler.PayloadKindString)
	if !ok || !bytes.Equal(section.Data, []byte("from-tlv\x00")) {
		t.Fatalf("handler section = %+v, %v; want TLV path section", section, ok)
	}
	ev.updateFDState(session.fdStateStore())
	if got := session.fdStateStore().paths["101:3"]; got != "from-tlv" {
		t.Fatalf("fd path = %q, want TLV snapshot path", got)
	}
}

func TestShouldEmitGenericEnterForPathFilter(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want bool
	}{
		{name: "text without path filter", args: []string{"-e", "trace=openat", "/bin/true"}, want: true},
		{name: "text with path filter", args: []string{"-e", "trace=openat", "-P", "from-tlv", "/bin/true"}, want: true},
		{name: "summary only without path filter", args: []string{"-c", "-e", "trace=openat", "/bin/true"}, want: false},
		{name: "json", args: []string{"--event-format=json", "-e", "trace=openat", "/bin/true"}, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldEmitGenericEnter(cli.ParseArgs(tt.args)); got != tt.want {
				t.Fatalf("shouldEmitGenericEnter() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSyscallEventContextMergesPendingEnterTLVPathForPathFilter(t *testing.T) {
	session := &traceSession{
		targetPid: 101,
		opts:      cli.ParseArgs([]string{"-e", "trace=openat", "-P", "from-tlv", "/bin/true"}),
		decoder:   event.NewDecoder(),
		fdState:   newFDStateStoreFromMaps(nil, nil),
		state:     newTraceState(),
	}
	args := [6]uint64{rawAtFdcwd, 0x1000, 0}
	pathPayload := payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindString,
		arg:     1,
		userPtr: 0x1000,
		userLen: uint32(len([]byte("from-tlv\x00"))),
		data:    []byte("from-tlv\x00"),
	})
	session.traceState().handleEnvelope(testTLVSyscallEnvelope(t, "openat", bpfEventTypeEnter, args, 0, pathPayload))
	exitUpdate := session.traceState().handleEnvelope(testTLVSyscallEnvelope(t, "openat", bpfEventTypeExit, args, -9, nil))
	ev := newSyscallEventContextFromView(
		session,
		exitUpdate.syscallView,
		101,
		exitUpdate.pendingEnter,
		exitUpdate.payloadSections,
	)

	if !ev.shouldOutput() {
		t.Fatal("openat exit should match -P from-tlv using pending enter TLV path")
	}
	section, ok := ev.handlerContext.Section(1, handler.PayloadKindString)
	if !ok || !bytes.Equal(section.Data, []byte("from-tlv\x00")) {
		t.Fatalf("merged handler section = %+v, %v; want pending enter TLV path", section, ok)
	}
}

func TestSyscallEventContextMergesPathStatEnterPathAndExitStructSections(t *testing.T) {
	tests := []struct {
		name       string
		args       [6]uint64
		pathArg    uint16
		structArg  uint16
		structSize int
		fill       byte
	}{
		{name: "stat", args: [6]uint64{0x1000, 0x2000}, pathArg: 0, structArg: 1, structSize: statPayloadStructSize, fill: 0x11},
		{name: "lstat", args: [6]uint64{0x1000, 0x2000}, pathArg: 0, structArg: 1, structSize: statPayloadStructSize, fill: 0x22},
		{name: "newfstatat", args: [6]uint64{rawAtFdcwd, 0x1000, 0x2000}, pathArg: 1, structArg: 2, structSize: statPayloadStructSize, fill: 0x33},
		{name: "statfs", args: [6]uint64{0x1000, 0x2000}, pathArg: 0, structArg: 1, structSize: statfsPayloadStructSize, fill: 0x44},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertPathStatSectionsMerged(t, tt.name, tt.args, tt.pathArg, tt.structArg, tt.structSize, tt.fill)
		})
	}
}

func assertPathStatSectionsMerged(
	t *testing.T,
	syscallName string,
	args [6]uint64,
	pathArg uint16,
	structArg uint16,
	structSize int,
	fill byte,
) {
	t.Helper()
	session := &traceSession{
		targetPid: 101,
		opts:      cli.ParseArgs([]string{"--event-format=json", "-e", "trace=" + syscallName, "/bin/true"}),
		decoder:   event.NewDecoder(),
		fdState:   newFDStateStoreFromMaps(nil, nil),
		state:     newTraceState(),
	}
	pathData := []byte("/proc/self\x00")
	pathPayload := payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindString,
		arg:     pathArg,
		userPtr: args[pathArg],
		userLen: uint32(len(pathData)),
		data:    pathData,
	})
	session.traceState().handleEnvelope(testTLVSyscallEnvelope(t, syscallName, bpfEventTypeEnter, args, 0, pathPayload))

	structData := bytes.Repeat([]byte{fill}, structSize)
	exitPayload := payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindStruct,
		flags:   payloadTLVFlagDirectionOut,
		arg:     structArg,
		userPtr: args[structArg],
		userLen: uint32(structSize),
		data:    structData,
	})

	exitUpdate := session.traceState().handleEnvelope(testTLVSyscallEnvelope(t, syscallName, bpfEventTypeExit, args, 0, exitPayload))
	ev := newSyscallEventContextFromView(session, exitUpdate.syscallView, 101, exitUpdate.pendingEnter, exitUpdate.payloadSections)
	pathSection, ok := ev.handlerContext.Section(int(pathArg), handler.PayloadKindString)
	if !ok || !bytes.Equal(pathSection.Data, pathData) {
		t.Fatalf("%s path section = %+v, %v; want pending enter path", syscallName, pathSection, ok)
	}
	structSection, ok := ev.handlerContext.Section(int(structArg), handler.PayloadKindStruct)
	if !ok || !bytes.Equal(structSection.Data, structData) {
		t.Fatalf("%s struct section = %+v, %v; want exit struct", syscallName, structSection, ok)
	}
}

func TestSyscallEventContextMergesReadlinkEnterPathAndExitBytesSections(t *testing.T) {
	tests := []readlinkTLVCase{
		{
			name:    "readlink",
			args:    [6]uint64{0x1000, 0x2000, 64},
			pathArg: 0,
			bufArg:  1,
		},
		{
			name:    "readlinkat",
			args:    [6]uint64{rawAtFdcwd, 0x1000, 0x2000, 64},
			pathArg: 1,
			bufArg:  2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertReadlinkSectionsMerged(t, tt)
		})
	}
}

func TestSyscallEventContextUsesGetcwdExitBytesSection(t *testing.T) {
	session := &traceSession{
		targetPid: 101,
		opts:      cli.ParseArgs([]string{"--event-format=json", "-e", "trace=getcwd", "/bin/true"}),
		decoder:   event.NewDecoder(),
		fdState:   newFDStateStoreFromMaps(nil, nil),
		state:     newTraceState(),
	}
	cwdData := []byte("/opt/strace-go\x00")
	exitPayload := payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindBytes,
		flags:   payloadTLVFlagDirectionOut,
		arg:     0,
		userPtr: 0x1000,
		userLen: uint32(len(cwdData)),
		data:    cwdData,
	})

	exitUpdate := session.traceState().handleEnvelope(testTLVSyscallEnvelope(
		t,
		"getcwd",
		bpfEventTypeExit,
		[6]uint64{0x1000, 128},
		int64(len(cwdData)),
		exitPayload,
	))
	ev := newSyscallEventContextFromView(session, exitUpdate.syscallView, 101, exitUpdate.pendingEnter, exitUpdate.payloadSections)
	section, ok := ev.handlerContext.Section(0, handler.PayloadKindBytes)
	if !ok || !bytes.Equal(section.Data, cwdData) {
		t.Fatalf("getcwd bytes section = %+v, %v; want exit cwd bytes", section, ok)
	}
}

func TestSyscallEventContextUsesFDArrayExitStructSection(t *testing.T) {
	tests := []struct {
		name     string
		args     [6]uint64
		argIndex uint16
	}{
		{name: "pipe", args: [6]uint64{0x1000}, argIndex: 0},
		{name: "pipe2", args: [6]uint64{0x2000, 0}, argIndex: 0},
		{name: "socketpair", args: [6]uint64{1, 1, 0, 0x3000}, argIndex: 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := &traceSession{
				targetPid: 101,
				opts:      cli.ParseArgs([]string{"--event-format=json", "-e", "trace=" + tt.name, "/bin/true"}),
				decoder:   event.NewDecoder(),
				fdState:   newFDStateStoreFromMaps(nil, nil),
				state:     newTraceState(),
			}
			fdData := fdArrayJSONData(21, 22)
			exitPayload := payloadTLVBytes(t, payloadTLVTestSection{
				kind:    payloadTLVKindStruct,
				flags:   payloadTLVFlagDirectionOut,
				arg:     tt.argIndex,
				userPtr: tt.args[tt.argIndex],
				userLen: fdArrayPayloadSize,
				data:    fdData,
			})

			exitUpdate := session.traceState().handleEnvelope(testTLVSyscallEnvelope(t, tt.name, bpfEventTypeExit, tt.args, 0, exitPayload))
			ev := newSyscallEventContextFromView(session, exitUpdate.syscallView, 101, exitUpdate.pendingEnter, exitUpdate.payloadSections)
			section, ok := ev.handlerContext.Section(int(tt.argIndex), handler.PayloadKindStruct)
			if !ok || !bytes.Equal(section.Data, fdData) {
				t.Fatalf("%s fd-array section = %+v, %v; want exit struct", tt.name, section, ok)
			}
		})
	}
}

type readlinkTLVCase struct {
	name    string
	args    [6]uint64
	pathArg uint16
	bufArg  uint16
}

func assertReadlinkSectionsMerged(t *testing.T, tt readlinkTLVCase) {
	t.Helper()
	session := &traceSession{
		targetPid: 101,
		opts:      cli.ParseArgs([]string{"--event-format=json", "-e", "trace=" + tt.name, "/bin/true"}),
		decoder:   event.NewDecoder(),
		fdState:   newFDStateStoreFromMaps(nil, nil),
		state:     newTraceState(),
	}
	pathData := []byte("/tmp/strace-go-ebpf-readlink\x00")
	pathPayload := payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindString,
		arg:     tt.pathArg,
		userPtr: tt.args[tt.pathArg],
		userLen: uint32(len(pathData)),
		data:    pathData,
	})
	session.traceState().handleEnvelope(testTLVSyscallEnvelope(t, tt.name, bpfEventTypeEnter, tt.args, 0, pathPayload))

	targetData := []byte("/proc/self")
	exitPayload := payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindBytes,
		flags:   payloadTLVFlagDirectionOut,
		arg:     tt.bufArg,
		userPtr: tt.args[tt.bufArg],
		userLen: uint32(len(targetData)),
		data:    targetData,
	})

	exitUpdate := session.traceState().handleEnvelope(testTLVSyscallEnvelope(t, tt.name, bpfEventTypeExit, tt.args, int64(len(targetData)), exitPayload))
	ev := newSyscallEventContextFromView(session, exitUpdate.syscallView, 101, exitUpdate.pendingEnter, exitUpdate.payloadSections)
	pathSection, ok := ev.handlerContext.Section(int(tt.pathArg), handler.PayloadKindString)
	if !ok || !bytes.Equal(pathSection.Data, pathData) {
		t.Fatalf("%s path section = %+v, %v; want pending enter path", tt.name, pathSection, ok)
	}
	bytesSection, ok := ev.handlerContext.Section(int(tt.bufArg), handler.PayloadKindBytes)
	if !ok || !bytes.Equal(bytesSection.Data, targetData) {
		t.Fatalf("%s bytes section = %+v, %v; want exit bytes", tt.name, bytesSection, ok)
	}
}
