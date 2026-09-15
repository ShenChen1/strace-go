package main

import (
	"bytes"
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/event"
	"strace-go/pkg/handler"
)

func TestSyscallEventContextMergesOpenCreatDirectTLVPath(t *testing.T) {
	tests := []struct {
		name string
		args [6]uint64
	}{
		{name: "open", args: [6]uint64{0x1000, 0}},
		{name: "creat", args: [6]uint64{0x1000, 0644}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			syscallIDByName(t, tt.name)
			fdState := newFDStateStoreFromMaps(nil, nil)
			session := newBareTestTraceSessionWithOptions(cli.ParseArgs([]string{"-e", "trace=" + tt.name, "/bin/true"}), traceSessionDeps{
				TargetPID: 101,
				Decoder:   event.NewDecoder(),
				FDState:   fdState,
				State:     newTraceState(),
			})
			pathData := []byte("/tmp/" + tt.name + "\x00")
			enterPayload := payloadTLVBytes(t, payloadTLVTestSection{
				kind:    payloadTLVKindString,
				arg:     0,
				userPtr: tt.args[0],
				userLen: uint32(len(pathData)),
				data:    pathData,
			})
			enterEnvelope := testTLVSyscallEnvelope(t, tt.name, bpfEventTypeEnter, tt.args, 0, enterPayload)
			session.traceState().handleEnvelope(enterEnvelope)

			exitEnvelope := testTLVSyscallEnvelope(t, tt.name, bpfEventTypeExit, tt.args, 7, nil)
			exitUpdate := session.traceState().handleEnvelope(exitEnvelope)
			ev := newSyscallEventContextFromView(
				session,
				exitUpdate.syscallView,
				101,
				exitUpdate.pendingEnter,
				exitUpdate.payloadSections)

			section, ok := ev.handlerContext.Section(0, handler.PayloadKindString)
			if !ok || !bytes.Equal(section.Data, pathData) {
				t.Fatalf("%s path section = %+v, %v; want arg0 direct TLV", tt.name, section, ok)
			}
			ev.updateFDState(session.fdStateStore())
			if got, ok := fdState.Path(101, 7); !ok || got != "/tmp/"+tt.name {
				t.Fatalf("%s fd path = %q, want direct TLV path", tt.name, got)
			}
		})
	}
}

func TestSyscallEventContextPrefersOpenCreatExitRetryTLVPath(t *testing.T) {
	tests := []struct {
		name    string
		args    [6]uint64
		pathArg uint16
	}{
		{name: "open", args: [6]uint64{0x1000}, pathArg: 0},
		{name: "creat", args: [6]uint64{0x1000, 0644}, pathArg: 0},
		{name: "openat", args: [6]uint64{^uint64(99), 0x1000}, pathArg: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			syscallIDByName(t, tt.name)
			session := newBareTestTraceSessionWithOptions(cli.ParseArgs([]string{
				"-e",
				"trace=" + tt.name,
				"/bin/true",
			}), traceSessionDeps{
				TargetPID: 101,
				Decoder:   event.NewDecoder(),
				FDState:   newFDStateStoreFromMaps(nil, nil),
				State:     newTraceState(),
			})
			enterPayload := payloadTLVBytes(t, payloadTLVTestSection{
				kind:     payloadTLVKindString,
				arg:      tt.pathArg,
				userPtr:  tt.args[tt.pathArg],
				probeRet: -14,
			})
			session.traceState().handleEnvelope(testTLVSyscallEnvelope(
				t,
				tt.name,
				bpfEventTypeEnter,
				tt.args,
				0,
				enterPayload))

			exitData := []byte("exit-retry-" + tt.name + "\x00")
			exitPayload := payloadTLVBytes(t, payloadTLVTestSection{
				kind:    payloadTLVKindString,
				arg:     tt.pathArg,
				userPtr: tt.args[tt.pathArg],
				userLen: uint32(len(exitData)),
				data:    exitData,
			})
			exitUpdate := session.traceState().handleEnvelope(testTLVSyscallEnvelope(
				t,
				tt.name,
				bpfEventTypeExit,
				tt.args,
				-2,
				exitPayload))
			ev := newSyscallEventContextFromView(
				session,
				exitUpdate.syscallView,
				101,
				exitUpdate.pendingEnter,
				exitUpdate.payloadSections)

			section, ok := ev.handlerContext.Section(int(tt.pathArg), handler.PayloadKindString)
			if !ok || section.ProbeRet != 0 || !bytes.Equal(section.Data, exitData) {
				t.Fatalf("%s retry path section = %+v, %v; want successful exit retry string TLV", tt.name, section, ok)
			}
		})
	}
}
