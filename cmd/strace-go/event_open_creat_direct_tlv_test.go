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
			session := &traceSession{
				targetPid: 101,
				opts:      cli.ParseArgs([]string{"-e", "trace=" + tt.name, "/bin/true"}),
				decoder:   event.NewDecoder(),
				fdState:   newFDStateStoreFromMaps(nil, nil),
				state:     newTraceState(),
			}
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
			if got := session.fdStateStore().paths["101:7"]; got != "/tmp/"+tt.name {
				t.Fatalf("%s fd path = %q, want direct TLV path", tt.name, got)
			}
		})
	}
}
