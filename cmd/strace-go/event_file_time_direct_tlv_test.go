package main

import (
	"bytes"
	"testing"

	"strace-go/pkg/handler"
)

func TestSyscallEventContextUsesFileTimeDirectTLVSections(t *testing.T) {
	tests := []struct {
		name     string
		args     [6]uint64
		pathArg  uint16
		valueArg uint16
		valueLen uint32
	}{
		{
			name:     "utime",
			args:     [6]uint64{0x1000, 0x2000},
			pathArg:  0,
			valueArg: 1,
			valueLen: timePayloadUtimbufSize,
		},
		{
			name:     "utimensat",
			args:     [6]uint64{rawAtFdcwd, 0x3000, 0x4000, 0},
			pathArg:  1,
			valueArg: 2,
			valueLen: timePayloadItimervalSize,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := miscStructTLVSession(tt.name)
			pathData := []byte("/tmp/strace-go-file-time\x00")
			valueData := bytes.Repeat([]byte{0x5a}, int(tt.valueLen))
			enterPayload := payloadTLVBytes(t, payloadTLVTestSection{
				kind:    payloadTLVKindString,
				arg:     tt.pathArg,
				userPtr: tt.args[tt.pathArg],
				userLen: uint32(len(pathData)),
				data:    pathData,
			})
			enterPayload = append(enterPayload, payloadTLVBytes(t, payloadTLVTestSection{
				kind:    payloadTLVKindStruct,
				arg:     tt.valueArg,
				userPtr: tt.args[tt.valueArg],
				userLen: tt.valueLen,
				data:    valueData,
			})...)
			enterEnvelope := testTLVSyscallEnvelope(t, tt.name, bpfEventTypeEnter, tt.args, 0, enterPayload)
			session.traceState().handleEnvelope(enterEnvelope)

			exitEnvelope := testTLVSyscallEnvelope(t, tt.name, bpfEventTypeExit, tt.args, -2, nil)
			exitUpdate := session.traceState().handleEnvelope(exitEnvelope)
			ev := newSyscallEventContextFromView(
				session,
				exitUpdate.syscallView,
				101,
				exitUpdate.pendingEnter,
				exitUpdate.payloadSections)

			pathSection, ok := ev.handlerContext.Section(int(tt.pathArg), handler.PayloadKindString)
			if !ok || pathSection.Direction != handler.PayloadDirectionIn || !bytes.Equal(pathSection.Data, pathData) {
				t.Fatalf("%s path section = %+v, %v; want pending enter string TLV", tt.name, pathSection, ok)
			}
			valueSection, ok := ev.handlerContext.PayloadStruct(int(tt.valueArg), handler.PayloadDirectionIn)
			if !ok || !bytes.Equal(valueSection, valueData) {
				t.Fatalf("%s time section = %x, %v; want pending enter struct TLV", tt.name, valueSection, ok)
			}
		})
	}
}
