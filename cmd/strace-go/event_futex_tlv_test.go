package main

import (
	"bytes"
	"testing"

	"strace-go/pkg/handler"
)

func TestSyscallEventContextUsesFutexTLVSection(t *testing.T) {
	tests := []struct {
		name       string
		args       [6]uint64
		timeoutArg int
		ret        int64
	}{
		{
			name:       "futex",
			args:       [6]uint64{0x1000, 0, 0, 0x2000},
			timeoutArg: 3,
			ret:        -110,
		},
		{
			name:       "futex_wait",
			args:       [6]uint64{0x1000, 1, 0xffffffff, 0, 0x3000, 1},
			timeoutArg: 4,
			ret:        -11,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := miscStructTLVSession(tt.name)
			timeout := bytes.Repeat([]byte{0x44}, timespecPayloadStructSize)
			enterPayload := payloadTLVBytes(t, payloadTLVTestSection{
				kind:    payloadTLVKindStruct,
				arg:     uint16(tt.timeoutArg),
				userPtr: tt.args[tt.timeoutArg],
				userLen: timespecPayloadStructSize,
				data:    timeout,
			})
			enterRaw := miscStructTLVEvent(t, tt.name, bpfEventTypeEnter, tt.args, 0, enterPayload)
			enterRaw.EventFlags |= bpfEventFlagGenericEnter
			session.traceState().handleEnvelope(newTraceEventEnvelopeFromBPF(enterRaw))

			exitRaw := miscStructTLVEvent(t, tt.name, bpfEventTypeExit, tt.args, tt.ret, nil)
			exitUpdate := session.traceState().handleEnvelope(newTraceEventEnvelopeFromBPF(exitRaw))
			ev := newSyscallEventContextFromView(session, exitUpdate.syscallView, 101, exitUpdate.pendingEnter, exitUpdate.payloadSections)

			section, ok := ev.handlerContext.PayloadStruct(tt.timeoutArg, handler.PayloadDirectionIn)
			if !ok || !bytes.Equal(section, timeout) {
				t.Fatalf("%s IN timeout section = %x, %v; want pending enter TLV struct", tt.name, section, ok)
			}
		})
	}
}
