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
		payloadArg int
		payloadLen int
		ret        int64
	}{
		{
			name:       "futex",
			args:       [6]uint64{0x1000, 0, 0, 0x2000},
			payloadArg: 3,
			payloadLen: timespecPayloadStructSize,
			ret:        -110,
		},
		{
			name:       "futex_wait",
			args:       [6]uint64{0x1000, 1, 0xffffffff, 0, 0x3000, 1},
			payloadArg: 4,
			payloadLen: timespecPayloadStructSize,
			ret:        -11,
		},
		{
			name:       "futex_requeue",
			args:       [6]uint64{0x4000, 2, 0, 0},
			payloadArg: 0,
			payloadLen: futexPayloadRequeueSize,
			ret:        0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := miscStructTLVSession(tt.name)
			payload := bytes.Repeat([]byte{0x44}, tt.payloadLen)
			enterPayload := payloadTLVBytes(t, payloadTLVTestSection{
				kind:    payloadTLVKindStruct,
				arg:     uint16(tt.payloadArg),
				userPtr: tt.args[tt.payloadArg],
				userLen: uint32(tt.payloadLen),
				data:    payload,
			})
			enterRaw := miscStructTLVEvent(t, tt.name, bpfEventTypeEnter, tt.args, 0, enterPayload)
			enterRaw.EventFlags |= bpfEventFlagGenericEnter
			session.traceState().handleEnvelope(newTraceEventEnvelopeFromBPF(enterRaw))

			exitRaw := miscStructTLVEvent(t, tt.name, bpfEventTypeExit, tt.args, tt.ret, nil)
			exitUpdate := session.traceState().handleEnvelope(newTraceEventEnvelopeFromBPF(exitRaw))
			ev := newSyscallEventContextFromView(session, exitUpdate.syscallView, 101, exitUpdate.pendingEnter, exitUpdate.payloadSections)

			section, ok := ev.handlerContext.PayloadStruct(tt.payloadArg, handler.PayloadDirectionIn)
			if !ok || !bytes.Equal(section, payload) {
				t.Fatalf("%s IN struct section = %x, %v; want pending enter TLV struct", tt.name, section, ok)
			}
		})
	}
}
