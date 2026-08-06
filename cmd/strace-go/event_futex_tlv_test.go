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
			enterEnvelope := testTLVSyscallEnvelope(t, tt.name, bpfEventTypeEnter, tt.args, 0, enterPayload)
			session.traceState().handleEnvelope(enterEnvelope)

			exitEnvelope := testTLVSyscallEnvelope(t, tt.name, bpfEventTypeExit, tt.args, tt.ret, nil)
			exitUpdate := session.traceState().handleEnvelope(exitEnvelope)
			ev := newSyscallEventContextFromView(session, exitUpdate.syscallView, 101, exitUpdate.pendingEnter, exitUpdate.payloadSections)

			section, ok := ev.handlerContext.PayloadStruct(tt.payloadArg, handler.PayloadDirectionIn)
			if !ok || !bytes.Equal(section, payload) {
				t.Fatalf("%s IN struct section = %x, %v; want pending enter TLV struct", tt.name, section, ok)
			}
		})
	}
}

func TestSyscallEventContextUsesFutexWaitvTLVSections(t *testing.T) {
	args := [6]uint64{0x1000, 2, 0, 0x4000}
	waiters := bytes.Repeat([]byte{0x55}, futexPayloadRequeueSize)
	timeout := bytes.Repeat([]byte{0x66}, timespecPayloadStructSize)
	enterPayload := append(
		payloadTLVBytes(t, payloadTLVTestSection{
			kind:    payloadTLVKindStruct,
			arg:     0,
			userPtr: args[0],
			userLen: uint32(len(waiters)),
			data:    waiters,
		}),
		payloadTLVBytes(t, payloadTLVTestSection{
			kind:    payloadTLVKindStruct,
			arg:     3,
			userPtr: args[3],
			userLen: uint32(len(timeout)),
			data:    timeout,
		})...,
	)

	session := miscStructTLVSession("futex_waitv")
	enterEnvelope := testTLVSyscallEnvelope(t, "futex_waitv", bpfEventTypeEnter, args, 0, enterPayload)
	session.traceState().handleEnvelope(enterEnvelope)

	exitEnvelope := testTLVSyscallEnvelope(t, "futex_waitv", bpfEventTypeExit, args, -11, nil)
	exitUpdate := session.traceState().handleEnvelope(exitEnvelope)
	ev := newSyscallEventContextFromView(session, exitUpdate.syscallView, 101, exitUpdate.pendingEnter, exitUpdate.payloadSections)

	if section, ok := ev.handlerContext.PayloadStruct(0, handler.PayloadDirectionIn); !ok || !bytes.Equal(section, waiters) {
		t.Fatalf("futex_waitv waiters section = %x, %v; want pending enter TLV struct", section, ok)
	}
	if section, ok := ev.handlerContext.PayloadStruct(3, handler.PayloadDirectionIn); !ok || !bytes.Equal(section, timeout) {
		t.Fatalf("futex_waitv timeout section = %x, %v; want pending enter TLV struct", section, ok)
	}
}
