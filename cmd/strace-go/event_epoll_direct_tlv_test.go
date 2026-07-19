package main

import (
	"bytes"
	"encoding/binary"
	"testing"

	"strace-go/pkg/handler"
)

func TestSyscallEventContextUsesEpollWaitDirectTLVSection(t *testing.T) {
	tests := []string{"epoll_wait", "epoll_pwait"}
	for _, syscallName := range tests {
		t.Run(syscallName, func(t *testing.T) {
			session := miscStructTLVSession(syscallName)
			args := [6]uint64{5, 0x2000, 2, 1000, 0, 8}
			events := append(epollDirectTestEventData(1, 0x11), epollDirectTestEventData(4, 0x22)...)
			exitPayload := payloadTLVBytes(t, payloadTLVTestSection{
				kind:    payloadTLVKindStruct,
				flags:   payloadTLVFlagDirectionOut,
				arg:     1,
				userPtr: args[1],
				userLen: uint32(len(events)),
				data:    events,
			})
			exitRaw := miscStructTLVEvent(t, syscallName, bpfEventTypeExit, args, 2, exitPayload)
			exitUpdate := session.traceState().handleEnvelope(newTraceEventEnvelopeFromBPF(exitRaw))
			ev := newSyscallEventContextFromView(
				session,
				exitUpdate.syscallView,
				101,
				exitUpdate.pendingEnter,
				exitUpdate.payloadSections)

			section, ok := ev.handlerContext.Section(1, handler.PayloadKindStruct)
			if !ok || section.Direction != handler.PayloadDirectionOut || !bytes.Equal(section.Data, events) {
				t.Fatalf("%s events section = %+v, %v; want direct OUT struct TLV", syscallName, section, ok)
			}
		})
	}
}

func epollDirectTestEventData(events uint32, data uint64) []byte {
	buf := make([]byte, epollPayloadEventSize)
	binary.LittleEndian.PutUint32(buf[0:4], events)
	binary.LittleEndian.PutUint64(buf[4:12], data)
	return buf
}
