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

func TestSyscallEventContextMergesEpollPwait2DirectTLVSections(t *testing.T) {
	session := miscStructTLVSession("epoll_pwait2")
	args := [6]uint64{5, 0x2000, 2, 0x3000, 0x4000, 8}
	timeout := epollDirectTestTimespecData(9, 10)
	enterPayload := payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindStruct,
		arg:     3,
		userPtr: args[3],
		userLen: uint32(len(timeout)),
		data:    timeout,
	})
	enterRaw := miscStructTLVEvent(t, "epoll_pwait2", bpfEventTypeEnter, args, 0, enterPayload)
	enterRaw.EventFlags |= bpfEventFlagGenericEnter
	session.traceState().handleEnvelope(newTraceEventEnvelopeFromBPF(enterRaw))

	events := append(epollDirectTestEventData(1, 0x11), epollDirectTestEventData(4, 0x22)...)
	exitPayload := payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindStruct,
		flags:   payloadTLVFlagDirectionOut,
		arg:     1,
		userPtr: args[1],
		userLen: uint32(len(events)),
		data:    events,
	})
	exitRaw := miscStructTLVEvent(t, "epoll_pwait2", bpfEventTypeExit, args, 2, exitPayload)
	exitUpdate := session.traceState().handleEnvelope(newTraceEventEnvelopeFromBPF(exitRaw))
	ev := newSyscallEventContextFromView(
		session,
		exitUpdate.syscallView,
		101,
		exitUpdate.pendingEnter,
		exitUpdate.payloadSections)

	timeoutSection, ok := ev.handlerContext.Section(3, handler.PayloadKindStruct)
	if !ok || timeoutSection.Direction != handler.PayloadDirectionIn || !bytes.Equal(timeoutSection.Data, timeout) {
		t.Fatalf("epoll_pwait2 timeout section = %+v, %v; want pending enter IN struct TLV", timeoutSection, ok)
	}
	eventsSection, ok := ev.handlerContext.Section(1, handler.PayloadKindStruct)
	if !ok || eventsSection.Direction != handler.PayloadDirectionOut || !bytes.Equal(eventsSection.Data, events) {
		t.Fatalf("epoll_pwait2 events section = %+v, %v; want direct OUT struct TLV", eventsSection, ok)
	}
}

func epollDirectTestEventData(events uint32, data uint64) []byte {
	buf := make([]byte, epollPayloadEventSize)
	binary.LittleEndian.PutUint32(buf[0:4], events)
	binary.LittleEndian.PutUint64(buf[4:12], data)
	return buf
}

func epollDirectTestTimespecData(sec int64, nsec uint64) []byte {
	buf := make([]byte, timespecPayloadStructSize)
	binary.LittleEndian.PutUint64(buf[0:8], uint64(sec))
	binary.LittleEndian.PutUint64(buf[8:16], nsec)
	return buf
}
