package main

import (
	"bytes"
	"testing"

	"strace-go/pkg/handler"
)

func TestSyscallEventContextMergesSelectDirectTLVSections(t *testing.T) {
	session := miscStructTLVSession("select")
	args := [6]uint64{16, 0x1000, 0x2000, 0x3000, 0x4000}
	enterRead := []byte{0x08, 0x00}
	enterWrite := []byte{0x10, 0x00}
	enterExcept := []byte{0x20, 0x00}
	enterTimeout := selectJSONTimeval(9, 10)
	enterPayload := selectDirectTLVPayload(t, args, handler.PayloadDirectionIn, enterRead, enterWrite, enterExcept, enterTimeout)
	enterRaw := miscStructTLVEvent(t, "select", bpfEventTypeEnter, args, 0, enterPayload)
	enterRaw.EventFlags |= bpfEventFlagGenericEnter
	session.traceState().handleEnvelope(newTraceEventEnvelopeFromBPF(enterRaw))

	exitRead := []byte{0x00, 0x01}
	exitWrite := []byte{0x00, 0x02}
	exitExcept := []byte{0x00, 0x04}
	exitTimeout := selectJSONTimeval(1, 2)
	exitPayload := selectDirectTLVPayload(t, args, handler.PayloadDirectionOut, exitRead, exitWrite, exitExcept, exitTimeout)
	exitRaw := miscStructTLVEvent(t, "select", bpfEventTypeExit, args, 2, exitPayload)
	exitUpdate := session.traceState().handleEnvelope(newTraceEventEnvelopeFromBPF(exitRaw))
	ev := newSyscallEventContextFromView(
		session,
		exitUpdate.syscallView,
		101,
		exitUpdate.pendingEnter,
		exitUpdate.payloadSections)

	assertSelectDirectSection(t, ev.handlerContext.PayloadSections, handler.PayloadKindBytes, 1, handler.PayloadDirectionIn, enterRead)
	assertSelectDirectSection(t, ev.handlerContext.PayloadSections, handler.PayloadKindBytes, 2, handler.PayloadDirectionIn, enterWrite)
	assertSelectDirectSection(t, ev.handlerContext.PayloadSections, handler.PayloadKindBytes, 3, handler.PayloadDirectionIn, enterExcept)
	assertSelectDirectSection(t, ev.handlerContext.PayloadSections, handler.PayloadKindStruct, 4, handler.PayloadDirectionIn, enterTimeout)
	assertSelectDirectSection(t, ev.handlerContext.PayloadSections, handler.PayloadKindBytes, 1, handler.PayloadDirectionOut, exitRead)
	assertSelectDirectSection(t, ev.handlerContext.PayloadSections, handler.PayloadKindBytes, 2, handler.PayloadDirectionOut, exitWrite)
	assertSelectDirectSection(t, ev.handlerContext.PayloadSections, handler.PayloadKindBytes, 3, handler.PayloadDirectionOut, exitExcept)
	assertSelectDirectSection(t, ev.handlerContext.PayloadSections, handler.PayloadKindStruct, 4, handler.PayloadDirectionOut, exitTimeout)
}

func selectDirectTLVPayload(
	t *testing.T,
	args [6]uint64,
	direction handler.PayloadDirection,
	readfds []byte,
	writefds []byte,
	exceptfds []byte,
	timeout []byte,
) []byte {
	t.Helper()
	flags := uint16(0)
	if direction == handler.PayloadDirectionOut {
		flags = payloadTLVFlagDirectionOut
	}
	payload := payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindBytes,
		flags:   flags,
		arg:     1,
		userPtr: args[1],
		userLen: uint32(len(readfds)),
		data:    readfds,
	})
	payload = append(payload, payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindBytes,
		flags:   flags,
		arg:     2,
		userPtr: args[2],
		userLen: uint32(len(writefds)),
		data:    writefds,
	})...)
	payload = append(payload, payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindBytes,
		flags:   flags,
		arg:     3,
		userPtr: args[3],
		userLen: uint32(len(exceptfds)),
		data:    exceptfds,
	})...)
	payload = append(payload, payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindStruct,
		flags:   flags,
		arg:     4,
		userPtr: args[4],
		userLen: uint32(len(timeout)),
		data:    timeout,
	})...)
	return payload
}

func assertSelectDirectSection(
	t *testing.T,
	sections []handler.PayloadSection,
	kind handler.PayloadKind,
	argIndex int,
	direction handler.PayloadDirection,
	wantData []byte,
) {
	t.Helper()
	for _, section := range sections {
		if section.Kind != kind || section.ArgIndex != argIndex || section.Direction != direction {
			continue
		}
		if !bytes.Equal(section.Data, wantData) {
			t.Fatalf("select %s arg%d section data = %v, want %v", direction, argIndex, section.Data, wantData)
		}
		return
	}
	t.Fatalf("select %s arg%d %s section missing in %+v", direction, argIndex, kind, sections)
}
