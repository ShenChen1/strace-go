package main

import (
	"bytes"
	"testing"

	"strace-go/pkg/handler"
)

func TestSyscallEventContextMergesAddKeyTLVSections(t *testing.T) {
	session := miscStructTLVSession("add_key")
	args := [6]uint64{0x1000, 0x2000, 0x3000, 3}
	typeData := []byte("user\x00")
	descData := []byte("desc\x00")
	payloadData := []byte("abc")
	enterPayload := payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindString,
		arg:     0,
		userPtr: args[0],
		userLen: uint32(len(typeData)),
		data:    typeData,
	})
	enterPayload = append(enterPayload, payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindString,
		arg:     1,
		userPtr: args[1],
		userLen: uint32(len(descData)),
		data:    descData,
	})...)
	enterPayload = append(enterPayload, payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindBytes,
		arg:     2,
		userPtr: args[2],
		userLen: uint32(len(payloadData)),
		data:    payloadData,
	})...)
	enterRaw := miscStructTLVEvent(t, "add_key", bpfEventTypeEnter, args, 0, enterPayload)
	enterRaw.EventFlags |= bpfEventFlagGenericEnter
	session.traceState().handleEnvelope(newTraceEventEnvelopeFromBPF(enterRaw))

	exitRaw := miscStructTLVEvent(t, "add_key", bpfEventTypeExit, args, 7, nil)
	exitUpdate := session.traceState().handleEnvelope(newTraceEventEnvelopeFromBPF(exitRaw))
	ev := newSyscallEventContextFromView(
		session,
		exitUpdate.syscallView,
		101,
		exitUpdate.pendingEnter,
		exitUpdate.payloadSections)

	assertKeyDirectSection(t, ev.handlerContext.PayloadSections, 0, handler.PayloadKindString, typeData)
	assertKeyDirectSection(t, ev.handlerContext.PayloadSections, 1, handler.PayloadKindString, descData)
	assertKeyDirectSection(t, ev.handlerContext.PayloadSections, 2, handler.PayloadKindBytes, payloadData)
}

func TestSyscallEventContextMergesRequestKeyTLVSections(t *testing.T) {
	session := miscStructTLVSession("request_key")
	args := [6]uint64{0x1000, 0x2000, 0x3000}
	typeData := []byte("user\x00")
	descData := []byte("desc\x00")
	infoData := []byte("info\x00")
	enterPayload := payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindString,
		arg:     0,
		userPtr: args[0],
		userLen: uint32(len(typeData)),
		data:    typeData,
	})
	enterPayload = append(enterPayload, payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindString,
		arg:     1,
		userPtr: args[1],
		userLen: uint32(len(descData)),
		data:    descData,
	})...)
	enterPayload = append(enterPayload, payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindString,
		arg:     2,
		userPtr: args[2],
		userLen: uint32(len(infoData)),
		data:    infoData,
	})...)
	enterRaw := miscStructTLVEvent(t, "request_key", bpfEventTypeEnter, args, 0, enterPayload)
	enterRaw.EventFlags |= bpfEventFlagGenericEnter
	session.traceState().handleEnvelope(newTraceEventEnvelopeFromBPF(enterRaw))

	exitRaw := miscStructTLVEvent(t, "request_key", bpfEventTypeExit, args, -1, nil)
	exitUpdate := session.traceState().handleEnvelope(newTraceEventEnvelopeFromBPF(exitRaw))
	ev := newSyscallEventContextFromView(
		session,
		exitUpdate.syscallView,
		101,
		exitUpdate.pendingEnter,
		exitUpdate.payloadSections)

	assertKeyDirectSection(t, ev.handlerContext.PayloadSections, 0, handler.PayloadKindString, typeData)
	assertKeyDirectSection(t, ev.handlerContext.PayloadSections, 1, handler.PayloadKindString, descData)
	assertKeyDirectSection(t, ev.handlerContext.PayloadSections, 2, handler.PayloadKindString, infoData)
}

func assertKeyDirectSection(
	t *testing.T,
	sections []handler.PayloadSection,
	argIndex int,
	kind handler.PayloadKind,
	wantData []byte,
) {
	t.Helper()
	for _, section := range sections {
		if section.ArgIndex == argIndex && section.Kind == kind {
			if section.Direction != handler.PayloadDirectionIn || !bytes.Equal(section.Data, wantData) {
				t.Fatalf("key section arg %d = %+v; want IN %s %v", argIndex, section, kind, wantData)
			}
			return
		}
	}
	t.Fatalf("missing key section arg %d kind %s in %+v", argIndex, kind, sections)
}
