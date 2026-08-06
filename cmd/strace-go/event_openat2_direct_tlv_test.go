package main

import (
	"bytes"
	"testing"

	"strace-go/pkg/handler"
)

func TestSyscallEventContextMergesOpenat2DirectTLVSections(t *testing.T) {
	session := miscStructTLVSession("openat2")
	args := [6]uint64{^uint64(99), 0x1000, 0x2000, 24}
	pathData := []byte("/tmp/openat2\x00")
	howData := bytes.Repeat([]byte{0x7a}, 24)
	enterPayload := payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindString,
		arg:     1,
		userPtr: args[1],
		userLen: uint32(len(pathData)),
		data:    pathData,
	})
	enterPayload = append(enterPayload, payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindStruct,
		arg:     2,
		userPtr: args[2],
		userLen: uint32(len(howData)),
		data:    howData,
	})...)
	enterEnvelope := testTLVSyscallEnvelope(t, "openat2", bpfEventTypeEnter, args, 0, enterPayload)
	session.traceState().handleEnvelope(enterEnvelope)

	exitEnvelope := testTLVSyscallEnvelope(t, "openat2", bpfEventTypeExit, args, -1, nil)
	exitUpdate := session.traceState().handleEnvelope(exitEnvelope)
	ev := newSyscallEventContextFromView(
		session,
		exitUpdate.syscallView,
		101,
		exitUpdate.pendingEnter,
		exitUpdate.payloadSections)

	assertOpenat2DirectSection(t, ev.handlerContext.PayloadSections, 1, handler.PayloadKindString, pathData)
	assertOpenat2DirectSection(t, ev.handlerContext.PayloadSections, 2, handler.PayloadKindStruct, howData)
}

func assertOpenat2DirectSection(
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
				t.Fatalf("openat2 section arg %d = %+v; want IN %s %v", argIndex, section, kind, wantData)
			}
			return
		}
	}
	t.Fatalf("missing openat2 section arg %d kind %s in %+v", argIndex, kind, sections)
}
