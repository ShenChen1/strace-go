package main

import (
	"bytes"
	"testing"

	"strace-go/pkg/meta"
)

func TestJSONSyscallEventIncludesSetxattrPayloadSections(t *testing.T) {
	args := [6]uint64{0x1000, 0x2000, 0x3000, 3}
	pathData := []byte("/tmp/a\x00")
	nameData := []byte("user.k\x00")
	valueData := []byte("abc")
	eventRaw := &bpfEvent{
		EventType: bpfEventTypeEnter,
		Args:      args,
	}
	setJSONTestTLVPayload(t, eventRaw,
		xattrJSONTLVString(0, args[0], pathData),
		xattrJSONTLVString(1, args[1], nameData),
		xattrJSONTLVBytes(2, 0, args[2], valueData),
	)

	sections := xattrJSONPayloadSections(t, eventRaw, "setxattr")
	if len(sections) != 3 {
		t.Fatalf("PayloadSections = %d, want 3", len(sections))
	}
	assertXattrJSONSection(t, sections[0], "string", "in", 0, 0x1000, pathData)
	assertXattrJSONSection(t, sections[1], "string", "in", 1, 0x2000, nameData)
	assertXattrJSONSection(t, sections[2], "bytes", "in", 2, 0x3000, valueData)
}

func TestJSONSyscallEventIncludesFgetxattrPayloadSection(t *testing.T) {
	args := [6]uint64{3, 0x2000, 0x3000, 4}
	nameData := []byte("user.k\x00")
	valueData := []byte("data")
	eventRaw := &bpfEvent{
		EventType: bpfEventTypeExit,
		Args:      args,
		Ret:       int64(len(valueData)),
	}
	setJSONTestTLVPayload(t, eventRaw,
		xattrJSONTLVString(1, args[1], nameData),
		xattrJSONTLVBytes(2, payloadTLVFlagDirectionOut, args[2], valueData),
	)

	sections := xattrJSONPayloadSections(t, eventRaw, "fgetxattr")
	if len(sections) != 2 {
		t.Fatalf("PayloadSections = %d, want 2", len(sections))
	}
	assertXattrJSONSection(t, sections[0], "string", "in", 1, 0x2000, nameData)
	assertXattrJSONSection(t, sections[1], "bytes", "out", 2, 0x3000, valueData)
}

func TestJSONSyscallEventIncludesListxattrPayloadSection(t *testing.T) {
	args := [6]uint64{0x1000, 0x3000, 13}
	pathData := []byte("/tmp/a\x00")
	listData := []byte("user.a\x00user.b")
	eventRaw := &bpfEvent{
		EventType: bpfEventTypeExit,
		Args:      args,
		Ret:       int64(len(listData)),
	}
	setJSONTestTLVPayload(t, eventRaw,
		xattrJSONTLVString(0, args[0], pathData),
		xattrJSONTLVBytes(1, payloadTLVFlagDirectionOut, args[1], listData),
	)

	sections := xattrJSONPayloadSections(t, eventRaw, "listxattr")
	if len(sections) != 2 {
		t.Fatalf("PayloadSections = %d, want 2", len(sections))
	}
	assertXattrJSONSection(t, sections[0], "string", "in", 0, 0x1000, pathData)
	assertXattrJSONSection(t, sections[1], "bytes", "out", 1, 0x3000, listData)
}

func xattrJSONTLVString(arg uint16, userPtr uint64, data []byte) payloadTLVTestSection {
	return payloadTLVTestSection{
		kind:    payloadTLVKindString,
		arg:     arg,
		userPtr: userPtr,
		userLen: uint32(len(data)),
		data:    data,
	}
}

func xattrJSONTLVBytes(arg uint16, flags uint16, userPtr uint64, data []byte) payloadTLVTestSection {
	return payloadTLVTestSection{
		kind:    payloadTLVKindBytes,
		flags:   flags,
		arg:     arg,
		userPtr: userPtr,
		userLen: uint32(len(data)),
		data:    data,
	}
}

func xattrJSONPayloadSections(t *testing.T, eventRaw *bpfEvent, name string) []jsonPayloadSection {
	t.Helper()
	scMeta := meta.Syscall{Name: name}
	ev := newJSONSyscallEvent(eventRaw, scMeta, payloadSectionsForEvent(eventRaw, scMeta))
	return ev.PayloadSections
}

func assertXattrJSONSection(
	t *testing.T,
	got jsonPayloadSection,
	kind string,
	direction string,
	argIndex int,
	userPtr uint64,
	wantData []byte,
) {
	t.Helper()
	if got.Kind != kind || got.Direction != direction || got.ArgIndex != argIndex {
		t.Fatalf("xattr section metadata = %+v", got)
	}
	if got.UserPtr != userPtr {
		t.Fatalf("xattr section bounds = %+v", got)
	}
	if got.UserLen != uint32(len(wantData)) || got.CopiedLen != uint32(len(wantData)) {
		t.Fatalf("xattr section lengths = %+v, want %d", got, len(wantData))
	}
	if data := mustDecodeBase64(t, got.DataBase64); !bytes.Equal(data, wantData) {
		t.Fatalf("xattr section data = %v, want %v", data, wantData)
	}
}
