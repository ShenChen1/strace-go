package main

import (
	"bytes"
	"testing"

	"strace-go/pkg/meta"
)

func TestJSONSyscallEventIncludesAddKeyPayloadSections(t *testing.T) {
	args := [6]uint64{0x1000, 0x2000, 0x3000, 3}
	typeData := []byte("user\x00")
	descData := []byte("desc\x00")
	payloadData := []byte("abc")
	payload := keyJSONTLVPayload(t, []payloadTLVTestSection{
		{
			kind:    payloadTLVKindString,
			arg:     0,
			userPtr: args[0],
			userLen: uint32(len(typeData)),
			data:    typeData,
		},
		{
			kind:    payloadTLVKindString,
			arg:     1,
			userPtr: args[1],
			userLen: uint32(len(descData)),
			data:    descData,
		},
		{
			kind:    payloadTLVKindBytes,
			arg:     2,
			userPtr: args[2],
			userLen: uint32(len(payloadData)),
			data:    payloadData,
		},
	})
	eventRaw := &bpfEvent{
		EventType:  bpfEventTypeEnter,
		EventFlags: bpfEventFlagPayloadTLV,
		Args:       args,
		DataLen:    uint32(len(payload)),
	}
	copy(eventRaw.StrArg[:], payload)

	sections := keyJSONPayloadSections(t, eventRaw, "add_key")
	if len(sections) != 3 {
		t.Fatalf("PayloadSections = %d, want 3", len(sections))
	}
	assertKeyJSONSection(t, sections[0], "string", 0, 0x1000, typeData)
	assertKeyJSONSection(t, sections[1], "string", 1, 0x2000, descData)
	assertKeyJSONSection(t, sections[2], "bytes", 2, 0x3000, payloadData)
}

func TestJSONSyscallEventIncludesRequestKeyPayloadSections(t *testing.T) {
	args := [6]uint64{0x1000, 0x2000, 0x3000}
	typeData := []byte("user\x00")
	descData := []byte("desc\x00")
	infoData := []byte("info\x00")
	payload := keyJSONTLVPayload(t, []payloadTLVTestSection{
		{
			kind:    payloadTLVKindString,
			arg:     0,
			userPtr: args[0],
			userLen: uint32(len(typeData)),
			data:    typeData,
		},
		{
			kind:    payloadTLVKindString,
			arg:     1,
			userPtr: args[1],
			userLen: uint32(len(descData)),
			data:    descData,
		},
		{
			kind:    payloadTLVKindString,
			arg:     2,
			userPtr: args[2],
			userLen: uint32(len(infoData)),
			data:    infoData,
		},
	})
	eventRaw := &bpfEvent{
		EventType:  bpfEventTypeEnter,
		EventFlags: bpfEventFlagPayloadTLV,
		Args:       args,
		DataLen:    uint32(len(payload)),
	}
	copy(eventRaw.StrArg[:], payload)

	sections := keyJSONPayloadSections(t, eventRaw, "request_key")
	if len(sections) != 3 {
		t.Fatalf("PayloadSections = %d, want 3", len(sections))
	}
	assertKeyJSONSection(t, sections[0], "string", 0, 0x1000, typeData)
	assertKeyJSONSection(t, sections[1], "string", 1, 0x2000, descData)
	assertKeyJSONSection(t, sections[2], "string", 2, 0x3000, infoData)
}

func keyJSONTLVPayload(t *testing.T, sections []payloadTLVTestSection) []byte {
	t.Helper()
	var payload []byte
	for _, section := range sections {
		payload = append(payload, payloadTLVBytes(t, section)...)
	}
	return payload
}

func keyJSONPayloadSections(t *testing.T, eventRaw *bpfEvent, name string) []jsonPayloadSection {
	t.Helper()
	scMeta := meta.Syscall{Name: name}
	ev := newJSONSyscallEvent(eventRaw, scMeta, payloadSectionsForEvent(eventRaw, scMeta))
	return ev.PayloadSections
}

func assertKeyJSONSection(
	t *testing.T,
	got jsonPayloadSection,
	kind string,
	argIndex int,
	userPtr uint64,
	wantData []byte,
) {
	t.Helper()
	if got.Kind != kind || got.Direction != "in" || got.ArgIndex != argIndex {
		t.Fatalf("key section metadata = %+v", got)
	}
	if got.UserPtr != userPtr {
		t.Fatalf("key section bounds = %+v", got)
	}
	if got.UserLen != uint32(len(wantData)) || got.CopiedLen != uint32(len(wantData)) {
		t.Fatalf("key section lengths = %+v, want %d", got, len(wantData))
	}
	if data := mustDecodeBase64(t, got.DataBase64); !bytes.Equal(data, wantData) {
		t.Fatalf("key section data = %v, want %v", data, wantData)
	}
}
