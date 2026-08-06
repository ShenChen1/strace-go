package main

import (
	"bytes"
	"testing"
)

const openat2HowPayloadMax = 64

func TestJSONSyscallEventIncludesOpenat2PayloadSections(t *testing.T) {
	pathData := []byte("file\x00")
	howData := bytes.Repeat([]byte{0x7a}, openat2HowPayloadMax)
	args := [6]uint64{^uint64(99), 0x1000, 0x2000, openat2HowPayloadMax}
	payload := payloadTLVBytesForTest(t, openat2JSONTLVSections(pathData, howData)...)

	ev := newJSONSyscallEventFromTLVForTest(t, "openat2", bpfEventTypeEnter, args, 0, payload)
	if len(ev.PayloadSections) != 2 {
		t.Fatalf("PayloadSections = %d, want 2", len(ev.PayloadSections))
	}
	assertOpenat2JSONSection(t, ev.PayloadSections[0], "string", 1, 0x1000, pathData)
	assertOpenat2JSONSection(t, ev.PayloadSections[1], "struct", 2, 0x2000, howData)
}

func openat2JSONTLVSections(pathData []byte, howData []byte) []payloadTLVTestSection {
	return []payloadTLVTestSection{
		{
			kind:    payloadTLVKindString,
			arg:     1,
			userPtr: 0x1000,
			userLen: uint32(len(pathData)),
			data:    pathData,
		},
		{
			kind:    payloadTLVKindStruct,
			arg:     2,
			userPtr: 0x2000,
			userLen: uint32(len(howData)),
			data:    howData,
		},
	}
}

func assertOpenat2JSONSection(
	t *testing.T,
	got jsonPayloadSection,
	kind string,
	argIndex int,
	userPtr uint64,
	wantData []byte,
) {
	t.Helper()
	if got.Kind != kind || got.Direction != "in" || got.ArgIndex != argIndex {
		t.Fatalf("openat2 section metadata = %+v", got)
	}
	if got.UserPtr != userPtr {
		t.Fatalf("openat2 section bounds = %+v", got)
	}
	if got.UserLen != uint32(len(wantData)) || got.CopiedLen != uint32(len(wantData)) {
		t.Fatalf("openat2 section lengths = %+v, want %d", got, len(wantData))
	}
	if data := mustDecodeBase64(t, got.DataBase64); !bytes.Equal(data, wantData) {
		t.Fatalf("openat2 section data = %v, want %v", data, wantData)
	}
}
