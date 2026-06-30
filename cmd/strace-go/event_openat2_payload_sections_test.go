package main

import (
	"bytes"
	"testing"

	"strace-go/pkg/meta"
)

func TestJSONSyscallEventIncludesOpenat2PayloadSections(t *testing.T) {
	eventRaw := &bpfEvent{
		EventType:     bpfEventTypeEnter,
		Args:          [6]uint64{^uint64(99), 0x1000, 0x2000, openat2HowPayloadMax},
		DataLen:       openat2HowPayloadOffset + openat2HowPayloadMax,
		ProbeRetEnter: 0,
	}
	pathData := []byte("file\x00")
	howData := bytes.Repeat([]byte{0x7a}, openat2HowPayloadMax)
	copy(eventRaw.StrArg[:], pathData)
	copy(eventRaw.StrArg[openat2HowPayloadOffset:], howData)

	scMeta := meta.Syscall{Name: "openat2"}
	ev := newJSONSyscallEvent(eventRaw, scMeta, payloadSectionsForEvent(eventRaw, scMeta))
	if len(ev.PayloadSections) != 2 {
		t.Fatalf("PayloadSections = %d, want 2", len(ev.PayloadSections))
	}
	assertOpenat2JSONSection(t, ev.PayloadSections[0], "string", 1, 0, 0x1000, pathData)
	assertOpenat2JSONSection(t, ev.PayloadSections[1], "struct", 2, openat2HowPayloadOffset, 0x2000, howData)
}

func assertOpenat2JSONSection(
	t *testing.T,
	got jsonPayloadSection,
	kind string,
	argIndex int,
	offset int,
	userPtr uint64,
	wantData []byte,
) {
	t.Helper()
	if got.Kind != kind || got.Direction != "in" || got.ArgIndex != argIndex {
		t.Fatalf("openat2 section metadata = %+v", got)
	}
	if got.Offset != uint32(offset) || got.UserPtr != userPtr {
		t.Fatalf("openat2 section bounds = %+v", got)
	}
	if got.UserLen != uint32(len(wantData)) || got.CopiedLen != uint32(len(wantData)) {
		t.Fatalf("openat2 section lengths = %+v, want %d", got, len(wantData))
	}
	if data := mustDecodeBase64(t, got.DataBase64); !bytes.Equal(data, wantData) {
		t.Fatalf("openat2 section data = %v, want %v", data, wantData)
	}
}
