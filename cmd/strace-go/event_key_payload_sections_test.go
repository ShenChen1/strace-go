package main

import (
	"bytes"
	"testing"

	"strace-go/pkg/meta"
)

func TestJSONSyscallEventIncludesAddKeyPayloadSections(t *testing.T) {
	eventRaw := &bpfEvent{
		EventType:     bpfEventTypeEnter,
		Args:          [6]uint64{0x1000, 0x2000, 0x3000, 3},
		DataLen:       keyDataPayloadOffset + 3,
		ProbeRetEnter: 0,
	}
	copy(eventRaw.StrArg[keyTypePayloadOffset:], []byte("user\x00"))
	copy(eventRaw.StrArg[keyDescriptionPayloadOffset:], []byte("desc\x00"))
	copy(eventRaw.StrArg[keyDataPayloadOffset:], []byte("abc"))

	sections := keyJSONPayloadSections(t, eventRaw, "add_key")
	if len(sections) != 3 {
		t.Fatalf("PayloadSections = %d, want 3", len(sections))
	}
	assertKeyJSONSection(t, sections[0], "string", 0, keyTypePayloadOffset, 0x1000, []byte("user\x00"))
	assertKeyJSONSection(t, sections[1], "string", 1, keyDescriptionPayloadOffset, 0x2000, []byte("desc\x00"))
	assertKeyJSONSection(t, sections[2], "bytes", 2, keyDataPayloadOffset, 0x3000, []byte("abc"))
}

func TestJSONSyscallEventIncludesRequestKeyPayloadSections(t *testing.T) {
	eventRaw := &bpfEvent{
		EventType:     bpfEventTypeEnter,
		Args:          [6]uint64{0x1000, 0x2000, 0x3000},
		DataLen:       keyDataPayloadOffset + keyDataPayloadMaxBytes,
		ProbeRetEnter: 0,
	}
	copy(eventRaw.StrArg[keyTypePayloadOffset:], []byte("user\x00"))
	copy(eventRaw.StrArg[keyDescriptionPayloadOffset:], []byte("desc\x00"))
	copy(eventRaw.StrArg[keyDataPayloadOffset:], []byte("info\x00"))

	sections := keyJSONPayloadSections(t, eventRaw, "request_key")
	if len(sections) != 3 {
		t.Fatalf("PayloadSections = %d, want 3", len(sections))
	}
	assertKeyJSONSection(t, sections[0], "string", 0, keyTypePayloadOffset, 0x1000, []byte("user\x00"))
	assertKeyJSONSection(t, sections[1], "string", 1, keyDescriptionPayloadOffset, 0x2000, []byte("desc\x00"))
	assertKeyJSONSection(t, sections[2], "string", 2, keyDataPayloadOffset, 0x3000, []byte("info\x00"))
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
	offset int,
	userPtr uint64,
	wantData []byte,
) {
	t.Helper()
	if got.Kind != kind || got.Direction != "in" || got.ArgIndex != argIndex {
		t.Fatalf("key section metadata = %+v", got)
	}
	if got.Offset != uint32(offset) || got.UserPtr != userPtr {
		t.Fatalf("key section bounds = %+v", got)
	}
	if got.UserLen != uint32(len(wantData)) || got.CopiedLen != uint32(len(wantData)) {
		t.Fatalf("key section lengths = %+v, want %d", got, len(wantData))
	}
	if data := mustDecodeBase64(t, got.DataBase64); !bytes.Equal(data, wantData) {
		t.Fatalf("key section data = %v, want %v", data, wantData)
	}
}
