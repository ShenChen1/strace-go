package main

import (
	"bytes"
	"testing"

	"strace-go/pkg/meta"
)

func TestJSONSyscallEventIncludesSetxattrPayloadSections(t *testing.T) {
	eventRaw := &bpfEvent{
		EventType:     bpfEventTypeEnter,
		Args:          [6]uint64{0x1000, 0x2000, 0x3000, 3},
		DataLen:       xattrValuePayloadOffset + 3,
		ProbeRetEnter: 0,
	}
	copy(eventRaw.StrArg[xattrPathPayloadOffset:], []byte("/tmp/a\x00"))
	copy(eventRaw.StrArg[xattrNamePayloadOffset:], []byte("user.k\x00"))
	copy(eventRaw.StrArg[xattrValuePayloadOffset:], []byte("abc"))

	sections := xattrJSONPayloadSections(t, eventRaw, "setxattr")
	if len(sections) != 3 {
		t.Fatalf("PayloadSections = %d, want 3", len(sections))
	}
	assertXattrJSONSection(t, sections[0], "string", "in", 0, xattrPathPayloadOffset, 0x1000, []byte("/tmp/a\x00"))
	assertXattrJSONSection(t, sections[1], "string", "in", 1, xattrNamePayloadOffset, 0x2000, []byte("user.k\x00"))
	assertXattrJSONSection(t, sections[2], "bytes", "in", 2, xattrValuePayloadOffset, 0x3000, []byte("abc"))
}

func TestJSONSyscallEventIncludesFgetxattrPayloadSection(t *testing.T) {
	eventRaw := &bpfEvent{
		EventType:     bpfEventTypeExit,
		Args:          [6]uint64{3, 0x2000, 0x3000, 4},
		Ret:           4,
		DataLen:       xattrFValuePayloadOffset + 4,
		ProbeRetEnter: 0,
		ProbeRetExit:  0,
	}
	copy(eventRaw.StrArg[xattrFNamePayloadOffset:], []byte("user.k\x00"))
	copy(eventRaw.StrArg[xattrFValuePayloadOffset:], []byte("data"))

	sections := xattrJSONPayloadSections(t, eventRaw, "fgetxattr")
	if len(sections) != 2 {
		t.Fatalf("PayloadSections = %d, want 2", len(sections))
	}
	assertXattrJSONSection(t, sections[0], "string", "in", 1, xattrFNamePayloadOffset, 0x2000, []byte("user.k\x00"))
	assertXattrJSONSection(t, sections[1], "bytes", "out", 2, xattrFValuePayloadOffset, 0x3000, []byte("data"))
}

func TestJSONSyscallEventIncludesListxattrPayloadSection(t *testing.T) {
	eventRaw := &bpfEvent{
		EventType:     bpfEventTypeExit,
		Args:          [6]uint64{0x1000, 0x3000, 13},
		Ret:           13,
		DataLen:       xattrListPayloadOffset + 13,
		ProbeRetEnter: 0,
		ProbeRetExit:  0,
	}
	copy(eventRaw.StrArg[xattrPathPayloadOffset:], []byte("/tmp/a\x00"))
	copy(eventRaw.StrArg[xattrListPayloadOffset:], []byte("user.a\x00user.b"))

	sections := xattrJSONPayloadSections(t, eventRaw, "listxattr")
	if len(sections) != 2 {
		t.Fatalf("PayloadSections = %d, want 2", len(sections))
	}
	assertXattrJSONSection(t, sections[0], "string", "in", 0, xattrPathPayloadOffset, 0x1000, []byte("/tmp/a\x00"))
	assertXattrJSONSection(t, sections[1], "bytes", "out", 1, xattrListPayloadOffset, 0x3000, []byte("user.a\x00user.b"))
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
	offset int,
	userPtr uint64,
	wantData []byte,
) {
	t.Helper()
	if got.Kind != kind || got.Direction != direction || got.ArgIndex != argIndex {
		t.Fatalf("xattr section metadata = %+v", got)
	}
	if got.Offset != uint32(offset) || got.UserPtr != userPtr {
		t.Fatalf("xattr section bounds = %+v", got)
	}
	if got.UserLen != uint32(len(wantData)) || got.CopiedLen != uint32(len(wantData)) {
		t.Fatalf("xattr section lengths = %+v, want %d", got, len(wantData))
	}
	if data := mustDecodeBase64(t, got.DataBase64); !bytes.Equal(data, wantData) {
		t.Fatalf("xattr section data = %v, want %v", data, wantData)
	}
}
