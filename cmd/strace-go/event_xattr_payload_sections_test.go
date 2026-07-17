package main

import (
	"bytes"
	"testing"

	"strace-go/pkg/handler"
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

func TestPayloadSectionsForPayloadEventUsesSourceAwareXattrSetRule(t *testing.T) {
	raw := &bpfEvent{
		EventType:     bpfEventTypeEnter,
		Args:          [6]uint64{0x1000, 0x2000, 0x3000, 3},
		ProbeRetEnter: 0,
	}
	data := xattrSourcePayloadData([]byte("/tmp/a\x00"), []byte("user.k\x00"), []byte("abc"), 0)
	event := payloadEvent{
		raw: raw,
		source: staticPayloadSource{
			args: raw.Args,
			data: data,
		},
	}

	sections := payloadSectionsForPayloadEvent(event, meta.Syscall{Name: "setxattr"})

	if len(sections) != 3 {
		t.Fatalf("sections = %d, want 3", len(sections))
	}
	assertXattrPayloadSection(t, sections[0], handler.PayloadKindString, handler.PayloadDirectionIn, 0, 0x1000, []byte("/tmp/a\x00"))
	assertXattrPayloadSection(t, sections[1], handler.PayloadKindString, handler.PayloadDirectionIn, 1, 0x2000, []byte("user.k\x00"))
	assertXattrPayloadSection(t, sections[2], handler.PayloadKindBytes, handler.PayloadDirectionIn, 2, 0x3000, []byte("abc"))
}

func TestPayloadSectionsForPayloadEventUsesSourceAwareXattrGetRule(t *testing.T) {
	raw := &bpfEvent{
		EventType:     bpfEventTypeExit,
		Args:          [6]uint64{3, 0x2000, 0x3000, 4},
		Ret:           4,
		ProbeRetEnter: 0,
		ProbeRetExit:  0,
	}
	data := make([]byte, xattrValuePayloadOffset+xattrValuePayloadMaxBytes)
	copy(data[xattrFNamePayloadOffset:], []byte("user.k\x00"))
	copy(data[xattrFValuePayloadOffset:], []byte("data"))
	event := payloadEvent{
		raw: raw,
		source: staticPayloadSource{
			args: raw.Args,
			data: data,
		},
	}

	sections := payloadSectionsForPayloadEvent(event, meta.Syscall{Name: "fgetxattr"})

	if len(sections) != 2 {
		t.Fatalf("sections = %d, want 2", len(sections))
	}
	assertXattrPayloadSection(t, sections[0], handler.PayloadKindString, handler.PayloadDirectionIn, 1, 0x2000, []byte("user.k\x00"))
	assertXattrPayloadSection(t, sections[1], handler.PayloadKindBytes, handler.PayloadDirectionOut, 2, 0x3000, []byte("data"))
}

func TestPayloadSectionsForPayloadEventUsesSourceAwareXattrListRule(t *testing.T) {
	raw := &bpfEvent{
		EventType:     bpfEventTypeExit,
		Args:          [6]uint64{0x1000, 0x3000, 13},
		Ret:           13,
		ProbeRetEnter: 0,
		ProbeRetExit:  0,
	}
	data := xattrSourcePayloadData([]byte("/tmp/a\x00"), nil, []byte("user.a\x00user.b"), xattrListPayloadOffset)
	event := payloadEvent{
		raw: raw,
		source: staticPayloadSource{
			args: raw.Args,
			data: data,
		},
	}

	sections := payloadSectionsForPayloadEvent(event, meta.Syscall{Name: "listxattr"})

	if len(sections) != 2 {
		t.Fatalf("sections = %d, want 2", len(sections))
	}
	assertXattrPayloadSection(t, sections[0], handler.PayloadKindString, handler.PayloadDirectionIn, 0, 0x1000, []byte("/tmp/a\x00"))
	assertXattrPayloadSection(t, sections[1], handler.PayloadKindBytes, handler.PayloadDirectionOut, 1, 0x3000, []byte("user.a\x00user.b"))
}

func TestPayloadSectionsForPayloadEventUsesSourceAwareXattrRemoveRule(t *testing.T) {
	raw := &bpfEvent{
		EventType:     bpfEventTypeEnter,
		Args:          [6]uint64{3, 0x2000},
		ProbeRetEnter: 0,
	}
	data := make([]byte, xattrNamePayloadMaxBytes)
	copy(data[xattrFNamePayloadOffset:], []byte("user.k\x00"))
	event := payloadEvent{
		raw: raw,
		source: staticPayloadSource{
			args: raw.Args,
			data: data,
		},
	}

	sections := payloadSectionsForPayloadEvent(event, meta.Syscall{Name: "fremovexattr"})

	if len(sections) != 1 {
		t.Fatalf("sections = %d, want 1", len(sections))
	}
	assertXattrPayloadSection(t, sections[0], handler.PayloadKindString, handler.PayloadDirectionIn, 1, 0x2000, []byte("user.k\x00"))
}

func xattrSourcePayloadData(path []byte, name []byte, value []byte, valueOffset int) []byte {
	data := make([]byte, xattrValuePayloadOffset+xattrValuePayloadMaxBytes)
	copy(data[xattrPathPayloadOffset:], path)
	copy(data[xattrNamePayloadOffset:], name)
	if valueOffset == 0 {
		valueOffset = xattrValuePayloadOffset
	}
	copy(data[valueOffset:], value)
	return data
}

func assertXattrPayloadSection(
	t *testing.T,
	got handler.PayloadSection,
	kind handler.PayloadKind,
	direction handler.PayloadDirection,
	argIndex int,
	userPtr uint64,
	wantData []byte,
) {
	t.Helper()
	if got.Kind != kind || got.Direction != direction || got.ArgIndex != argIndex {
		t.Fatalf("section metadata = %+v", got)
	}
	if got.UserPtr != userPtr {
		t.Fatalf("section ptr = %#x, want %#x", got.UserPtr, userPtr)
	}
	if !bytes.Equal(got.Data, wantData) {
		t.Fatalf("section data = %v, want %v", got.Data, wantData)
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
	offset int,
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
