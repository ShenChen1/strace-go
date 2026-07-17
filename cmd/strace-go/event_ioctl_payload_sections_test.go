package main

import (
	"bytes"
	"testing"

	"strace-go/pkg/meta"
)

func TestJSONSyscallEventIncludesIoctlEnterPayloadSection(t *testing.T) {
	wantData := bytes.Repeat([]byte{0x5a}, 32)
	eventRaw := &bpfEvent{
		EventType:     bpfEventTypeEnter,
		Args:          [6]uint64{3, ioctlTestCmdSize(len(wantData)), 0x1000},
		DataLen:       ioctlArgPayloadOffset + uint32(len(wantData)),
		ProbeRetEnter: 0,
	}
	copy(eventRaw.StrArg[ioctlArgPayloadOffset:], wantData)

	sections := ioctlJSONPayloadSections(t, eventRaw)
	if len(sections) != 1 {
		t.Fatalf("PayloadSections = %d, want 1", len(sections))
	}
	assertIoctlJSONSection(t, sections[0], "in", ioctlArgPayloadOffset, 0x1000, wantData)
}

func TestJSONSyscallEventIncludesIoctlExitPayloadSection(t *testing.T) {
	inData := bytes.Repeat([]byte{0x11}, 8)
	outData := bytes.Repeat([]byte{0x22}, 8)
	eventRaw := &bpfEvent{
		EventType:     bpfEventTypeExit,
		Args:          [6]uint64{3, ioctlTestCmdSize(len(inData)), 0x1000},
		Ret:           0,
		DataLen:       payloadExitArgOffset + uint32(len(outData)),
		ProbeRetEnter: 0,
		ProbeRetExit:  0,
	}
	copy(eventRaw.StrArg[ioctlArgPayloadOffset:], inData)
	copy(eventRaw.StrArg[payloadExitArgOffset:], outData)

	sections := ioctlJSONPayloadSections(t, eventRaw)
	if len(sections) != 2 {
		t.Fatalf("PayloadSections = %d, want 2", len(sections))
	}
	assertIoctlJSONSection(t, sections[0], "in", ioctlArgPayloadOffset, 0x1000, inData)
	assertIoctlJSONSection(t, sections[1], "out", payloadExitArgOffset, 0x1000, outData)
}

func TestJSONSyscallEventIncludesIoctlZeroSizePayloadSection(t *testing.T) {
	wantData := bytes.Repeat([]byte{0x7f}, ioctlArgZeroPayloadLen)
	eventRaw := &bpfEvent{
		EventType:     bpfEventTypeEnter,
		Args:          [6]uint64{3, 0, 0x1000},
		DataLen:       ioctlArgPayloadOffset + ioctlArgZeroPayloadLen,
		ProbeRetEnter: 0,
	}
	copy(eventRaw.StrArg[ioctlArgPayloadOffset:], wantData)

	sections := ioctlJSONPayloadSections(t, eventRaw)
	if len(sections) != 1 {
		t.Fatalf("PayloadSections = %d, want 1", len(sections))
	}
	if sections[0].UserLen != ioctlArgZeroPayloadLen {
		t.Fatalf("ioctl zero-size UserLen = %d, want %d", sections[0].UserLen, ioctlArgZeroPayloadLen)
	}
	assertIoctlJSONSection(t, sections[0], "in", ioctlArgPayloadOffset, 0x1000, wantData)
}

func ioctlJSONPayloadSections(t *testing.T, eventRaw *bpfEvent) []jsonPayloadSection {
	t.Helper()
	scMeta := meta.Syscall{Name: "ioctl"}
	ev := newJSONSyscallEvent(eventRaw, scMeta, payloadSectionsForEvent(eventRaw, scMeta))
	return ev.PayloadSections
}

func assertIoctlJSONSection(
	t *testing.T,
	got jsonPayloadSection,
	direction string,
	offset int,
	userPtr uint64,
	wantData []byte,
) {
	t.Helper()
	if got.Kind != "bytes" || got.Direction != direction || got.ArgIndex != 2 {
		t.Fatalf("ioctl section metadata = %+v", got)
	}
	if got.Offset != uint32(offset) || got.UserPtr != userPtr {
		t.Fatalf("ioctl section bounds = %+v", got)
	}
	if got.CopiedLen != uint32(len(wantData)) {
		t.Fatalf("ioctl copied length = %d, want %d", got.CopiedLen, len(wantData))
	}
	if data := mustDecodeBase64(t, got.DataBase64); !bytes.Equal(data, wantData) {
		t.Fatalf("ioctl section data length = %d, want %d", len(data), len(wantData))
	}
}

func ioctlTestCmdSize(size int) uint64 {
	return uint64(size) << ioctlArgSizeShift
}
