package main

import (
	"bytes"
	"testing"
)

func TestJSONSyscallEventIncludesIoctlEnterPayloadSection(t *testing.T) {
	wantData := bytes.Repeat([]byte{0x5a}, 32)
	payloadSections := ioctlJSONTLVSections(0x1000, []wantIoctlJSONPayloadSection{
		{direction: "in", userLen: uint32(len(wantData)), data: wantData},
	})
	args := [6]uint64{3, ioctlTestCmdSize(len(wantData)), 0x1000}

	sections := ioctlJSONPayloadSections(t, bpfEventTypeEnter, args, 0, payloadSections)
	if len(sections) != 1 {
		t.Fatalf("PayloadSections = %d, want 1", len(sections))
	}
	assertIoctlJSONSection(t, sections[0], "in", 0x1000, uint32(len(wantData)), wantData)
}

func TestJSONSyscallEventIncludesIoctlExitPayloadSection(t *testing.T) {
	inData := bytes.Repeat([]byte{0x11}, 8)
	outData := bytes.Repeat([]byte{0x22}, 8)
	payloadSections := ioctlJSONTLVSections(0x1000, []wantIoctlJSONPayloadSection{
		{direction: "in", userLen: uint32(len(inData)), data: inData},
		{direction: "out", userLen: uint32(len(outData)), data: outData},
	})
	args := [6]uint64{3, ioctlTestCmdSize(len(inData)), 0x1000}

	sections := ioctlJSONPayloadSections(t, bpfEventTypeExit, args, 0, payloadSections)
	if len(sections) != 2 {
		t.Fatalf("PayloadSections = %d, want 2", len(sections))
	}
	assertIoctlJSONSection(t, sections[0], "in", 0x1000, uint32(len(inData)), inData)
	assertIoctlJSONSection(t, sections[1], "out", 0x1000, uint32(len(outData)), outData)
}

func TestJSONSyscallEventIncludesIoctlZeroSizePayloadSection(t *testing.T) {
	wantData := bytes.Repeat([]byte{0x7f}, ioctlArgZeroPayloadLen)
	payloadSections := ioctlJSONTLVSections(0x1000, []wantIoctlJSONPayloadSection{
		{direction: "in", userLen: ioctlArgZeroPayloadLen, data: wantData},
	})
	args := [6]uint64{3, 0, 0x1000}

	sections := ioctlJSONPayloadSections(t, bpfEventTypeEnter, args, 0, payloadSections)
	if len(sections) != 1 {
		t.Fatalf("PayloadSections = %d, want 1", len(sections))
	}
	if sections[0].UserLen != ioctlArgZeroPayloadLen {
		t.Fatalf("ioctl zero-size UserLen = %d, want %d", sections[0].UserLen, ioctlArgZeroPayloadLen)
	}
	assertIoctlJSONSection(t, sections[0], "in", 0x1000, ioctlArgZeroPayloadLen, wantData)
}

func ioctlJSONPayloadSections(
	t *testing.T,
	eventType uint16,
	args [6]uint64,
	ret int64,
	sections []payloadTLVTestSection,
) []jsonPayloadSection {
	t.Helper()
	payload := payloadTLVBytesForTest(t, sections...)
	ev := newJSONSyscallEventFromTLVForTest(t, "ioctl", eventType, args, ret, payload)
	return ev.PayloadSections
}

func assertIoctlJSONSection(
	t *testing.T,
	got jsonPayloadSection,
	direction string,
	userPtr uint64,
	userLen uint32,
	wantData []byte,
) {
	t.Helper()
	if got.Kind != "bytes" || got.Direction != direction || got.ArgIndex != 2 {
		t.Fatalf("ioctl section metadata = %+v", got)
	}
	if got.UserPtr != userPtr {
		t.Fatalf("ioctl section bounds = %+v", got)
	}
	if got.UserLen != userLen {
		t.Fatalf("ioctl user length = %d, want %d", got.UserLen, userLen)
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

type wantIoctlJSONPayloadSection struct {
	direction string
	userLen   uint32
	data      []byte
}

func ioctlJSONTLVSections(userPtr uint64, wants []wantIoctlJSONPayloadSection) []payloadTLVTestSection {
	sections := make([]payloadTLVTestSection, 0, len(wants))
	for _, want := range wants {
		sections = append(sections, payloadTLVTestSection{
			kind:    payloadTLVKindBytes,
			flags:   ioctlJSONTLVFlags(want.direction),
			arg:     2,
			userPtr: userPtr,
			userLen: want.userLen,
			data:    want.data,
		})
	}
	return sections
}

func ioctlJSONTLVFlags(direction string) uint16 {
	if direction == "out" {
		return payloadTLVFlagDirectionOut
	}
	return 0
}
