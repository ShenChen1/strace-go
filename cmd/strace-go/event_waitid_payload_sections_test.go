package main

import (
	"bytes"
	"testing"
)

const (
	waitidSiginfoPayloadSize = 128
	waitidRusagePayloadSize  = 144
)

func TestJSONSyscallEventIncludesWaitidPayloadSections(t *testing.T) {
	siginfo := bytes.Repeat([]byte{0x11}, waitidSiginfoPayloadSize)
	rusage := bytes.Repeat([]byte{0x22}, waitidRusagePayloadSize)
	args := [6]uint64{0, 0, 0x1000, 0, 0x2000}
	payload := payloadTLVBytesForTest(t,
		waitidJSONTLVStruct(2, 0x1000, siginfo),
		waitidJSONTLVStruct(4, 0x2000, rusage),
	)

	ev := newJSONSyscallEventFromTLVForTest(t, "waitid", bpfEventTypeExit, args, 0, payload)
	if len(ev.PayloadSections) != 2 {
		t.Fatalf("PayloadSections = %d, want 2", len(ev.PayloadSections))
	}
	assertWaitidSection(t, ev.PayloadSections[0], 2, 0x1000, waitidSiginfoPayloadSize, siginfo)
	assertWaitidSection(t, ev.PayloadSections[1], 4, 0x2000, waitidRusagePayloadSize, rusage)
}

func assertWaitidSection(
	t *testing.T,
	section jsonPayloadSection,
	argIndex int,
	userPtr uint64,
	size uint32,
	wantData []byte,
) {
	t.Helper()
	if section.Kind != "struct" || section.Direction != "out" || section.ArgIndex != argIndex {
		t.Fatalf("section metadata = %+v", section)
	}
	if section.UserPtr != userPtr {
		t.Fatalf("section bounds = %+v", section)
	}
	if section.UserLen != size || section.CopiedLen != size {
		t.Fatalf("section lengths = %+v", section)
	}
	if got := mustDecodeBase64(t, section.DataBase64); !bytes.Equal(got, wantData) {
		t.Fatalf("section data length = %d, want %d", len(got), len(wantData))
	}
}

func waitidJSONTLVStruct(arg uint16, userPtr uint64, data []byte) payloadTLVTestSection {
	return payloadTLVTestSection{
		kind:    payloadTLVKindStruct,
		flags:   payloadTLVFlagDirectionOut,
		arg:     arg,
		userPtr: userPtr,
		userLen: uint32(len(data)),
		data:    data,
	}
}
