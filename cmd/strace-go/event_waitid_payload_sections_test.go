package main

import (
	"bytes"
	"testing"

	"strace-go/pkg/meta"
)

func TestJSONSyscallEventIncludesWaitidPayloadSections(t *testing.T) {
	eventRaw := &bpfEvent{
		EventType:    bpfEventTypeExit,
		Args:         [6]uint64{0, 0, 0x1000, 0, 0x2000},
		Ret:          0,
		DataLen:      payloadExitArgOffset + 136 + waitidRusagePayloadSize,
		ProbeRetExit: 0,
	}
	siginfo := bytes.Repeat([]byte{0x11}, waitidSiginfoPayloadSize)
	rusage := bytes.Repeat([]byte{0x22}, waitidRusagePayloadSize)
	copy(eventRaw.StrArg[payloadExitArgOffset:], siginfo)
	copy(eventRaw.StrArg[payloadExitArgOffset+136:], rusage)

	scMeta := meta.Syscall{Name: "waitid"}
	ev := newJSONSyscallEvent(eventRaw, scMeta, payloadSectionsForEvent(eventRaw, scMeta))
	if len(ev.PayloadSections) != 2 {
		t.Fatalf("PayloadSections = %d, want 2", len(ev.PayloadSections))
	}
	assertWaitidSection(t, ev.PayloadSections[0], 2, payloadExitArgOffset, 0x1000, waitidSiginfoPayloadSize, siginfo)
	assertWaitidSection(t, ev.PayloadSections[1], 4, payloadExitArgOffset+136, 0x2000, waitidRusagePayloadSize, rusage)
}

func assertWaitidSection(
	t *testing.T,
	section jsonPayloadSection,
	argIndex int,
	offset int,
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
