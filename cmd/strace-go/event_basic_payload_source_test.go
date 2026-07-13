package main

import (
	"bytes"
	"testing"

	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

func TestPayloadSectionsForPayloadEventUsesSourceAwarePrlimitRule(t *testing.T) {
	raw := &bpfEvent{
		EventType:     bpfEventTypeExit,
		Args:          [6]uint64{101, 7, 0x3000, 0x4000},
		Ret:           0,
		ProbeRetEnter: 0,
		ProbeRetExit:  0,
	}
	oldLimit := bytes.Repeat([]byte{0x11}, rlimitPayloadStructSize)
	newLimit := bytes.Repeat([]byte{0x22}, rlimitPayloadStructSize)
	data := make([]byte, payloadExitArgOffset+rlimitPayloadStructSize)
	copy(data[payloadEnterArgOffset:], oldLimit)
	copy(data[payloadExitArgOffset:], newLimit)
	event := payloadEvent{
		raw: raw,
		source: staticPayloadSource{
			args: raw.Args,
			data: data,
		},
	}

	sections := payloadSectionsForPayloadEvent(event, meta.Syscall{Name: "prlimit64"})

	if len(sections) != 2 {
		t.Fatalf("sections = %d, want 2", len(sections))
	}
	assertBasicStructPayloadSourceSection(t, sections[0], 2, handler.PayloadDirectionIn, payloadEnterArgOffset, 0x3000, oldLimit)
	assertBasicStructPayloadSourceSection(t, sections[1], 3, handler.PayloadDirectionOut, payloadExitArgOffset, 0x4000, newLimit)
}

func TestPayloadSectionsForPayloadEventUsesSourceAwareSetrlimitRule(t *testing.T) {
	raw := &bpfEvent{
		EventType:     bpfEventTypeEnter,
		Args:          [6]uint64{7, 0x4000},
		ProbeRetEnter: 0,
	}
	limit := bytes.Repeat([]byte{0x33}, rlimitPayloadStructSize)
	event := payloadEvent{
		raw: raw,
		source: staticPayloadSource{
			args: raw.Args,
			data: limit,
		},
	}

	sections := payloadSectionsForPayloadEvent(event, meta.Syscall{Name: "setrlimit"})

	if len(sections) != 1 {
		t.Fatalf("sections = %d, want 1", len(sections))
	}
	assertBasicStructPayloadSourceSection(t, sections[0], 1, handler.PayloadDirectionIn, payloadEnterArgOffset, 0x4000, limit)
}

func TestPayloadSectionsForPayloadEventUsesSourceAwareRobustListRule(t *testing.T) {
	raw := &bpfEvent{
		EventType:    bpfEventTypeExit,
		Args:         [6]uint64{0, 0x1000, 0x2000},
		Ret:          0,
		ProbeRetExit: 0,
	}
	data := make([]byte, payloadExitArgOffset+24)
	copy(data[payloadExitArgOffset:], robustListJSONWord(0xfeedface))
	copy(data[payloadExitArgOffset+16:], robustListJSONWord(24))
	event := payloadEvent{
		raw: raw,
		source: staticPayloadSource{
			args: raw.Args,
			data: data,
		},
	}

	sections := payloadSectionsForPayloadEvent(event, meta.Syscall{Name: "get_robust_list"})

	if len(sections) != 2 {
		t.Fatalf("sections = %d, want 2", len(sections))
	}
	assertBasicStructPayloadSourceSection(t, sections[0], 1, handler.PayloadDirectionOut, payloadExitArgOffset, 0x1000, robustListJSONWord(0xfeedface))
	assertBasicStructPayloadSourceSection(t, sections[1], 2, handler.PayloadDirectionOut, payloadExitArgOffset+16, 0x2000, robustListJSONWord(24))
}

func TestPayloadSectionsForPayloadEventUsesSourceAwareWaitidRule(t *testing.T) {
	raw := &bpfEvent{
		EventType:    bpfEventTypeExit,
		Args:         [6]uint64{0, 0, 0x1000, 0, 0x2000},
		Ret:          0,
		ProbeRetExit: 0,
	}
	siginfo := bytes.Repeat([]byte{0x11}, waitidSiginfoPayloadSize)
	rusage := bytes.Repeat([]byte{0x22}, waitidRusagePayloadSize)
	data := make([]byte, payloadExitArgOffset+136+waitidRusagePayloadSize)
	copy(data[payloadExitArgOffset:], siginfo)
	copy(data[payloadExitArgOffset+136:], rusage)
	event := payloadEvent{
		raw: raw,
		source: staticPayloadSource{
			args: raw.Args,
			data: data,
		},
	}

	sections := payloadSectionsForPayloadEvent(event, meta.Syscall{Name: "waitid"})

	if len(sections) != 2 {
		t.Fatalf("sections = %d, want 2", len(sections))
	}
	assertBasicStructPayloadSourceSection(t, sections[0], 2, handler.PayloadDirectionOut, payloadExitArgOffset, 0x1000, siginfo)
	assertBasicStructPayloadSourceSection(t, sections[1], 4, handler.PayloadDirectionOut, payloadExitArgOffset+136, 0x2000, rusage)
}

func assertBasicStructPayloadSourceSection(
	t *testing.T,
	section handler.PayloadSection,
	argIndex int,
	direction handler.PayloadDirection,
	offset int,
	userPtr uint64,
	wantData []byte,
) {
	t.Helper()
	if section.Kind != handler.PayloadKindStruct || section.Direction != direction || section.ArgIndex != argIndex {
		t.Fatalf("section metadata = %+v", section)
	}
	if section.Offset != uint32(offset) || section.UserPtr != userPtr {
		t.Fatalf("section bounds = %+v", section)
	}
	if section.UserLen != uint32(len(wantData)) || section.CopiedLen != uint32(len(wantData)) {
		t.Fatalf("section lengths = %+v", section)
	}
	if !bytes.Equal(section.Data, wantData) {
		t.Fatalf("section data length = %d, want %d", len(section.Data), len(wantData))
	}
}
