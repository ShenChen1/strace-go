package main

import (
	"bytes"
	"testing"

	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

func TestPayloadSectionsForPayloadEventUsesSourceAwareClone3Rule(t *testing.T) {
	wantData := bytes.Repeat([]byte{0x44}, 88)
	raw := &bpfEvent{
		EventType:     bpfEventTypeEnter,
		Args:          [6]uint64{0x1000, uint64(len(wantData))},
		ProbeRetEnter: 0,
	}
	event := payloadEvent{
		raw: raw,
		source: staticPayloadSource{
			args: raw.Args,
			data: wantData,
		},
	}

	sections := payloadSectionsForPayloadEvent(event, meta.Syscall{Name: "clone3"})

	if len(sections) != 1 {
		t.Fatalf("sections = %d, want 1", len(sections))
	}
	assertStructPayloadSourceSection(t, sections[0], 0, handler.PayloadDirectionIn, handler.BpfEnterArgOffset, 0x1000, wantData)
}

func TestPayloadSectionsForPayloadEventUsesSourceAwareCachestatRule(t *testing.T) {
	raw := &bpfEvent{
		EventType:     bpfEventTypeExit,
		Args:          [6]uint64{3, 0x1000, 0x2000, 0},
		Ret:           0,
		ProbeRetEnter: 0,
		ProbeRetExit:  0,
	}
	rangeData := bytes.Repeat([]byte{0x11}, cachestatRangePayloadSize)
	statsData := bytes.Repeat([]byte{0x22}, cachestatStatsPayloadSize)
	data := make([]byte, handler.BpfExitArgOffset+cachestatStatsPayloadSize)
	copy(data[cachestatRangePayloadOffset:], rangeData)
	copy(data[handler.BpfExitArgOffset:], statsData)
	event := payloadEvent{
		raw: raw,
		source: staticPayloadSource{
			args: raw.Args,
			data: data,
		},
	}

	sections := payloadSectionsForPayloadEvent(event, meta.Syscall{Name: "cachestat"})

	if len(sections) != 2 {
		t.Fatalf("sections = %d, want 2", len(sections))
	}
	assertStructPayloadSourceSection(t, sections[0], 1, handler.PayloadDirectionIn, cachestatRangePayloadOffset, 0x1000, rangeData)
	assertStructPayloadSourceSection(t, sections[1], 2, handler.PayloadDirectionOut, handler.BpfExitArgOffset, 0x2000, statsData)
}

func assertStructPayloadSourceSection(
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
