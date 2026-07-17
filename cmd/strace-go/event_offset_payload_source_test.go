package main

import (
	"bytes"
	"testing"

	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

func TestPayloadSectionsForPayloadEventUsesSourceAwareSendfileRule(t *testing.T) {
	raw := &bpfEvent{
		EventType:    bpfEventTypeExit,
		Args:         [6]uint64{4, 5, 0x1000, 99},
		Ret:          99,
		ProbeRetExit: 0,
	}
	data := make([]byte, payloadExitArgOffset+offsetPointerPayloadSize)
	copy(data[payloadMiscArgOffset:], offsetJSONWord(10))
	copy(data[payloadExitArgOffset:], offsetJSONWord(20))
	event := payloadEvent{
		raw: raw,
		source: staticPayloadSource{
			args: raw.Args,
			data: data,
		},
	}

	sections := payloadSectionsForPayloadEvent(event, meta.Syscall{Name: "sendfile"})

	if len(sections) != 2 {
		t.Fatalf("sections = %d, want 2", len(sections))
	}
	assertOffsetPayloadSourceSection(t, sections[0], 2, handler.PayloadDirectionIn, payloadMiscArgOffset, 0x1000, offsetJSONWord(10))
	assertOffsetPayloadSourceSection(t, sections[1], 2, handler.PayloadDirectionOut, payloadExitArgOffset, 0x1000, offsetJSONWord(20))
}

func TestPayloadSectionsForPayloadEventUsesSourceAwareCopyFileRangeRule(t *testing.T) {
	raw := &bpfEvent{
		EventType:     bpfEventTypeEnter,
		Args:          [6]uint64{4, 0x1000, 5, 0x2000, 99, 0},
		ProbeRetEnter: 0,
	}
	data := make([]byte, payloadMiscArgOffset+offsetPointerPayloadSize*2)
	copy(data[payloadMiscArgOffset:], offsetJSONWord(11))
	copy(data[payloadMiscArgOffset+8:], offsetJSONWord(22))
	event := payloadEvent{
		raw: raw,
		source: staticPayloadSource{
			args: raw.Args,
			data: data,
		},
	}

	sections := payloadSectionsForPayloadEvent(event, meta.Syscall{Name: "copy_file_range"})

	if len(sections) != 2 {
		t.Fatalf("sections = %d, want 2", len(sections))
	}
	assertOffsetPayloadSourceSection(t, sections[0], 1, handler.PayloadDirectionIn, payloadMiscArgOffset, 0x1000, offsetJSONWord(11))
	assertOffsetPayloadSourceSection(t, sections[1], 3, handler.PayloadDirectionIn, payloadMiscArgOffset+8, 0x2000, offsetJSONWord(22))
}

func assertOffsetPayloadSourceSection(
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
	if section.UserPtr != userPtr {
		t.Fatalf("section bounds = %+v", section)
	}
	if section.UserLen != offsetPointerPayloadSize || section.CopiedLen != offsetPointerPayloadSize {
		t.Fatalf("section lengths = %+v", section)
	}
	if !bytes.Equal(section.Data, wantData) {
		t.Fatalf("section data = %v, want %v", section.Data, wantData)
	}
}
