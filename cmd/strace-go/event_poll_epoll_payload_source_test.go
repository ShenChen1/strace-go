package main

import (
	"bytes"
	"testing"

	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

func TestPayloadSectionsForPayloadEventUsesSourceAwarePollRules(t *testing.T) {
	raw := &bpfEvent{
		EventType:     bpfEventTypeExit,
		Args:          [6]uint64{0x1000, 2, 0x3000},
		Ret:           1,
		ProbeRetEnter: 0,
		ProbeRetExit:  0,
	}
	data := make([]byte, payloadExitArgOffset+16)
	pollEnter := bytes.Repeat([]byte{0x11}, 16)
	ppollTimeout := bytes.Repeat([]byte{0x22}, timespecPayloadStructSize)
	pollExit := bytes.Repeat([]byte{0x33}, 16)
	copy(data[:], pollEnter)
	copy(data[payloadMiscArgOffset:], ppollTimeout)
	copy(data[payloadExitArgOffset:], pollExit)
	event := payloadEventFromRawForTest(raw, data)

	sections := payloadSectionsForPayloadEvent(event, meta.Syscall{Name: "ppoll"})

	if len(sections) != 3 {
		t.Fatalf("sections = %d, want 3", len(sections))
	}
	assertSourcePayloadSection(t, sections[0], handler.PayloadKindStruct, handler.PayloadDirectionIn, 0, 0x1000)
	assertSourcePayloadSection(t, sections[1], handler.PayloadKindStruct, handler.PayloadDirectionIn, 2, 0x3000)
	assertSourcePayloadSection(t, sections[2], handler.PayloadKindStruct, handler.PayloadDirectionOut, 0, 0x1000)
	if !bytes.Equal(sections[0].Data, pollEnter) {
		t.Fatalf("poll enter data = %q", sections[0].Data)
	}
	if !bytes.Equal(sections[1].Data, ppollTimeout) {
		t.Fatalf("ppoll timeout data = %q", sections[1].Data)
	}
	if !bytes.Equal(sections[2].Data, pollExit) {
		t.Fatalf("poll exit data = %q", sections[2].Data)
	}
}

func TestPayloadSectionsForPayloadEventUsesSourceAwareSelectRule(t *testing.T) {
	raw := &bpfEvent{
		EventType:     bpfEventTypeExit,
		Args:          [6]uint64{8, 0x1000, 0, 0, 0x3000},
		Ret:           1,
		ProbeRetEnter: 0,
		ProbeRetExit:  0,
	}
	data := make([]byte, selectPayloadExitTimeoutOff+selectPayloadTimeoutSize)
	copy(data[selectPayloadFdSetOffset(1):], []byte{0x08})
	copy(data[selectPayloadTimeoutOffset:], selectJSONTimeval(9, 10))
	copy(data[selectPayloadExitFdSetOffset+selectPayloadFdSetOffset(1):], []byte{0x20})
	copy(data[selectPayloadExitTimeoutOff:], selectJSONTimeval(1, 2))
	event := payloadEventFromRawForTest(raw, data)

	sections := payloadSectionsForPayloadEvent(event, meta.Syscall{Name: "select"})

	if len(sections) != 4 {
		t.Fatalf("sections = %d, want 4", len(sections))
	}
	assertSourcePayloadSection(t, sections[0], handler.PayloadKindBytes, handler.PayloadDirectionIn, 1, 0x1000)
	assertSourcePayloadSection(t, sections[1], handler.PayloadKindStruct, handler.PayloadDirectionIn, 4, 0x3000)
	assertSourcePayloadSection(t, sections[2], handler.PayloadKindBytes, handler.PayloadDirectionOut, 1, 0x1000)
	assertSourcePayloadSection(t, sections[3], handler.PayloadKindStruct, handler.PayloadDirectionOut, 4, 0x3000)
	if !bytes.Equal(sections[0].Data, []byte{0x08}) || !bytes.Equal(sections[2].Data, []byte{0x20}) {
		t.Fatalf("select fdset data = %v/%v", sections[0].Data, sections[2].Data)
	}
	if !bytes.Equal(sections[1].Data, selectJSONTimeval(9, 10)) {
		t.Fatalf("select enter timeout = %v", sections[1].Data)
	}
	if !bytes.Equal(sections[3].Data, selectJSONTimeval(1, 2)) {
		t.Fatalf("select exit timeout = %v", sections[3].Data)
	}
}

func TestPayloadSectionsForPayloadEventUsesSourceAwareEpollRules(t *testing.T) {
	tests := []struct {
		name       string
		raw        bpfEvent
		wantCount  int
		firstArg   int
		firstDir   handler.PayloadDirection
		firstPtr   uint64
		firstBytes []byte
	}{
		{
			name: "epoll_ctl",
			raw: bpfEvent{
				EventType:     bpfEventTypeEnter,
				Args:          [6]uint64{5, 1, 6, 0x3000},
				ProbeRetEnter: 0,
			},
			wantCount:  1,
			firstArg:   3,
			firstDir:   handler.PayloadDirectionIn,
			firstPtr:   0x3000,
			firstBytes: bytes.Repeat([]byte{0x11}, epollPayloadEventSize),
		},
		{
			name: "epoll_wait",
			raw: bpfEvent{
				EventType:    bpfEventTypeExit,
				Args:         [6]uint64{5, 0x2000, 2, 1000},
				Ret:          2,
				ProbeRetExit: 0,
			},
			wantCount:  1,
			firstArg:   1,
			firstDir:   handler.PayloadDirectionOut,
			firstPtr:   0x2000,
			firstBytes: bytes.Repeat([]byte{0x33}, 24),
		},
		{
			name: "epoll_pwait2",
			raw: bpfEvent{
				EventType:     bpfEventTypeExit,
				Args:          [6]uint64{5, 0x2000, 2, 0x3000, 0, 8},
				Ret:           2,
				ProbeRetEnter: 0,
				ProbeRetExit:  0,
			},
			wantCount:  2,
			firstArg:   3,
			firstDir:   handler.PayloadDirectionIn,
			firstPtr:   0x3000,
			firstBytes: bytes.Repeat([]byte{0x22}, timespecPayloadStructSize),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := make([]byte, payloadExitArgOffset+24)
			copy(data[:], bytes.Repeat([]byte{0x11}, epollPayloadEventSize))
			copy(data[payloadMiscArgOffset:], bytes.Repeat([]byte{0x22}, timespecPayloadStructSize))
			copy(data[payloadExitArgOffset:], bytes.Repeat([]byte{0x33}, 24))
			event := payloadEventFromRawForTest(&tt.raw, data)

			sections := payloadSectionsForPayloadEvent(event, meta.Syscall{Name: tt.name})

			if len(sections) != tt.wantCount {
				t.Fatalf("sections = %d, want %d", len(sections), tt.wantCount)
			}
			assertSourcePayloadSection(t, sections[0], handler.PayloadKindStruct, tt.firstDir, tt.firstArg, tt.firstPtr)
			if !bytes.Equal(sections[0].Data, tt.firstBytes) {
				t.Fatalf("%s first section data = %v", tt.name, sections[0].Data)
			}
		})
	}
}

func assertSourcePayloadSection(
	t *testing.T,
	section handler.PayloadSection,
	kind handler.PayloadKind,
	direction handler.PayloadDirection,
	argIndex int,
	userPtr uint64,
) {
	t.Helper()
	if section.Kind != kind || section.Direction != direction || section.ArgIndex != argIndex {
		t.Fatalf("section type = %+v, want %s/%s arg %d", section, kind, direction, argIndex)
	}
	if section.UserPtr != userPtr {
		t.Fatalf("section ptr = %#x, want %#x", section.UserPtr, userPtr)
	}
}
