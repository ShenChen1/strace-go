package main

import (
	"encoding/binary"
	"testing"

	"strace-go/pkg/handler"
)

func TestPayloadSectionsDecodeEventFDStateTLV(t *testing.T) {
	data := eventFDStateSnapshotBytes(5, 17, 1)
	payload := payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindEventFDState,
		arg:     handler.PayloadEventFDStateArgIndex,
		flags:   payloadTLVFlagDirectionOut,
		userLen: handler.EventFDStateSnapshotSize,
		data:    data,
	})
	raw := rawPayloadEvent{
		valid:      true,
		eventType:  bpfEventTypeExit,
		eventFlags: bpfEventFlagPayloadTLV,
		ret:        7,
		data:       payload,
	}

	sections := payloadSectionsForRawPayloadEvent(raw)
	if len(sections) != 1 {
		t.Fatalf("sections = %d, want one eventfd state section", len(sections))
	}
	section := sections[0]
	if section.Kind != handler.PayloadKindEventFDState ||
		section.ArgIndex != handler.PayloadEventFDStateArgIndex ||
		section.Direction != handler.PayloadDirectionOut ||
		section.UserLen != handler.EventFDStateSnapshotSize {
		t.Fatalf("eventfd state section metadata = %+v", section)
	}
	state, ok := handler.DecodeEventFDState(section.Data)
	if !ok || state.Count != 5 || state.ID != 17 || state.Semaphore != 1 {
		t.Fatalf("eventfd state = %+v, ok=%v", state, ok)
	}
}

func eventFDStateSnapshotBytes(count uint64, id int32, semaphore uint32) []byte {
	data := make([]byte, handler.EventFDStateSnapshotSize)
	binary.LittleEndian.PutUint64(data[0:8], count)
	binary.LittleEndian.PutUint32(data[8:12], uint32(id))
	binary.LittleEndian.PutUint32(data[12:16], semaphore)
	return data
}
