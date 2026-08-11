package main

import (
	"bytes"
	"encoding/binary"
	"testing"

	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

func TestPayloadSectionsDecodeFDStateTLV(t *testing.T) {
	data := fdStateSnapshotBytes(9, handler.FDStateFlagIdentity|handler.FDStateFlagOffset, 0100644, 17, 18, 19, 20)
	payload := payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindFDState,
		arg:     handler.PayloadFDStateArgIndex,
		flags:   payloadTLVFlagDirectionOut,
		userLen: handler.FDStateSnapshotSize,
		data:    data,
	})
	raw := rawPayloadEvent{
		valid:      true,
		eventType:  bpfEventTypeExit,
		eventFlags: bpfEventFlagPayloadTLV,
		ret:        9,
		data:       payload,
	}

	sections := payloadSectionsForRawPayloadEvent(raw, meta.Syscall{Name: "openat"})
	if len(sections) != 1 {
		t.Fatalf("sections = %d, want one FD state section", len(sections))
	}
	section := sections[0]
	if section.Kind != handler.PayloadKindFDState || section.Direction != handler.PayloadDirectionOut ||
		section.ArgIndex != handler.PayloadFDStateArgIndex || section.UserPtr != 0 ||
		section.UserLen != handler.FDStateSnapshotSize || section.CopiedLen != handler.FDStateSnapshotSize {
		t.Fatalf("FD state section metadata = %+v", section)
	}
	observation, ok := handler.DecodeFDStateObservation(section.Data)
	if !ok || observation.FD != 9 || observation.Mode != 0100644 || observation.Offset != 20 {
		t.Fatalf("FD state observation = %+v, ok=%v", observation, ok)
	}
	if !bytes.Equal(section.Data, data) {
		t.Fatalf("FD state data changed during decode")
	}
}

func TestPayloadSectionsPreserveFailedFDStateTLV(t *testing.T) {
	payload := payloadTLVBytes(t, payloadTLVTestSection{
		kind:     payloadTLVKindFDState,
		arg:      handler.PayloadFDStateArgIndex,
		flags:    payloadTLVFlagDirectionOut,
		probeRet: -14,
	})
	raw := rawPayloadEvent{
		valid:      true,
		eventType:  bpfEventTypeExit,
		eventFlags: bpfEventFlagPayloadTLV,
		ret:        3,
		data:       payload,
	}

	sections := payloadSectionsForRawPayloadEvent(raw, meta.Syscall{Name: "open"})
	if len(sections) != 1 || sections[0].Kind != handler.PayloadKindFDState || sections[0].ProbeRet != -14 {
		t.Fatalf("failed FD state section = %+v, want explicit probe failure", sections)
	}
	if _, ok := handler.DecodeFDStateObservation(sections[0].Data); ok {
		t.Fatal("failed FD state section unexpectedly decoded as an observation")
	}
}

func fdStateSnapshotBytes(fd int32, flags, mode uint32, dev, rdev, inode uint64, offset int64) []byte {
	data := make([]byte, handler.FDStateSnapshotSize)
	binary.LittleEndian.PutUint32(data[0:4], uint32(fd))
	binary.LittleEndian.PutUint32(data[4:8], flags)
	binary.LittleEndian.PutUint32(data[8:12], mode)
	binary.LittleEndian.PutUint64(data[16:24], dev)
	binary.LittleEndian.PutUint64(data[24:32], rdev)
	binary.LittleEndian.PutUint64(data[32:40], inode)
	binary.LittleEndian.PutUint64(data[40:48], uint64(offset))
	return data
}
