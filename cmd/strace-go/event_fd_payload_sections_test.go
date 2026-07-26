package main

import (
	"encoding/binary"
	"testing"

	"strace-go/pkg/meta"
)

func TestJSONSyscallEventIncludesFDArrayPayloadSections(t *testing.T) {
	tests := []struct {
		name     string
		args     [6]uint64
		argIndex int
		userPtr  uint64
	}{
		{name: "pipe", args: [6]uint64{0x1000}, argIndex: 0, userPtr: 0x1000},
		{name: "pipe2", args: [6]uint64{0x2000, 0}, argIndex: 0, userPtr: 0x2000},
		{name: "socketpair", args: [6]uint64{1, 1, 0, 0x3000}, argIndex: 3, userPtr: 0x3000},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wantData := fdArrayJSONData(11, 12)
			eventRaw := &bpfEvent{
				EventType: bpfEventTypeExit,
				Args:      tt.args,
				Ret:       0,
			}
			setFDArrayExitTLVPayload(t, eventRaw, uint16(tt.argIndex), tt.userPtr, 11, 12)

			scMeta := meta.Syscall{Name: tt.name}
			ev := newJSONSyscallEvent(eventRaw, scMeta, payloadSectionsForEvent(eventRaw, scMeta))
			if len(ev.PayloadSections) != 1 {
				t.Fatalf("PayloadSections = %d, want 1", len(ev.PayloadSections))
			}
			section := ev.PayloadSections[0]
			if section.Kind != "struct" || section.Direction != "out" || section.ArgIndex != tt.argIndex {
				t.Fatalf("fd array section metadata = %+v", section)
			}
			if section.UserPtr != tt.userPtr {
				t.Fatalf("fd array section bounds = %+v", section)
			}
			if section.UserLen != fdArrayPayloadSize || section.CopiedLen != fdArrayPayloadSize {
				t.Fatalf("fd array section lengths = %+v", section)
			}
			if got := mustDecodeBase64(t, section.DataBase64); string(got) != string(wantData) {
				t.Fatalf("fd array data = %v, want %v", got, wantData)
			}
		})
	}
}

func fdArrayJSONData(first uint32, second uint32) []byte {
	data := make([]byte, fdArrayPayloadSize)
	binary.LittleEndian.PutUint32(data[0:4], first)
	binary.LittleEndian.PutUint32(data[4:8], second)
	return data
}
