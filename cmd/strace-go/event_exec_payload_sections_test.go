package main

import (
	"encoding/binary"
	"testing"

	"strace-go/pkg/meta"
)

func TestJSONSyscallEventIncludesExecArgsPayloadSection(t *testing.T) {
	tests := []struct {
		name     string
		args     [6]uint64
		argIndex int
		userPtr  uint64
	}{
		{name: "execve", args: [6]uint64{0x1000, 0x2000, 0x3000}, argIndex: 1, userPtr: 0x2000},
		{name: "execveat", args: [6]uint64{^uint64(99), 0x1000, 0x2000, 0x3000, 0}, argIndex: 2, userPtr: 0x2000},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			snapshot := execJSONSnapshot()
			eventRaw := &bpfEvent{
				EventType:     bpfEventTypeEnter,
				Args:          tt.args,
				DataLen:       execPayloadSnapshotOffset + uint32(len(snapshot)),
				ProbeRetEnter: 0,
			}
			copy(eventRaw.StrArg[execPayloadSnapshotOffset:], snapshot)

			scMeta := meta.Syscall{Name: tt.name}
			ev := newJSONSyscallEvent(eventRaw, scMeta, payloadSectionsForEvent(eventRaw, scMeta))
			if len(ev.PayloadSections) != 1 {
				t.Fatalf("PayloadSections = %d, want 1", len(ev.PayloadSections))
			}
			section := ev.PayloadSections[0]
			if section.Kind != "exec_args" || section.Direction != "in" || section.ArgIndex != tt.argIndex {
				t.Fatalf("exec section metadata = %+v", section)
			}
			if section.Offset != execPayloadSnapshotOffset || section.UserPtr != tt.userPtr {
				t.Fatalf("exec section bounds = %+v", section)
			}
			if section.UserLen != uint32(len(snapshot)) || section.CopiedLen != uint32(len(snapshot)) {
				t.Fatalf("exec section lengths = %+v, want %d", section, len(snapshot))
			}
			if got := mustDecodeBase64(t, section.DataBase64); string(got) != string(snapshot) {
				t.Fatalf("exec section data length = %d, want %d", len(got), len(snapshot))
			}
		})
	}
}

func execJSONSnapshot() []byte {
	data := make([]byte, execPayloadSnapshotSize)
	binary.LittleEndian.PutUint32(data[0:4], execPayloadSnapshotMagic)
	binary.LittleEndian.PutUint16(data[4:6], 1)
	binary.LittleEndian.PutUint16(data[6:8], 1)
	return data
}
