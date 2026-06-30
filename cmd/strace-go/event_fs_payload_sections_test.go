package main

import (
	"testing"

	"strace-go/pkg/meta"
)

func TestJSONSyscallEventIncludesMountPayloadSections(t *testing.T) {
	eventRaw := &bpfEvent{
		EventType:     bpfEventTypeEnter,
		Args:          [6]uint64{0x1000, 0x2000, 0x3000, 0, 0x4000},
		DataLen:       mountDataOffset + mountStringMaxBytes,
		ProbeRetEnter: 0,
	}
	copy(eventRaw.StrArg[mountSourceOffset:], []byte("/dev/sda1\x00"))
	copy(eventRaw.StrArg[mountTargetOffset:], []byte("/mnt\x00"))
	copy(eventRaw.StrArg[mountTypeOffset:], []byte("ext4\x00"))
	copy(eventRaw.StrArg[mountDataOffset:], []byte("rw\x00"))

	scMeta := meta.Syscall{Name: "mount"}
	ev := newJSONSyscallEvent(eventRaw, scMeta, payloadSectionsForEvent(eventRaw, scMeta))
	want := []wantFsJSONPayloadSection{
		{argIndex: 0, offset: mountSourceOffset, userPtr: 0x1000, kind: "string", data: "/dev/sda1\x00"},
		{argIndex: 1, offset: mountTargetOffset, userPtr: 0x2000, kind: "string", data: "/mnt\x00"},
		{argIndex: 2, offset: mountTypeOffset, userPtr: 0x3000, kind: "string", data: "ext4\x00"},
		{argIndex: 4, offset: mountDataOffset, userPtr: 0x4000, kind: "string", data: "rw\x00"},
	}
	assertFsJSONPayloadSections(t, ev.PayloadSections, want)
}

func TestJSONSyscallEventIncludesFsconfigPayloadSections(t *testing.T) {
	tests := []struct {
		name string
		args [6]uint64
		data []byte
		want []wantFsJSONPayloadSection
	}{
		{
			name: "string",
			args: [6]uint64{3, 1, 0x1000, 0x2000, 0},
			data: append(fsPayloadData("key\x00", fsconfigValueOffset), []byte("value\x00")...),
			want: []wantFsJSONPayloadSection{
				{argIndex: 2, offset: fsconfigKeyOffset, userPtr: 0x1000, kind: "string", data: "key\x00"},
				{argIndex: 3, offset: fsconfigValueOffset, userPtr: 0x2000, kind: "string", data: "value\x00"},
			},
		},
		{
			name: "binary",
			args: [6]uint64{3, 2, 0x1000, 0x2000, 3},
			data: append(fsPayloadData("blob\x00", fsconfigValueOffset), []byte{1, 2, 3}...),
			want: []wantFsJSONPayloadSection{
				{argIndex: 2, offset: fsconfigKeyOffset, userPtr: 0x1000, kind: "string", data: "blob\x00"},
				{argIndex: 3, offset: fsconfigValueOffset, userPtr: 0x2000, kind: "bytes", data: string([]byte{1, 2, 3})},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eventRaw := &bpfEvent{
				EventType:     bpfEventTypeEnter,
				Args:          tt.args,
				DataLen:       uint32(len(tt.data)),
				ProbeRetEnter: 0,
			}
			copy(eventRaw.StrArg[:], tt.data)

			scMeta := meta.Syscall{Name: "fsconfig"}
			ev := newJSONSyscallEvent(eventRaw, scMeta, payloadSectionsForEvent(eventRaw, scMeta))
			assertFsJSONPayloadSections(t, ev.PayloadSections, tt.want)
		})
	}
}

func TestJSONSyscallEventIncludesUmountPayloadSection(t *testing.T) {
	eventRaw := &bpfEvent{
		EventType:     bpfEventTypeEnter,
		Args:          [6]uint64{0x1000},
		DataLen:       6,
		ProbeRetEnter: 0,
	}
	copy(eventRaw.StrArg[:], []byte("/mnt\x00"))

	scMeta := meta.Syscall{Name: "umount2"}
	ev := newJSONSyscallEvent(eventRaw, scMeta, payloadSectionsForEvent(eventRaw, scMeta))
	want := []wantFsJSONPayloadSection{
		{argIndex: 0, offset: 0, userPtr: 0x1000, kind: "string", data: "/mnt\x00"},
	}
	assertFsJSONPayloadSections(t, ev.PayloadSections, want)
}

type wantFsJSONPayloadSection struct {
	argIndex int
	offset   uint32
	userPtr  uint64
	kind     string
	data     string
}

func assertFsJSONPayloadSections(t *testing.T, got []jsonPayloadSection, want []wantFsJSONPayloadSection) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("PayloadSections = %d, want %d", len(got), len(want))
	}
	for i := range want {
		assertFsJSONPayloadSection(t, got[i], want[i])
	}
}

func assertFsJSONPayloadSection(t *testing.T, got jsonPayloadSection, want wantFsJSONPayloadSection) {
	t.Helper()
	if got.Kind != want.kind || got.Direction != "in" || got.ArgIndex != want.argIndex {
		t.Fatalf("fs section metadata = %+v, want %+v", got, want)
	}
	if got.Offset != want.offset || got.UserPtr != want.userPtr {
		t.Fatalf("fs section bounds = %+v, want %+v", got, want)
	}
	if got.UserLen != uint32(len(want.data)) || got.CopiedLen != uint32(len(want.data)) {
		t.Fatalf("fs section lengths = %+v, want %d", got, len(want.data))
	}
	if data := mustDecodeBase64(t, got.DataBase64); string(data) != want.data {
		t.Fatalf("fs section data = %q, want %q", string(data), want.data)
	}
}

func fsPayloadData(prefix string, valueOffset int) []byte {
	data := make([]byte, valueOffset)
	copy(data, []byte(prefix))
	return data
}
