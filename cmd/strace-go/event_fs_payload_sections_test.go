package main

import (
	"testing"

	"strace-go/pkg/meta"
)

func TestJSONSyscallEventIncludesMountPayloadSections(t *testing.T) {
	args := [6]uint64{0x1000, 0x2000, 0x3000, 0, 0x4000}
	sourceData := []byte("/dev/sda1\x00")
	targetData := []byte("/mnt\x00")
	typeData := []byte("ext4\x00")
	dataData := []byte("rw\x00")
	eventRaw := &bpfEvent{
		EventType: bpfEventTypeEnter,
		Args:      args,
	}
	setJSONTestTLVPayload(t, eventRaw,
		fsJSONTLVString(0, args[0], sourceData),
		fsJSONTLVString(1, args[1], targetData),
		fsJSONTLVString(2, args[2], typeData),
		fsJSONTLVString(4, args[4], dataData),
	)

	scMeta := meta.Syscall{Name: "mount"}
	ev := newJSONSyscallEvent(eventRaw, scMeta, payloadSectionsForEvent(eventRaw, scMeta))
	want := []wantFsJSONPayloadSection{
		{argIndex: 0, userPtr: 0x1000, kind: "string", direction: "in", data: string(sourceData)},
		{argIndex: 1, userPtr: 0x2000, kind: "string", direction: "in", data: string(targetData)},
		{argIndex: 2, userPtr: 0x3000, kind: "string", direction: "in", data: string(typeData)},
		{argIndex: 4, userPtr: 0x4000, kind: "string", direction: "in", data: string(dataData)},
	}
	assertFsJSONPayloadSections(t, ev.PayloadSections, want)
}

func TestJSONSyscallEventIncludesFsconfigPayloadSections(t *testing.T) {
	tests := []struct {
		name     string
		args     [6]uint64
		sections []payloadTLVTestSection
		want     []wantFsJSONPayloadSection
	}{
		{
			name: "string",
			args: [6]uint64{3, 1, 0x1000, 0x2000, 0},
			sections: []payloadTLVTestSection{
				fsJSONTLVString(2, 0x1000, []byte("key\x00")),
				fsJSONTLVString(3, 0x2000, []byte("value\x00")),
			},
			want: []wantFsJSONPayloadSection{
				{argIndex: 2, userPtr: 0x1000, kind: "string", direction: "in", data: "key\x00"},
				{argIndex: 3, userPtr: 0x2000, kind: "string", direction: "in", data: "value\x00"},
			},
		},
		{
			name: "binary",
			args: [6]uint64{3, 2, 0x1000, 0x2000, 3},
			sections: []payloadTLVTestSection{
				fsJSONTLVString(2, 0x1000, []byte("blob\x00")),
				fsJSONTLVBytes(3, 0x2000, []byte{1, 2, 3}, 0),
			},
			want: []wantFsJSONPayloadSection{
				{argIndex: 2, userPtr: 0x1000, kind: "string", direction: "in", data: "blob\x00"},
				{argIndex: 3, userPtr: 0x2000, kind: "bytes", direction: "in", data: string([]byte{1, 2, 3})},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eventRaw := &bpfEvent{
				EventType: bpfEventTypeEnter,
				Args:      tt.args,
			}
			setJSONTestTLVPayload(t, eventRaw, tt.sections...)

			scMeta := meta.Syscall{Name: "fsconfig"}
			ev := newJSONSyscallEvent(eventRaw, scMeta, payloadSectionsForEvent(eventRaw, scMeta))
			assertFsJSONPayloadSections(t, ev.PayloadSections, tt.want)
		})
	}
}

func TestJSONSyscallEventIncludesUmountPayloadSection(t *testing.T) {
	args := [6]uint64{0x1000}
	targetData := []byte("/mnt\x00")
	eventRaw := &bpfEvent{
		EventType: bpfEventTypeEnter,
		Args:      args,
	}
	setJSONTestTLVPayload(t, eventRaw, fsJSONTLVString(0, args[0], targetData))

	scMeta := meta.Syscall{Name: "umount2"}
	ev := newJSONSyscallEvent(eventRaw, scMeta, payloadSectionsForEvent(eventRaw, scMeta))
	want := []wantFsJSONPayloadSection{
		{argIndex: 0, userPtr: 0x1000, kind: "string", direction: "in", data: string(targetData)},
	}
	assertFsJSONPayloadSections(t, ev.PayloadSections, want)
}

func TestJSONSyscallEventIncludesGetdentsPayloadSection(t *testing.T) {
	direntData := []byte("dirent-section!!")
	eventRaw := &bpfEvent{
		EventType: bpfEventTypeExit,
		Args:      [6]uint64{3, 0x3000, 512},
		Ret:       int64(len(direntData)),
	}
	setJSONTestTLVPayload(t, eventRaw, fsJSONTLVBytes(1, 0x3000, direntData, payloadTLVFlagDirectionOut))

	scMeta := meta.Syscall{Name: "getdents64"}
	ev := newJSONSyscallEvent(eventRaw, scMeta, payloadSectionsForEvent(eventRaw, scMeta))
	want := []wantFsJSONPayloadSection{
		{argIndex: 1, userPtr: 0x3000, kind: "bytes", direction: "out", data: string(direntData)},
	}
	assertFsJSONPayloadSections(t, ev.PayloadSections, want)
}

func fsJSONTLVString(arg uint16, userPtr uint64, data []byte) payloadTLVTestSection {
	return payloadTLVTestSection{
		kind:    payloadTLVKindString,
		arg:     arg,
		userPtr: userPtr,
		userLen: uint32(len(data)),
		data:    data,
	}
}

func fsJSONTLVBytes(arg uint16, userPtr uint64, data []byte, flags uint16) payloadTLVTestSection {
	return payloadTLVTestSection{
		kind:    payloadTLVKindBytes,
		flags:   flags,
		arg:     arg,
		userPtr: userPtr,
		userLen: uint32(len(data)),
		data:    data,
	}
}

type wantFsJSONPayloadSection struct {
	argIndex  int
	userPtr   uint64
	kind      string
	direction string
	data      string
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
	if got.Kind != want.kind || got.Direction != want.direction || got.ArgIndex != want.argIndex {
		t.Fatalf("fs section metadata = %+v, want %+v", got, want)
	}
	if got.UserPtr != want.userPtr {
		t.Fatalf("fs section bounds = %+v, want %+v", got, want)
	}
	if got.UserLen != uint32(len(want.data)) || got.CopiedLen != uint32(len(want.data)) {
		t.Fatalf("fs section lengths = %+v, want %d", got, len(want.data))
	}
	if data := mustDecodeBase64(t, got.DataBase64); string(data) != want.data {
		t.Fatalf("fs section data = %q, want %q", string(data), want.data)
	}
}
