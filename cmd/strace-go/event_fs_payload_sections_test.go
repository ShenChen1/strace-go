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
	payload := fsJSONTLVPayload(
		fsDirectTLVString(t, 0, args[0], sourceData),
		fsDirectTLVString(t, 1, args[1], targetData),
		fsDirectTLVString(t, 2, args[2], typeData),
		fsDirectTLVString(t, 4, args[4], dataData),
	)
	eventRaw := &bpfEvent{
		EventType:  bpfEventTypeEnter,
		EventFlags: bpfEventFlagPayloadTLV,
		Args:       args,
		DataLen:    uint32(len(payload)),
	}
	copy(eventRaw.StrArg[:], payload)

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
		name string
		args [6]uint64
		data []byte
		want []wantFsJSONPayloadSection
	}{
		{
			name: "string",
			args: [6]uint64{3, 1, 0x1000, 0x2000, 0},
			data: fsJSONTLVPayload(
				fsDirectTLVString(t, 2, 0x1000, []byte("key\x00")),
				fsDirectTLVString(t, 3, 0x2000, []byte("value\x00")),
			),
			want: []wantFsJSONPayloadSection{
				{argIndex: 2, userPtr: 0x1000, kind: "string", direction: "in", data: "key\x00"},
				{argIndex: 3, userPtr: 0x2000, kind: "string", direction: "in", data: "value\x00"},
			},
		},
		{
			name: "binary",
			args: [6]uint64{3, 2, 0x1000, 0x2000, 3},
			data: fsJSONTLVPayload(
				fsDirectTLVString(t, 2, 0x1000, []byte("blob\x00")),
				fsDirectTLVBytes(t, 3, 0x2000, []byte{1, 2, 3}),
			),
			want: []wantFsJSONPayloadSection{
				{argIndex: 2, userPtr: 0x1000, kind: "string", direction: "in", data: "blob\x00"},
				{argIndex: 3, userPtr: 0x2000, kind: "bytes", direction: "in", data: string([]byte{1, 2, 3})},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eventRaw := &bpfEvent{
				EventType:  bpfEventTypeEnter,
				EventFlags: bpfEventFlagPayloadTLV,
				Args:       tt.args,
				DataLen:    uint32(len(tt.data)),
			}
			copy(eventRaw.StrArg[:], tt.data)

			scMeta := meta.Syscall{Name: "fsconfig"}
			ev := newJSONSyscallEvent(eventRaw, scMeta, payloadSectionsForEvent(eventRaw, scMeta))
			assertFsJSONPayloadSections(t, ev.PayloadSections, tt.want)
		})
	}
}

func TestJSONSyscallEventIncludesUmountPayloadSection(t *testing.T) {
	args := [6]uint64{0x1000}
	targetData := []byte("/mnt\x00")
	payload := fsDirectTLVString(t, 0, args[0], targetData)
	eventRaw := &bpfEvent{
		EventType:  bpfEventTypeEnter,
		EventFlags: bpfEventFlagPayloadTLV,
		Args:       args,
		DataLen:    uint32(len(payload)),
	}
	copy(eventRaw.StrArg[:], payload)

	scMeta := meta.Syscall{Name: "umount2"}
	ev := newJSONSyscallEvent(eventRaw, scMeta, payloadSectionsForEvent(eventRaw, scMeta))
	want := []wantFsJSONPayloadSection{
		{argIndex: 0, userPtr: 0x1000, kind: "string", direction: "in", data: string(targetData)},
	}
	assertFsJSONPayloadSections(t, ev.PayloadSections, want)
}

func TestJSONSyscallEventIncludesGetdentsPayloadSection(t *testing.T) {
	direntData := []byte("dirent-section!!")
	payload := fsJSONTLVOutBytes(t, 1, 0x3000, direntData)
	eventRaw := &bpfEvent{
		EventType:  bpfEventTypeExit,
		EventFlags: bpfEventFlagPayloadTLV,
		Args:       [6]uint64{3, 0x3000, 512},
		Ret:        int64(len(direntData)),
		DataLen:    uint32(len(payload)),
	}
	copy(eventRaw.StrArg[:], payload)

	scMeta := meta.Syscall{Name: "getdents64"}
	ev := newJSONSyscallEvent(eventRaw, scMeta, payloadSectionsForEvent(eventRaw, scMeta))
	want := []wantFsJSONPayloadSection{
		{argIndex: 1, userPtr: 0x3000, kind: "bytes", direction: "out", data: string(direntData)},
	}
	assertFsJSONPayloadSections(t, ev.PayloadSections, want)
}

func fsJSONTLVPayload(sections ...[]byte) []byte {
	var payload []byte
	for _, section := range sections {
		payload = append(payload, section...)
	}
	return payload
}

func fsJSONTLVOutBytes(t *testing.T, arg uint16, userPtr uint64, data []byte) []byte {
	t.Helper()
	return payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindBytes,
		flags:   payloadTLVFlagDirectionOut,
		arg:     arg,
		userPtr: userPtr,
		userLen: uint32(len(data)),
		data:    data,
	})
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
